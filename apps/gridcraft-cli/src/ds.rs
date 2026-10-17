//! `ds://` workbooks: open and save through the DSCO storage fabric.
//!
//! The fabric's data plane is `dsco-chunk-http/3` (fleet-mesh `payload_replication.py`): a
//! payload is split into SHA-256-addressed chunks described by an HMAC-signed manifest. Saving
//! posts the manifest, uploads only the chunks the receiver is missing, and asks it to assemble
//! the file; the receiver verifies every chunk and the whole payload and answers with a signed
//! receipt. Opening downloads the manifest's chunks and verifies them before the engine sees a
//! byte.
//!
//! The receiver has no name index or manifest download route, so this client keeps the signed
//! manifest of every workbook it saves as a local *ref* (`$GRIDCRAFT_DS_HOME/refs/…`). A ref is
//! self-verifying (manifest HMAC + digest) and can be copied to another machine that holds the
//! same fabric key.
//!
//! Configuration (environment):
//! - `DSCO_REPLICATION_KEY` (or `DSCO_DHT_SWARM`): the fabric's shared key, at least 16 bytes.
//! - `GRIDCRAFT_DS_ENDPOINT`: receiver origin, default `http://127.0.0.1:17610`.
//! - `GRIDCRAFT_DS_HOME`: refs and HLC state, default `$XDG_CONFIG_HOME/dsco/gridcraft` or
//!   `~/.config/dsco/gridcraft`.
//! - `GRIDCRAFT_DS_NODE`: this sender's node name in manifests, default `gridcraft-cli`.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const SCHEME: &str = "ds://";
pub const PROTOCOL: &str = "dsco-chunk-http/3";
const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:17610";
/// Workbooks are small next to the fabric's 4 MiB default; 1 MiB chunks keep re-saves cheap.
pub const DEFAULT_CHUNK_SIZE: usize = 1 << 20;
const MIN_CHUNK_SIZE: usize = 64 << 10;
const MAX_CHUNK_SIZE: usize = 8 << 20;
const MAX_MANIFEST_BYTES: usize = 4 << 20;
/// Largest workbook this client will download or upload.
pub const MAX_PAYLOAD: u64 = 1 << 30;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// True for a `ds://name` path.
pub fn is_ds(path: &str) -> bool {
    path.starts_with(SCHEME)
}

/// `ds://book.xlsx` → `book.xlsx`. The name must be a bare file name: the receiver installs the
/// payload under that name and rejects anything with a directory part.
pub fn parse_url(url: &str) -> Result<String, String> {
    let name = url.strip_prefix(SCHEME).ok_or_else(|| format!("{url}: not a ds:// path"))?;
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']) || name.len() > 255 {
        return Err(format!("{url}: a ds:// path is ds://<file name> (no folders), e.g. ds://budget.xlsx"));
    }
    Ok(name.to_string())
}

// ---------------------------------------------------------------- primitives

pub fn sha256(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

pub fn hex(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&sha256(data))
}

/// HMAC-SHA256 (RFC 2104) over the workspace's `sha2`.
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = if key.len() > BLOCK { sha256(key) } else { key.to_vec() };
    k.resize(BLOCK, 0);
    let mut inner = Sha256::new();
    inner.update(k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(message);
    let inner = inner.finalize().to_vec();
    let mut outer = Sha256::new();
    outer.update(k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(&inner);
    outer.finalize().to_vec()
}

pub fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    hex(&hmac_sha256(key, message))
}

/// Constant-time comparison of two hex strings.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Python's `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`: the
/// fabric's canonical form, which every signature and digest covers.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                if let Some(x) = o.get(k.as_str()) {
                    write_canonical(x, out);
                }
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

/// Binary SHA-256 Merkle root over chunk digests, duplicating an odd last node.
pub fn merkle_root_hex(digests: &[Vec<u8>]) -> String {
    if digests.is_empty() {
        return sha256_hex(b"");
    }
    let mut nodes: Vec<Vec<u8>> = digests.to_vec();
    while nodes.len() > 1 {
        if nodes.len() % 2 == 1
            && let Some(last) = nodes.last().cloned()
        {
            nodes.push(last);
        }
        nodes = nodes
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                for n in pair {
                    h.update(n);
                }
                h.finalize().to_vec()
            })
            .collect();
    }
    nodes.first().map(|n| hex(n)).unwrap_or_default()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect()
}

/// Wall-clock milliseconds for HLC stamps. The CLI is native-only (never built for wasm).
#[allow(clippy::disallowed_methods)]
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)).unwrap_or(0)
}

fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------- manifests

/// A signed manifest and its digest (the SHA-256 of its canonical JSON).
#[derive(Debug, Clone)]
pub struct Manifest {
    pub value: Value,
    pub sha256: String,
}

impl Manifest {
    pub fn name(&self) -> &str {
        self.value["name"].as_str().unwrap_or("")
    }
    pub fn size(&self) -> u64 {
        self.value["size"].as_u64().unwrap_or(0)
    }
    /// `(digest, size)` per chunk, in payload order.
    pub fn chunks(&self) -> Vec<(String, u64)> {
        self.value["chunks"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| (c["sha256"].as_str().unwrap_or("").to_string(), c["size"].as_u64().unwrap_or(0)))
            .collect()
    }
}

/// Splits `data` into chunks and signs a manifest for it.
pub fn build_manifest(name: &str, data: &[u8], key: &[u8], node: &str, hlc: &str, chunk_size: usize) -> Result<(Manifest, Vec<Vec<u8>>), String> {
    if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(format!("chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}"));
    }
    let mut chunks = Vec::new();
    let mut digests = Vec::new();
    let mut parts = Vec::new();
    let mut offset = 0usize;
    for part in data.chunks(chunk_size) {
        let d = sha256(part);
        chunks.push(json!({"offset": offset, "size": part.len(), "sha256": hex(&d)}));
        digests.push(d);
        parts.push(part.to_vec());
        offset = offset.saturating_add(part.len());
    }
    let mut m = Map::new();
    m.insert("protocol".into(), json!(PROTOCOL));
    m.insert("name".into(), json!(name));
    m.insert("size".into(), json!(data.len()));
    m.insert("sha256".into(), json!(sha256_hex(data)));
    m.insert("chunk_size".into(), json!(chunk_size));
    m.insert("chunks".into(), Value::Array(chunks));
    m.insert("merkle_root".into(), json!(merkle_root_hex(&digests)));
    m.insert("hlc".into(), json!(hlc));
    m.insert("source_node".into(), json!(node));
    m.insert("created_unix_ms".into(), json!(now_ms()));
    let mut value = Value::Object(m);
    let mac = hmac_hex(key, canonical_json(&value).as_bytes());
    value["hmac_sha256"] = json!(mac);
    let sha = sha256_hex(canonical_json(&value).as_bytes());
    Ok((Manifest { value, sha256: sha }, parts))
}

/// Checks a manifest's signature and structure (the receiver's own rules) and returns it with
/// its digest.
pub fn verify_manifest(value: &Value, key: &[u8]) -> Result<Manifest, String> {
    let supplied = value.get("hmac_sha256").and_then(Value::as_str).ok_or("manifest signature missing")?;
    let mut unsigned = value.clone();
    if let Some(o) = unsigned.as_object_mut() {
        o.remove("hmac_sha256");
    }
    if !same(supplied, &hmac_hex(key, canonical_json(&unsigned).as_bytes())) {
        return Err("manifest signature mismatch (wrong DSCO_REPLICATION_KEY?)".into());
    }
    if value["protocol"] != PROTOCOL {
        return Err("unsupported manifest protocol".into());
    }
    let name = value["name"].as_str().unwrap_or("");
    parse_url(&format!("{SCHEME}{name}")).map_err(|_| "unsafe payload name in manifest".to_string())?;
    let chunks = value["chunks"].as_array().ok_or("invalid chunk list")?;
    let mut offset = 0u64;
    let mut digests = Vec::with_capacity(chunks.len().min(1 << 16));
    for c in chunks {
        let d = c["sha256"].as_str().filter(|d| is_digest(d)).ok_or("invalid chunk digest")?;
        let size = c["size"].as_u64().filter(|s| *s <= MAX_CHUNK_SIZE as u64).ok_or("invalid chunk size")?;
        if c["offset"].as_u64() != Some(offset) {
            return Err("invalid chunk offset".into());
        }
        offset = offset.saturating_add(size);
        digests.push(unhex(d).ok_or("invalid chunk digest")?);
    }
    if value["size"].as_u64() != Some(offset) {
        return Err("manifest size mismatch".into());
    }
    if offset > MAX_PAYLOAD {
        return Err(format!("payload of {offset} bytes is larger than the {MAX_PAYLOAD}-byte limit"));
    }
    if value["merkle_root"].as_str() != Some(merkle_root_hex(&digests).as_str()) {
        return Err("manifest Merkle root mismatch".into());
    }
    if !value["sha256"].as_str().is_some_and(is_digest) {
        return Err("invalid payload digest".into());
    }
    Ok(Manifest { value: value.clone(), sha256: sha256_hex(canonical_json(value).as_bytes()) })
}

/// Checks a receipt's signature.
pub fn verify_receipt(receipt: &Value, key: &[u8]) -> Result<(), String> {
    let supplied = receipt.get("receipt_hmac_sha256").and_then(Value::as_str).ok_or("receipt signature missing")?;
    let mut unsigned = receipt.clone();
    if let Some(o) = unsigned.as_object_mut() {
        o.remove("receipt_hmac_sha256");
    }
    if same(supplied, &hmac_hex(key, canonical_json(&unsigned).as_bytes())) { Ok(()) } else { Err("receipt signature mismatch".into()) }
}

// ---------------------------------------------------------------- HTTP (plain, private mesh)

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// `http://host:port` (an origin; the fabric speaks plain HTTP over the private mesh).
    pub fn parse(s: &str) -> Result<Endpoint, String> {
        let rest = s.strip_prefix("http://").ok_or_else(|| format!("{s}: the fabric endpoint is an http:// origin"))?;
        let rest = rest.trim_end_matches('/');
        if rest.is_empty() || rest.contains(['/', '@', '?', '#']) {
            return Err(format!("{s}: give an origin only, e.g. http://127.0.0.1:17610"));
        }
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| format!("{s}: bad port"))?),
            None => (rest, 80),
        };
        if host.is_empty() {
            return Err(format!("{s}: missing host"));
        }
        Ok(Endpoint { host: host.to_string(), port })
    }

    pub fn origin(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// A file-name-safe id for the refs folder.
    fn id(&self) -> String {
        let h: String = self.host.chars().map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' }).collect();
        format!("{h}_{}", self.port)
    }

    /// One request on a fresh connection. Returns the status and the body (bounded by `max`).
    fn request(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8], max: usize) -> Result<(u16, Vec<u8>), String> {
        let addr = format!("{}:{}", self.host, self.port);
        let mut last = format!("cannot resolve {addr}");
        let mut stream = None;
        for sa in addr.to_socket_addrs().map_err(|e| format!("{addr}: {e}"))? {
            match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = format!("{addr}: {e}"),
            }
        }
        let mut stream = stream.ok_or_else(|| format!("storage fabric not reachable: {last}"))?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
        stream.set_nodelay(true).ok();
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        let io = |e: std::io::Error| format!("{method} {path}: {e}");
        stream.write_all(head.as_bytes()).map_err(io)?;
        stream.write_all(body).map_err(io)?;
        stream.flush().map_err(io)?;
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.by_ref().take(8192).read_line(&mut line).map_err(io)?;
        let status =
            line.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok()).ok_or_else(|| format!("{method} {path}: bad HTTP status line"))?;
        let mut length: Option<usize> = None;
        for _ in 0..200 {
            line.clear();
            if reader.by_ref().take(8192).read_line(&mut line).map_err(io)? == 0 {
                break;
            }
            let l = line.trim_end();
            if l.is_empty() {
                break;
            }
            if let Some((k, v)) = l.split_once(':')
                && k.trim().eq_ignore_ascii_case("content-length")
            {
                length = v.trim().parse().ok();
            }
        }
        let length = length.ok_or_else(|| format!("{method} {path}: reply without Content-Length"))?;
        if length > max {
            return Err(format!("{method} {path}: reply of {length} bytes exceeds the protocol limit"));
        }
        let mut data = vec![0u8; length];
        reader.read_exact(&mut data).map_err(io)?;
        Ok((status, data))
    }

    fn json(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<Value, String> {
        let mut h = vec![("Content-Type", "application/json")];
        h.extend_from_slice(headers);
        let (status, data) = self.request(method, path, &h, body, MAX_MANIFEST_BYTES * 2)?;
        let v: Value = serde_json::from_slice(&data).map_err(|e| format!("{method} {path}: bad JSON reply ({e})"))?;
        if status >= 400 {
            let detail = v.get("error").and_then(Value::as_str).unwrap_or("error");
            return Err(format!("storage fabric {method} {path}: HTTP {status}: {detail}"));
        }
        Ok(v)
    }
}

// ---------------------------------------------------------------- the client

/// What a save did.
#[derive(Debug, Clone)]
pub struct Saved {
    pub url: String,
    pub manifest_sha256: String,
    pub payload_sha256: String,
    pub bytes: usize,
    pub chunks: usize,
    pub missing_before: usize,
    pub transferred_bytes: usize,
    pub receipt: Value,
}

impl Saved {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.url,
            "bytes": self.bytes,
            "fabric": {
                "manifestSha256": self.manifest_sha256,
                "payloadSha256": self.payload_sha256,
                "chunks": self.chunks,
                "missingBefore": self.missing_before,
                "transferredBytes": self.transferred_bytes,
                "receiptNode": self.receipt["node"],
                "verified": self.receipt["status"] == "verified",
            }
        })
    }
}

pub struct Fabric {
    pub endpoint: Endpoint,
    key: Vec<u8>,
    pub node: String,
    pub home: PathBuf,
    pub chunk_size: usize,
}

impl std::fmt::Debug for Fabric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key.
        f.debug_struct("Fabric").field("endpoint", &self.endpoint).field("node", &self.node).field("home", &self.home).finish_non_exhaustive()
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

impl Fabric {
    pub fn new(endpoint: Endpoint, key: Vec<u8>, node: String, home: PathBuf) -> Result<Fabric, String> {
        if key.len() < 16 {
            return Err("the storage fabric key must contain at least 16 bytes".into());
        }
        if node.is_empty() {
            return Err("empty node name".into());
        }
        Ok(Fabric { endpoint, key, node, home, chunk_size: DEFAULT_CHUNK_SIZE })
    }

    /// Configuration from the environment; `endpoint` overrides `GRIDCRAFT_DS_ENDPOINT`.
    pub fn from_env(endpoint: Option<&str>) -> Result<Fabric, String> {
        let key = env("DSCO_REPLICATION_KEY")
            .or_else(|| env("DSCO_DHT_SWARM"))
            .ok_or("ds:// needs the storage fabric key in DSCO_REPLICATION_KEY (or DSCO_DHT_SWARM)")?;
        let endpoint = match endpoint.map(str::to_string).or_else(|| env("GRIDCRAFT_DS_ENDPOINT")) {
            Some(e) => Endpoint::parse(&e)?,
            None => Endpoint::parse(DEFAULT_ENDPOINT)?,
        };
        let home = match env("GRIDCRAFT_DS_HOME") {
            Some(h) => PathBuf::from(h),
            None => match env("XDG_CONFIG_HOME") {
                Some(x) => PathBuf::from(x).join("dsco").join("gridcraft"),
                None => PathBuf::from(env("HOME").ok_or("set GRIDCRAFT_DS_HOME (no HOME)")?).join(".config").join("dsco").join("gridcraft"),
            },
        };
        let node = env("GRIDCRAFT_DS_NODE").unwrap_or_else(|| "gridcraft-cli".to_string());
        Fabric::new(endpoint, key.into_bytes(), node, home)
    }

    fn refs_dir(&self) -> PathBuf {
        self.home.join("refs").join(self.endpoint.id())
    }

    fn ref_path(&self, name: &str) -> PathBuf {
        self.refs_dir().join(format!("{name}.json"))
    }

    /// The next hybrid logical clock value `physical_ms:logical:node`, persisted so it never goes
    /// backwards on this machine (the receiver rejects manifests older than its watermark).
    fn next_hlc(&self) -> Result<String, String> {
        let path = self.home.join("hlc.json");
        let prior: Value = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
        let prior_phys = prior["physical_ms"].as_u64().unwrap_or(0);
        let now = now_ms();
        let physical = now.max(prior_phys);
        let logical = if physical == prior_phys { prior["logical"].as_u64().map_or(0, |l| l.saturating_add(1)) } else { 0 };
        write_atomic(&path, canonical_json(&json!({"physical_ms": physical, "logical": logical})).as_bytes())?;
        Ok(format!("{physical}:{logical}:{}", self.node))
    }

    /// Uploads `data` as `ds://name`: manifest, missing chunks, assemble, verified receipt.
    pub fn save(&self, url: &str, data: &[u8]) -> Result<Saved, String> {
        let name = parse_url(url)?;
        if data.len() as u64 > MAX_PAYLOAD {
            return Err(format!("{url}: {} bytes is larger than the {MAX_PAYLOAD}-byte limit", data.len()));
        }
        let hlc = self.next_hlc()?;
        let (manifest, parts) = build_manifest(&name, data, &self.key, &self.node, &hlc, self.chunk_size)?;
        let accepted = self.endpoint.json("POST", "/v1/manifest", &[], canonical_json(&manifest.value).as_bytes())?;
        if accepted["manifest_sha256"].as_str() != Some(manifest.sha256.as_str()) {
            return Err("the storage fabric computed a different manifest digest (protocol mismatch)".into());
        }
        let missing: Vec<String> = accepted["missing"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect();
        let index = manifest.chunks();
        let mut transferred = 0usize;
        for digest in &missing {
            let part = index
                .iter()
                .position(|(d, _)| d == digest)
                .and_then(|i| parts.get(i))
                .ok_or_else(|| format!("the storage fabric asked for an unknown chunk {digest}"))?;
            let auth = hmac_hex(&self.key, format!("chunk:{}:{digest}", manifest.sha256).as_bytes());
            let r = self.endpoint.json(
                "PUT",
                &format!("/v1/chunks/{digest}"),
                &[("Content-Type", "application/octet-stream"), ("X-DSCO-Manifest", &manifest.sha256), ("X-DSCO-Auth", &auth)],
                part,
            )?;
            if r["sha256"].as_str() != Some(digest.as_str()) {
                return Err("the storage fabric did not acknowledge a chunk".into());
            }
            transferred = transferred.saturating_add(part.len());
        }
        let assemble = json!({
            "manifest_sha256": manifest.sha256,
            "auth": hmac_hex(&self.key, format!("assemble:{}", manifest.sha256).as_bytes()),
            "transferred_bytes": transferred,
            "missing_before": missing.len(),
        });
        let receipt = self.endpoint.json("POST", "/v1/assemble", &[], canonical_json(&assemble).as_bytes())?;
        verify_receipt(&receipt, &self.key)?;
        if receipt["status"] != "verified"
            || receipt["manifest_sha256"].as_str() != Some(manifest.sha256.as_str())
            || receipt["payload_sha256"] != manifest.value["sha256"]
        {
            return Err("the storage fabric's receipt does not match the upload".into());
        }
        let r = json!({
            "endpoint": self.endpoint.origin(),
            "url": format!("{SCHEME}{name}"),
            "manifest_sha256": manifest.sha256,
            "manifest": manifest.value,
            "receipt": receipt,
        });
        write_atomic(&self.ref_path(&name), format!("{}\n", serde_json::to_string_pretty(&r).unwrap_or_default()).as_bytes())?;
        Ok(Saved {
            url: format!("{SCHEME}{name}"),
            manifest_sha256: manifest.sha256.clone(),
            payload_sha256: manifest.value["sha256"].as_str().unwrap_or("").to_string(),
            bytes: data.len(),
            chunks: index.len(),
            missing_before: missing.len(),
            transferred_bytes: transferred,
            receipt,
        })
    }

    /// The verified manifest of the last save of `ds://name` from this machine (or a copied ref).
    pub fn manifest_for(&self, url: &str) -> Result<Manifest, String> {
        let name = parse_url(url)?;
        let path = self.ref_path(&name);
        let data = std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                format!("{url}: no ref for this workbook at {} (save it once, or copy its ref there)", self.endpoint.origin())
            } else {
                format!("{}: {e}", path.display())
            }
        })?;
        let r: Value = serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
        let m = verify_manifest(&r["manifest"], &self.key)?;
        if m.name() != name {
            return Err(format!("{}: the ref is for `{}`", path.display(), m.name()));
        }
        Ok(m)
    }

    /// Downloads and verifies `ds://name`.
    pub fn open(&self, url: &str) -> Result<(String, Vec<u8>), String> {
        let m = self.manifest_for(url)?;
        let size = usize::try_from(m.size()).map_err(|_| "payload too large".to_string())?;
        let mut out = Vec::with_capacity(size.min(64 << 20));
        for (digest, csize) in m.chunks() {
            let auth = hmac_hex(&self.key, format!("get:{}:{digest}", m.sha256).as_bytes());
            let (status, data) = self.endpoint.request(
                "GET",
                &format!("/v1/chunks/{digest}"),
                &[("X-DSCO-Manifest", &m.sha256), ("X-DSCO-Auth", &auth)],
                &[],
                MAX_CHUNK_SIZE,
            )?;
            if status != 200 {
                let detail = serde_json::from_slice::<Value>(&data).ok().and_then(|v| v["error"].as_str().map(str::to_string)).unwrap_or_default();
                return Err(format!("{url}: chunk {digest}: HTTP {status} {detail}"));
            }
            if data.len() as u64 != csize || sha256_hex(&data) != digest {
                return Err(format!("{url}: chunk {digest} failed verification"));
            }
            out.extend_from_slice(&data);
        }
        if out.len() != size || Some(sha256_hex(&out).as_str()) != m.value["sha256"].as_str() {
            return Err(format!("{url}: assembled workbook failed verification"));
        }
        Ok((m.name().to_string(), out))
    }

    /// The workbooks this machine has refs for at this endpoint: `(url, size, manifest digest)`.
    pub fn list(&self) -> Vec<(String, u64, String)> {
        let mut v: Vec<(String, u64, String)> = std::fs::read_dir(self.refs_dir())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let data = std::fs::read(e.path()).ok()?;
                let r: Value = serde_json::from_slice(&data).ok()?;
                let m = verify_manifest(&r["manifest"], &self.key).ok()?;
                Some((format!("{SCHEME}{}", m.name()), m.size(), m.sha256))
            })
            .collect();
        v.sort();
        v
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().ok_or_else(|| format!("{}: no parent folder", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".{}.tmp{}", path.file_name().and_then(|n| n.to_str()).unwrap_or("ref"), std::process::id()));
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

// ---------------------------------------------------------------- engine glue

/// The engine's save format for a file name: `x.csv` → `csv`; xlsx by default.
pub fn format_for(name: &str) -> Result<&'static str, String> {
    let ext = Path::new(name).extension().and_then(|e| e.to_str()).map(str::to_ascii_lowercase).unwrap_or_default();
    Ok(match ext.as_str() {
        "" | "xlsx" => "xlsx",
        "csv" => "csv",
        "tsv" => "tsv",
        "json" => "json",
        "html" | "htm" => "html",
        other => return Err(format!("ds:// saves .xlsx, .csv, .tsv, .json or .html, not .{other}")),
    })
}

/// Runs an engine command (`id`, `params`) and returns its result.
pub type Exec<'a> = dyn FnMut(&str, Value) -> Result<Value, String> + 'a;

/// Opens `ds://name` in the engine (`file.open {name, base64}`); returns the command's result.
pub fn open_into(fabric: &Fabric, exec: &mut Exec<'_>, url: &str, password: Option<&Value>) -> Result<Value, String> {
    let (name, bytes) = fabric.open(url)?;
    let mut p = json!({"name": name, "base64": gridcraft_engine::io::base64_encode(&bytes)});
    if let Some(pw) = password {
        p["password"] = pw.clone();
    }
    let mut r = exec("file.open", p)?;
    if let Some(o) = r.as_object_mut() {
        o.insert("path".into(), json!(url));
        o.insert("fabric".into(), json!({"bytes": bytes.len(), "endpoint": fabric.endpoint.origin()}));
    }
    Ok(r)
}

/// Saves the active workbook to `ds://name` (`file.saveBytes` in the format the name implies).
pub fn save_from(fabric: &Fabric, exec: &mut Exec<'_>, url: &str) -> Result<Saved, String> {
    let name = parse_url(url)?;
    let fmt = format_for(&name)?;
    let r = exec("file.saveBytes", json!({"format": fmt}))?;
    let b64 = r["base64"].as_str().ok_or("file.saveBytes returned no data")?;
    let bytes = gridcraft_engine::io::base64_decode(b64).ok_or("file.saveBytes returned invalid base64")?;
    fabric.save(url, &bytes)
}

/// Wraps a [`gridcraft_mcp::Backend`] so `file.open` / `file.save` / `file.saveAs` (and the MCP
/// `open_workbook` / `save_workbook` tools built on them) accept `ds://` paths. Everything else
/// passes through, so it works for the headless engine and for a running app (`--connect`).
pub struct DsBackend {
    inner: Box<dyn gridcraft_mcp::Backend>,
    fabric: Fabric,
    /// Document title → its `ds://` path (the engine only knows filesystem paths).
    titles: Vec<(String, String)>,
}

impl DsBackend {
    pub fn new(inner: Box<dyn gridcraft_mcp::Backend>, fabric: Fabric) -> DsBackend {
        DsBackend { inner, fabric, titles: Vec::new() }
    }

    /// The `ds://` path of the active document, when it came from (or was saved to) the fabric
    /// and has no filesystem path.
    fn active_ds(&mut self) -> Option<String> {
        let info = self.inner.call("document.inspect", json!({})).ok()?;
        if !info["path"].is_null() {
            return None;
        }
        let title = info["title"].as_str()?;
        self.titles.iter().rev().find(|(t, _)| t == title).map(|(_, u)| u.clone())
    }

    fn remember(&mut self, title: Option<&str>, url: &str) {
        if let Some(t) = title {
            self.titles.retain(|(x, _)| x != t);
            self.titles.push((t.to_string(), url.to_string()));
        }
    }

    fn file_command(&mut self, id: &str, params: &Value) -> Option<Result<Value, String>> {
        let path = params.get("path").and_then(Value::as_str).map(str::to_string);
        match (id, path) {
            ("file.open", Some(p)) if is_ds(&p) => {
                let pw = params.get("password").cloned();
                let fabric = &self.fabric;
                let inner = &mut self.inner;
                let mut exec = |id: &str, p: Value| inner.call("engine.execute", json!({"command": id, "params": p}));
                let r = open_into(fabric, &mut exec, &p, pw.as_ref());
                if let Ok(v) = &r {
                    let title = v["title"].as_str().map(str::to_string);
                    self.remember(title.as_deref(), &p);
                }
                Some(r)
            }
            ("file.save" | "file.saveAs", Some(p)) if is_ds(&p) => Some(self.save_ds(&p)),
            ("file.save", None) => self.active_ds().map(|p| self.save_ds(&p)),
            _ => None,
        }
    }

    fn save_ds(&mut self, url: &str) -> Result<Value, String> {
        let fabric = &self.fabric;
        let inner = &mut self.inner;
        let mut exec = |id: &str, p: Value| inner.call("engine.execute", json!({"command": id, "params": p}));
        let saved = save_from(fabric, &mut exec, url)?;
        let title = self.inner.call("document.inspect", json!({})).ok().and_then(|v| v["title"].as_str().map(str::to_string));
        self.remember(title.as_deref(), url);
        Ok(saved.to_json())
    }
}

impl gridcraft_mcp::Backend for DsBackend {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        match method {
            "engine.execute" => {
                let id = params.get("command").and_then(Value::as_str).unwrap_or("").to_string();
                let p = params.get("params").cloned().unwrap_or_else(|| json!({}));
                if let Some(r) = self.file_command(&id, &p) {
                    return r;
                }
                self.inner.call(method, params)
            }
            "file.open" | "file.save" | "file.saveAs" => {
                if let Some(r) = self.file_command(method, &params) {
                    return r;
                }
                self.inner.call(method, params)
            }
            "document.inspect" => {
                let mut v = self.inner.call(method, params)?;
                if v["path"].is_null()
                    && let Some(title) = v["title"].as_str().map(str::to_string)
                    && let Some((_, url)) = self.titles.iter().rev().find(|(t, _)| *t == title)
                {
                    v["path"] = json!(url);
                }
                Ok(v)
            }
            _ => self.inner.call(method, params),
        }
    }

    fn has_ui(&self) -> bool {
        self.inner.has_ui()
    }

    fn describe(&self) -> String {
        format!("{}; ds:// paths via the storage fabric at {}", self.inner.describe(), self.fabric.endpoint.origin())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn sha_and_hmac_vectors() {
        assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        // RFC 4231 test cases 2 and 6 (key longer than the block).
        assert_eq!(hmac_hex(b"Jefe", b"what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(
            hmac_hex(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn canonical_matches_python() {
        let v = json!({"b": 1, "a": [true, null, "é\n\"x\""], "c": {"z": 0, "y": -2}});
        // python3 -c 'import json;print(json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False))'
        assert_eq!(canonical_json(&v), r#"{"a":[true,null,"é\n\"x\""],"b":1,"c":{"y":-2,"z":0}}"#);
        assert_eq!(canonical_json(&json!({"d": 1.5})), r#"{"d":1.5}"#);
    }

    #[test]
    fn merkle_roots() {
        assert_eq!(merkle_root_hex(&[]), sha256_hex(b""));
        let a = sha256(b"a");
        assert_eq!(merkle_root_hex(std::slice::from_ref(&a)), hex(&a));
        let b = sha256(b"b");
        let c = sha256(b"c");
        let ab = sha256(&[a.clone(), b.clone()].concat());
        let cc = sha256(&[c.clone(), c.clone()].concat());
        assert_eq!(merkle_root_hex(&[a, b, c]), sha256_hex(&[ab, cc].concat()));
    }

    #[test]
    fn manifests_round_trip_and_reject_tampering() {
        let key = b"0123456789abcdef-test".to_vec();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (m, parts) = build_manifest("book.xlsx", &data, &key, "test", "1:0:test", MIN_CHUNK_SIZE).unwrap();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts.concat(), data);
        let v = verify_manifest(&m.value, &key).unwrap();
        assert_eq!(v.sha256, m.sha256);
        assert_eq!(v.size(), 200_000);
        assert!(verify_manifest(&m.value, b"another-key-0123456").unwrap_err().contains("signature"));
        let mut bad = m.value.clone();
        bad["name"] = json!("../x.xlsx");
        assert!(verify_manifest(&bad, &key).is_err());
        assert!(build_manifest("b.xlsx", &data, &key, "t", "1:0:t", 10).is_err());
    }

    #[test]
    fn urls_and_endpoints() {
        assert_eq!(parse_url("ds://budget.xlsx").unwrap(), "budget.xlsx");
        for bad in ["ds://", "ds://a/b.xlsx", "ds://..", "/tmp/x.xlsx", "ds://a\\b"] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
        assert_eq!(Endpoint::parse("http://10.84.0.12:17610/").unwrap(), Endpoint { host: "10.84.0.12".into(), port: 17610 });
        assert_eq!(Endpoint::parse("http://fabric").unwrap().port, 80);
        assert!(Endpoint::parse("https://x:1").is_err());
        assert!(Endpoint::parse("http://u@x:1").is_err());
        assert!(Endpoint::parse("http://x:1/path").is_err());
        assert_eq!(format_for("a.CSV").unwrap(), "csv");
        assert_eq!(format_for("a").unwrap(), "xlsx");
        assert!(format_for("a.pdf").is_err());
    }

    #[test]
    fn short_keys_are_refused_and_never_printed() {
        let e = Endpoint::parse(DEFAULT_ENDPOINT).unwrap();
        assert!(Fabric::new(e.clone(), b"short".to_vec(), "n".into(), PathBuf::from("/tmp")).is_err());
        let f = Fabric::new(e, b"secret-key-material-123".to_vec(), "n".into(), PathBuf::from("/tmp")).unwrap();
        assert!(!format!("{f:?}").contains("secret"));
    }
}
