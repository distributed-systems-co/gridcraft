//! `ds://` workbooks against the real DSCO storage fabric receiver.
//!
//! These tests start fleet-mesh's `payload_replication.py serve` (protocol `dsco-chunk-http/3`)
//! on a loopback port and drive `gridcraft-cli` against it. Point `GRIDCRAFT_DS_FABRIC_PY` at
//! the script to run them, e.g.
//!
//! ```text
//! GRIDCRAFT_DS_FABRIC_PY=~/Dsco/fleet-mesh/payload_replication.py cargo test -p gridcraft-cli --test ds_fabric
//! ```
//!
//! Without it (upstream CI) they report themselves skipped and pass.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

const KEY: &str = "gridcraft-ds-test-key-0123456789";

struct Receiver {
    child: Child,
    port: u16,
    root: PathBuf,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn script() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("GRIDCRAFT_DS_FABRIC_PY")?);
    assert!(p.is_file(), "GRIDCRAFT_DS_FABRIC_PY={} is not a file", p.display());
    Some(p)
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("gridcraft-ds-test-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn start_receiver(script: &Path, dir: &Path) -> Receiver {
    // The receiver refuses port 0; borrow a free port from the OS.
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let root = dir.join("receiver");
    let mut child = Command::new("python3")
        .arg(script)
        .args(["serve", "--root", root.to_str().unwrap(), "--port", &port.to_string(), "--node", "test-receiver"])
        .env("DSCO_REPLICATION_KEY", KEY)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("start python3 payload_replication.py serve");
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap()).read_line(&mut line).unwrap();
    let ready: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("receiver said {line:?}: {e}"));
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["protocol"], "dsco-chunk-http/3");
    Receiver { child, port, root }
}

fn cli(r: &Receiver, home: &Path, key: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gridcraft-cli"))
        .args(args)
        .env("DSCO_REPLICATION_KEY", key)
        .env_remove("DSCO_DHT_SWARM")
        .env("GRIDCRAFT_DS_ENDPOINT", format!("http://127.0.0.1:{}", r.port))
        .env("GRIDCRAFT_DS_HOME", home)
        .env("GRIDCRAFT_DS_NODE", "gridcraft-test")
        .output()
        .unwrap()
}

fn ok(r: &Receiver, home: &Path, args: &[&str]) -> (String, String) {
    let o = cli(r, home, KEY, args);
    let err = String::from_utf8_lossy(&o.stderr).to_string();
    assert!(o.status.success(), "gridcraft-cli {args:?} failed: {err}");
    (String::from_utf8(o.stdout).unwrap(), err)
}

fn sha256_file(p: &Path) -> String {
    // The receiver's own digest of what it installed, via python to stay independent of ds.rs.
    let o = Command::new("python3")
        .args(["-c", "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"])
        .arg(p)
        .output()
        .unwrap();
    String::from_utf8(o.stdout).unwrap().trim().to_string()
}

fn mcp(r: &Receiver, home: &Path, args: &[&str], calls: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gridcraft-cli"))
        .arg("mcp")
        .args(args)
        .env("DSCO_REPLICATION_KEY", KEY)
        .env("GRIDCRAFT_DS_ENDPOINT", format!("http://127.0.0.1:{}", r.port))
        .env("GRIDCRAFT_DS_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, r#"{{"jsonrpc":"2.0","id":0,"method":"initialize","params":{{"protocolVersion":"2025-06-18"}}}}"#).unwrap();
        for (i, c) in calls.iter().enumerate() {
            let msg = serde_json::json!({"jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": c});
            writeln!(stdin, "{msg}").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "mcp failed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8(out.stdout).unwrap();
    let mut replies: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    replies.retain(|v| v["id"] != 0);
    assert_eq!(replies.len(), calls.len(), "{text}");
    replies.into_iter().map(|v| v["result"].clone()).collect()
}

fn tool_text(r: &serde_json::Value) -> &str {
    r["content"][0]["text"].as_str().unwrap_or("")
}

#[test]
fn save_open_and_resync_workbooks_through_the_fabric() {
    let Some(script) = script() else {
        eprintln!("skipped: set GRIDCRAFT_DS_FABRIC_PY to fleet-mesh/payload_replication.py");
        return;
    };
    let dir = tmpdir("flow");
    let r = start_receiver(&script, &dir);
    let home = dir.join("home");

    // Save: a sample workbook with an edit goes into the fabric and is installed by the receiver.
    let (_, err) =
        ok(&r, &home, &["run", "--sample", "sales", "--cmd", r#"cell.set={"cell":"K1","input":"42"}"#, "--out", "ds://sales.xlsx", "--quiet"]);
    assert!(err.contains("stored ds://sales.xlsx"), "{err}");
    let installed = r.root.join("outputs").join("sales.xlsx");
    assert!(installed.is_file(), "receiver did not install the workbook");
    let refs = home.join("refs").join(format!("127.0.0.1_{}", r.port)).join("sales.xlsx.json");
    let rf: serde_json::Value = serde_json::from_slice(&std::fs::read(&refs).unwrap()).unwrap();
    assert_eq!(rf["manifest"]["sha256"].as_str().unwrap(), sha256_file(&installed));
    assert_eq!(rf["receipt"]["status"], "verified");
    assert_eq!(rf["receipt"]["node"], "test-receiver");
    let receipt = r.root.join("receipts").join(format!("{}.receipt.json", rf["manifest_sha256"].as_str().unwrap()));
    assert!(receipt.is_file());

    // Open: every subcommand that takes a file reads ds:// paths.
    let (out, _) = ok(&r, &home, &["cat", "ds://sales.xlsx", "--range", "K1"]);
    assert_eq!(out.trim(), "42");
    let (out, _) = ok(&r, &home, &["eval", "=K1*2", "--in", "ds://sales.xlsx"]);
    assert_eq!(out.trim(), "84");
    let (out, _) = ok(&r, &home, &["info", "ds://sales.xlsx"]);
    assert!(out.starts_with("sales.xlsx"), "{out}");

    // Byte-exact get, and a warm re-put of identical bytes sends nothing.
    let copy = dir.join("copy.xlsx");
    ok(&r, &home, &["ds", "get", "ds://sales.xlsx", copy.to_str().unwrap()]);
    assert_eq!(std::fs::read(&copy).unwrap(), std::fs::read(&installed).unwrap());
    let (out, _) = ok(&r, &home, &["ds", "put", copy.to_str().unwrap(), "ds://sales.xlsx"]);
    let put: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(put["fabric"]["transferredBytes"], 0, "{out}");
    assert_eq!(put["fabric"]["missingBefore"], 0, "{out}");
    assert_eq!(put["fabric"]["verified"], true);
    let (out, _) = ok(&r, &home, &["ds", "ls", "--json"]);
    let ls: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(ls[0]["path"], "ds://sales.xlsx");

    // convert straight into the fabric (format by extension).
    ok(&r, &home, &["convert", "ds://sales.xlsx", "ds://sales.csv"]);
    let csv = std::fs::read_to_string(r.root.join("outputs").join("sales.csv")).unwrap();
    assert!(csv.lines().next().unwrap().contains("42"), "{csv}");

    // MCP: open_workbook / save_workbook take ds:// paths with --ds, and a plain save goes back
    // to the workbook's ds:// path.
    let replies = mcp(
        &r,
        &home,
        &["--ds"],
        &[
            serde_json::json!({"name": "open_workbook", "arguments": {"path": "ds://sales.xlsx"}}),
            serde_json::json!({"name": "get_cell", "arguments": {"cell": "K1"}}),
            serde_json::json!({"name": "set_cell", "arguments": {"cell": "K1", "input": "43"}}),
            serde_json::json!({"name": "save_workbook", "arguments": {}}),
            serde_json::json!({"name": "inspect_workbook", "arguments": {}}),
            serde_json::json!({"name": "save_workbook", "arguments": {"path": "ds://agent-copy.xlsx"}}),
            serde_json::json!({"name": "save_workbook", "arguments": {"path": "ds://../escape.xlsx"}}),
        ],
    );
    for (i, rep) in replies.iter().enumerate().take(6) {
        assert_ne!(rep["isError"], true, "call {i}: {}", tool_text(rep));
    }
    assert!(tool_text(&replies[1]).contains("42"), "{}", tool_text(&replies[1]));
    assert!(tool_text(&replies[3]).contains("ds://sales.xlsx"), "{}", tool_text(&replies[3]));
    assert!(tool_text(&replies[4]).contains("ds://sales.xlsx"), "{}", tool_text(&replies[4]));
    assert_eq!(replies[6]["isError"], true, "a path with folders must be refused");
    let (out, _) = ok(&r, &home, &["cat", "ds://sales.xlsx", "--range", "K1"]);
    assert_eq!(out.trim(), "43");
    let (out, _) = ok(&r, &home, &["cat", "ds://agent-copy.xlsx", "--range", "K1"]);
    assert_eq!(out.trim(), "43");
    assert!(!r.root.join("escape.xlsx").exists());

    // Without --ds the MCP server never touches the network for ds:// paths.
    let replies = mcp(&r, &home, &[], &[serde_json::json!({"name": "open_workbook", "arguments": {"path": "ds://sales.xlsx"}})]);
    assert_eq!(replies[0]["isError"], true);

    // Multi-chunk payloads: changing the last MiB of a 2.5 MiB file re-sends only that chunk.
    let big = dir.join("big.xlsx");
    let mut data: Vec<u8> = (0..(5u32 << 19)).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
    std::fs::write(&big, &data).unwrap();
    let (out, _) = ok(&r, &home, &["ds", "put", big.to_str().unwrap()]);
    let first: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(first["fabric"]["chunks"], 3, "{out}");
    assert_eq!(first["fabric"]["missingBefore"], 3, "{out}");
    if let Some(b) = data.last_mut() {
        *b ^= 1;
    }
    std::fs::write(&big, &data).unwrap();
    let (out, _) = ok(&r, &home, &["ds", "put", big.to_str().unwrap()]);
    let second: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(second["fabric"]["missingBefore"], 1, "{out}");
    assert_eq!(second["fabric"]["transferredBytes"], (5u64 << 19) - (2u64 << 20), "{out}");
    assert_eq!(std::fs::read(r.root.join("outputs").join("big.xlsx")).unwrap(), data);

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_keys_tampering_and_misconfiguration_are_refused() {
    let Some(script) = script() else {
        eprintln!("skipped: set GRIDCRAFT_DS_FABRIC_PY to fleet-mesh/payload_replication.py");
        return;
    };
    let dir = tmpdir("refuse");
    let r = start_receiver(&script, &dir);
    let home = dir.join("home");
    ok(&r, &home, &["run", "--sample", "budget", "--out", "ds://budget.xlsx", "--quiet"]);

    // A sender with another key: the receiver rejects its manifest, and its own ref check fails.
    let o = cli(&r, &home, "a-different-key-0123456789", &["run", "--out", "ds://other.xlsx"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("signature mismatch"), "{}", String::from_utf8_lossy(&o.stderr));
    let o = cli(&r, &home, "a-different-key-0123456789", &["cat", "ds://budget.xlsx"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("signature mismatch"));

    // Short keys and unknown workbooks fail with a message, not a crash.
    let o = cli(&r, &home, "short", &["cat", "ds://budget.xlsx"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("at least 16 bytes"));
    let o = cli(&r, &home, KEY, &["cat", "ds://nope.xlsx"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("no ref"));
    let o = cli(&r, &home, KEY, &["run", "--out", "ds://report.pdf"]);
    assert!(!o.status.success());

    // A chunk corrupted at rest on the receiver is never handed to the engine.
    let chunks = r.root.join("chunks");
    for e in std::fs::read_dir(&chunks).unwrap() {
        let p = e.unwrap().path();
        let mut data = std::fs::read(&p).unwrap();
        if let Some(b) = data.first_mut() {
            *b ^= 0xff;
        }
        std::fs::write(&p, data).unwrap();
    }
    let o = cli(&r, &home, KEY, &["cat", "ds://budget.xlsx"]);
    assert!(!o.status.success(), "a corrupted workbook was opened");

    // Nothing listening: a clear error.
    drop(r);
    let gone = Receiver { child: Command::new("true").spawn().unwrap(), port: 9, root: dir.clone() };
    let o = cli(&gone, &home, KEY, &["run", "--out", "ds://budget.xlsx"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("not reachable"), "{}", String::from_utf8_lossy(&o.stderr));
    drop(gone);
    let _ = std::fs::remove_dir_all(&dir);
}
