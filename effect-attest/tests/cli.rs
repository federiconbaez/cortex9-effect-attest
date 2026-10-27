//! CLI tests that need no privileges.
use effect_attest::dsse::keys;
use effect_attest::statement::{self, Call, Integrity, Observer, Predicate, Statement};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_effect-attest");
const WORKLOAD: &str = env!("CARGO_BIN_EXE_ea-workload");

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ea-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn statement(drained: bool) -> Statement {
    Statement::new(
        statement::subjects("t", &json!(1), &json!({}), &json!({"content": []})),
        Predicate {
            observer: Observer {
                mechanism: "ebpf:raw_syscalls+cgroup_v2".into(),
                kernel: "k".into(),
                syscalls: vec![],
                version: "0".into(),
            },
            call: Call {
                tool: "t".into(),
                request_id: json!(1),
                arguments: json!({}),
                argv: vec!["/bin/true".into()],
                cgroup_id: 1,
                started_at: "a".into(),
                finished_at: "b".into(),
                exit_code: Some(0),
                signal: None,
                killed_leftovers: false,
            },
            effects: vec![],
            integrity: Integrity {
                cgroup_drained: drained,
                ..Default::default()
            },
        },
    )
}

fn keygen(dir: &Path) -> PathBuf {
    let prefix = dir.join("k");
    let out = Command::new(EXE)
        .args(["keygen", "--out"])
        .arg(&prefix)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim().len(),
        64,
        "keyid"
    );
    prefix
}

fn verify(pubkey: &Path, files: &[&Path], extra: &[&str]) -> std::process::Output {
    Command::new(EXE)
        .args(["verify", "--pubkey"])
        .arg(pubkey)
        .args(extra)
        .args(files)
        .output()
        .unwrap()
}

#[test]
fn keygen_writes_private_key_0600() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmpdir("keygen");
    let p = keygen(&d);
    let mode = std::fs::metadata(p.with_extension("key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    // Refuses to overwrite an existing key.
    let again = Command::new(EXE)
        .args(["keygen", "--out"])
        .arg(&p)
        .output()
        .unwrap();
    assert!(!again.status.success());
}

#[test]
fn verify_accepts_good_and_rejects_tampered() {
    let d = tmpdir("verify");
    let p = keygen(&d);
    let key = keys::read_signing(&p.with_extension("key")).unwrap();
    let good = d.join("good.json");
    std::fs::write(
        &good,
        serde_json::to_vec(&statement(true).sign(&key)).unwrap(),
    )
    .unwrap();

    let out = verify(
        &p.with_extension("pub"),
        &[&good],
        &["--require-complete", "--print"],
    );
    assert!(out.status.success(), "{out:?}");
    let printed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(printed["_type"], statement::STATEMENT_TYPE);

    let mut env: Value = serde_json::from_slice(&std::fs::read(&good).unwrap()).unwrap();
    let mut body = effect_attest::dsse::b64decode(env["payload"].as_str().unwrap()).unwrap();
    let pos = body.windows(5).position(|w| w == b"\"t\",\"").unwrap_or(10);
    body[pos + 1] = b'u';
    use base64::Engine;
    env["payload"] = json!(base64::engine::general_purpose::STANDARD.encode(&body));
    let bad = d.join("bad.json");
    std::fs::write(&bad, env.to_string()).unwrap();
    let out = verify(&p.with_extension("pub"), &[&good, &bad], &[]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("FAIL") && err.contains("1 of 2"), "{err}");
}

#[test]
fn verify_strict_rejects_undrained() {
    let d = tmpdir("strict");
    let p = keygen(&d);
    let key = keys::read_signing(&p.with_extension("key")).unwrap();
    let f = d.join("undrained.json");
    std::fs::write(
        &f,
        serde_json::to_vec(&statement(false).sign(&key)).unwrap(),
    )
    .unwrap();
    assert!(verify(&p.with_extension("pub"), &[&f], &[])
        .status
        .success());
    let out = verify(&p.with_extension("pub"), &[&f], &["--require-complete"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not drained"));
}

fn catalog(dir: &Path) -> PathBuf {
    let c = dir.join("catalog.json");
    std::fs::write(
        &c,
        json!({"tools": [{"name": "wl", "command": [WORKLOAD]}]}).to_string(),
    )
    .unwrap();
    c
}

#[test]
fn unattested_serve_over_stdio() {
    let d = tmpdir("serve");
    let target = d.join("out.txt");
    let mut child = Command::new(EXE)
        .args(["serve", "--unattested", "--catalog"])
        .arg(catalog(&d))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(stdin, r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{"protocolVersion":"2025-11-25"}}}}"#).unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call",
               "params":{"name":"wl","arguments":{"args":["--write", target.to_str().unwrap()]}}})
    )
    .unwrap();
    drop(stdin);
    let lines: Vec<Value> = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    assert!(child.wait().unwrap().success());
    let call = lines.iter().find(|v| v["id"] == 2).unwrap();
    assert_eq!(call["result"]["isError"], false, "{call}");
    assert!(
        call["result"].get("_meta").is_none(),
        "no attestation when unattested"
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "effect\n");
}

/// Attested mode must never silently degrade: without privileges it exits
/// with an error naming BPF; as root it must answer `initialize`.
#[test]
fn attested_serve_fails_loudly_without_bpf() {
    let d = tmpdir("nobpf");
    let p = keygen(&d);
    let mut child = Command::new(EXE)
        .args(["serve", "--catalog"])
        .arg(catalog(&d))
        .arg("--key")
        .arg(p.with_extension("key"))
        .args(["--bpf-object", "/nonexistent/effect-attest-ebpf"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let out = child.wait_with_output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("BPF did not load"), "{err}");
}

#[test]
fn workload_rejects_unknown_flags() {
    let out = Command::new(WORKLOAD).arg("--nope").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
