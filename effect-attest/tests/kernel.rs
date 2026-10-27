//! Tests that load the eBPF program into the running kernel. They need
//! root and the compiled object (`EFFECT_ATTEST_BPF_OBJ`), and are marked
//! `#[ignore]`: run them with
//!
//! ```text
//! EFFECT_ATTEST_BPF_OBJ=$PWD/effect-attest-ebpf/target/bpfel-unknown-none/release/effect-attest-ebpf \
//! CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='sudo -E' \
//!   cargo test --release -p effect-attest --test kernel -- --ignored
//! ```
//!
//! They never skip: if BPF cannot load, they fail.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const EXE: &str = env!("CARGO_BIN_EXE_effect-attest");
const WORKLOAD: &str = env!("CARGO_BIN_EXE_ea-workload");

fn object() -> String {
    std::env::var("EFFECT_ATTEST_BPF_OBJ")
        .expect("EFFECT_ATTEST_BPF_OBJ must point to the compiled eBPF object")
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ea-kernel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
#[ignore = "needs root and BPF; run with sudo (see module docs)"]
fn single_call_is_attested_and_verifies() {
    // SAFETY: geteuid has no preconditions.
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as root");
    let d = tmpdir("single");
    let prefix = d.join("k");
    assert!(Command::new(EXE)
        .args(["keygen", "--out"])
        .arg(&prefix)
        .status()
        .unwrap()
        .success());
    let catalog = d.join("catalog.json");
    std::fs::write(
        &catalog,
        json!({"tools":[{"name":"wl","command":[WORKLOAD]}]}).to_string(),
    )
    .unwrap();
    let attest = d.join("attest");
    let w = d.join("written");
    let r = d.join("only-read");
    std::fs::write(&r, "x").unwrap();

    let mut child = Command::new(EXE)
        .args(["serve", "--catalog"])
        .arg(&catalog)
        .arg("--key")
        .arg(prefix.with_extension("key"))
        .args(["--bpf-object", &object(), "--attest-dir"])
        .arg(&attest)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    writeln!(
        stdin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    writeln!(
        stdin,
        "{}",
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"wl","arguments":{"args":[
            "--read", r.to_str().unwrap(), "--write", w.to_str().unwrap(), "--fork", "--exec", "/bin/true"]}}})
    )
    .unwrap();
    drop(stdin);
    let lines: Vec<Value> = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map(|l| serde_json::from_str(&l.unwrap()).unwrap())
        .collect();
    assert!(child.wait().unwrap().success(), "server failed (BPF load?)");
    let call = lines
        .iter()
        .find(|v| v["id"] == 2)
        .expect("tools/call response");
    assert_eq!(call["result"]["isError"], false, "{call}");

    let files: Vec<PathBuf> = std::fs::read_dir(&attest)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 1);
    let out = Command::new(EXE)
        .args(["verify", "--require-complete", "--print", "--pubkey"])
        .arg(prefix.with_extension("pub"))
        .arg(&files[0])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let st: Value = serde_json::from_slice(&out.stdout).unwrap();
    let effects = st["predicate"]["effects"].as_array().unwrap();
    let has = |kind: &str, target: &str| {
        effects.iter().any(|e| {
            e["kind"] == kind && e["target"] == target && e["ret"].as_i64().unwrap_or(-1) >= 0
        })
    };
    assert!(has("exec", WORKLOAD), "{effects:#?}");
    assert!(has("open_write", w.to_str().unwrap()), "{effects:#?}");
    assert!(has("exec", "/bin/true"), "{effects:#?}");
    assert!(
        !effects.iter().any(|e| e["target"] == r.to_str().unwrap()),
        "read-only open must not be reported: {effects:#?}"
    );
    // The envelope in the response is the same as the one on disk.
    let meta_env = &call["result"]["_meta"]["io.github.federiconbaez/effect-attest.envelope"];
    let disk: Value = serde_json::from_slice(&std::fs::read(&files[0]).unwrap()).unwrap();
    assert_eq!(meta_env, &disk);
}

#[test]
#[ignore = "needs root and BPF; run with sudo (see module docs)"]
fn bench_50_tools_meets_criterion() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "must run as root");
    let out = std::env::temp_dir().join(format!("ea-bench-report-{}.json", std::process::id()));
    let st = Command::new(EXE)
        .args([
            "bench",
            "--tools",
            "50",
            "--rounds",
            "3",
            "--bpf-object",
            &object(),
            "--out",
        ])
        .arg(&out)
        .args(["--workload", WORKLOAD])
        .status()
        .unwrap();
    assert!(
        st.success(),
        "bench failed the acceptance criterion or could not load BPF"
    );
    let r: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(r["calls"], 150);
    assert!(r["completeness"].as_f64().unwrap() >= 0.99, "{r}");
    assert_eq!(r["misattributions"], 0, "{r}");
}
