//! Completeness / attribution bench.
//!
//! Generates N tools with known effects (ground truth by construction),
//! runs them concurrently through `effect-attest serve` (a real MCP stdio
//! session), verifies every envelope and compares the signed effects with
//! the ground truth.
//!
//! Each round uses fresh paths and listening ports, and every path or address
//! encodes the (round, tool) pair, so an effect that shows up in the wrong
//! call's attestation is detected as a misattribution.
use crate::dsse::Envelope;
use crate::server::{META_ENVELOPE, SERVER_NAME};
use crate::statement::{self, Policy};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub struct BenchOpts {
    pub tools: usize,
    pub rounds: usize,
    pub bpf_object: PathBuf,
    pub cgroup_root: PathBuf,
    pub workload: PathBuf,
    pub out: Option<PathBuf>,
    pub min_completeness: f64,
    pub baseline: bool,
}

/// One expected effect.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Expected {
    pub kind: &'static str,
    pub target: String,
}

/// Generated call: tool name, arguments, expected effects, and the tokens
/// (path prefix, socket addresses) that identify it.
#[derive(Clone, Debug)]
pub struct CaseCall {
    pub tool: String,
    pub args: Vec<String>,
    pub expected: Vec<Expected>,
    pub prefix: String,
    /// Socket addresses (`ip:port`) this call connects to. Compared as full
    /// strings: IPv4 and IPv6 listeners can share a port number.
    pub addrs: Vec<String>,
    pub pattern: &'static str,
}

pub const PATTERNS: [&str; 6] = ["direct", "fork", "thread", "shell", "daemon", "variants"];

fn which_true() -> Result<PathBuf> {
    for p in ["/usr/bin/true", "/bin/true"] {
        if Path::new(p).exists() {
            return Ok(PathBuf::from(p));
        }
    }
    bail!("no true(1) binary found")
}

/// Build round `r`, tool `i`. Creates directories and exec symlinks under
/// `base`; `ports` are already-bound listener ports for this call (two).
pub fn make_case(
    base: &Path,
    r: usize,
    i: usize,
    ports: [u16; 2],
    v6: bool,
    workload: &Path,
    true_bin: &Path,
) -> Result<CaseCall> {
    let dir = base.join(format!("r{r}")).join(format!("t{i:02}"));
    std::fs::create_dir_all(&dir)?;
    let p = |n: &str| dir.join(n).to_string_lossy().into_owned();
    let x0 = p("x0");
    let _ = std::fs::remove_file(&x0);
    std::os::unix::fs::symlink(true_bin, &x0)?;
    let (w0, w1) = (p("w0"), p("w1"));
    let a = format!("127.0.0.1:{}", ports[0]);
    let b = if v6 {
        format!("[::1]:{}", ports[1])
    } else {
        format!("127.0.0.1:{}", ports[1])
    };
    let sleep = ((i * 7) % 40).to_string();
    let wl = workload.to_string_lossy().into_owned();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let pattern = PATTERNS[i % PATTERNS.len()];
    let ex = |kind, t: &str| Expected {
        kind,
        target: t.to_string(),
    };
    let (args, mut expected) = match pattern {
        "direct" => (
            s(&[
                "--write",
                &w0,
                "--sleep",
                &sleep,
                "--exec",
                &x0,
                "--write",
                &w1,
                "--connect",
                &a,
            ]),
            vec![
                ex("open_write", &w0),
                ex("exec", &x0),
                ex("open_write", &w1),
                ex("connect", &a),
            ],
        ),
        "fork" => (
            s(&[
                "--write",
                &w0,
                "--fork",
                "--exec",
                &x0,
                "--sleep",
                &sleep,
                "--write",
                &w1,
                "--connect",
                &a,
            ]),
            vec![
                ex("open_write", &w0),
                ex("exec", &x0),
                ex("open_write", &w1),
                ex("connect", &a),
            ],
        ),
        "thread" => (
            s(&[
                "--thread",
                "--write",
                &w0,
                "--exec",
                &x0,
                "--sleep",
                &sleep,
                "--connect",
                &a,
                "--write",
                &w1,
            ]),
            vec![
                ex("open_write", &w0),
                ex("exec", &x0),
                ex("connect", &a),
                ex("open_write", &w1),
            ],
        ),
        "shell" => (
            s(&[&w0, &x0, &wl, &sleep, &w1, &a]),
            vec![
                ex("open_write", &w0),
                ex("exec", &x0),
                ex("exec", &wl),
                ex("open_write", &w1),
                ex("connect", &a),
            ],
        ),
        "daemon" => (
            s(&[
                "--write",
                &w0,
                "--daemon",
                "--sleep",
                "150",
                "--write",
                &w1,
                "--exec",
                &x0,
                "--connect",
                &a,
            ]),
            vec![
                ex("open_write", &w0),
                ex("open_write", &w1),
                ex("exec", &x0),
                ex("connect", &a),
            ],
        ),
        _ => (
            s(&[
                "--creat",
                &w0,
                "--openat2",
                &w1,
                "--read",
                "/etc/hostname",
                "--execveat",
                &x0,
                "--sleep",
                &sleep,
                "--connect",
                &b,
            ]),
            vec![
                ex("open_write", &w0),
                ex("open_write", &w1),
                ex("exec", &x0),
                ex("connect", &b),
            ],
        ),
    };
    // The call's own first exec (the tool program).
    let program = if pattern == "shell" {
        "/bin/sh".to_string()
    } else {
        wl.clone()
    };
    expected.insert(0, ex("exec", &program));
    Ok(CaseCall {
        tool: format!("t{i:02}"),
        args,
        expected,
        prefix: format!("{}/", dir.to_string_lossy()),
        addrs: if pattern == "variants" {
            vec![b]
        } else {
            vec![a]
        },
        pattern,
    })
}

/// Catalog for `n` tools.
pub fn catalog_json(n: usize, workload: &Path) -> Value {
    let wl = workload.to_string_lossy();
    let tools: Vec<Value> = (0..n)
        .map(|i| {
            let command = if PATTERNS[i % PATTERNS.len()] == "shell" {
                json!(["/bin/sh", "-c",
                    "echo a > \"$1\" && \"$2\" && exec \"$3\" --sleep \"$4\" --write \"$5\" --connect \"$6\"",
                    "sh"])
            } else {
                json!([wl])
            };
            json!({"name": format!("t{i:02}"), "description": format!("bench tool {i}"),
                   "command": command, "timeout_ms": 20000})
        })
        .collect();
    json!({ "tools": tools })
}

/// Per-call evaluation.
#[derive(Debug, Default, Serialize)]
pub struct CallEval {
    pub tool: String,
    pub pattern: &'static str,
    pub round: usize,
    pub expected: usize,
    pub found: usize,
    pub missing: Vec<Expected>,
    /// Effects carrying another call's path prefix or port.
    pub misattributed: Vec<String>,
    pub verify_us: u128,
    pub latency_ms: f64,
    pub drained: bool,
    /// Effects in the attestation.
    pub effects_seen: usize,
    /// The tool itself reported an error (stderr), so ground truth may not
    /// have happened.
    pub tool_error: Option<String>,
    pub error: Option<String>,
}

fn effect_matches(e: &crate::effects::Effect, x: &Expected) -> bool {
    if e.kind != x.kind || e.target != x.target {
        return false;
    }
    match x.kind {
        // A connect attempt is the effect, whatever the handshake result.
        "connect" => true,
        _ => e.succeeded(),
    }
}

/// Evaluate one response against its case and all cases of the round.
pub fn evaluate(
    case: &CaseCall,
    all: &[CaseCall],
    id: &Value,
    resp: &Value,
    key: &ed25519_dalek::VerifyingKey,
) -> CallEval {
    let mut ev = CallEval {
        tool: case.tool.clone(),
        pattern: case.pattern,
        expected: case.expected.len(),
        missing: case.expected.clone(),
        ..Default::default()
    };
    let res = || -> Result<()> {
        let result = resp.get("result").context("no result")?;
        let env: Envelope = serde_json::from_value(
            result
                .get("_meta")
                .and_then(|m| m.get(META_ENVELOPE))
                .cloned()
                .context("no envelope in _meta")?,
        )?;
        let t0 = Instant::now();
        let st = statement::verify_envelope(&env, key)?;
        let policy = Policy {
            require_complete: true,
            expect_request: Some((case.tool.clone(), json!({"args": case.args}), id.clone())),
        };
        statement::check_policy(&st, &policy)?;
        ev.verify_us = t0.elapsed().as_micros();
        let mut bare = result.clone();
        bare.as_object_mut().unwrap().remove("_meta");
        let want = statement::subjects(&case.tool, id, &json!({"args": case.args}), &bare);
        if st.subject != want {
            bail!("result subject does not match the returned result");
        }
        ev.drained = st.predicate.integrity.cgroup_drained;
        ev.effects_seen = st.predicate.effects.len();
        if result["isError"] == true {
            ev.tool_error = Some(result["content"].to_string());
        }
        for e in &st.predicate.effects {
            for other in all.iter().filter(|o| o.tool != case.tool) {
                let foreign_path = e.target.starts_with(&other.prefix);
                let foreign_port = e.kind == "connect" && other.addrs.contains(&e.target);
                if foreign_path || foreign_port {
                    ev.misattributed.push(format!(
                        "{} {} (belongs to {})",
                        e.kind, e.target, other.tool
                    ));
                }
            }
        }
        ev.missing
            .retain(|x| !st.predicate.effects.iter().any(|e| effect_matches(e, x)));
        ev.found = ev.expected - ev.missing.len();
        Ok(())
    }();
    if let Err(e) = res {
        ev.error = Some(format!("{e:#}"));
        ev.found = 0;
    }
    ev
}

struct Session {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    rx: mpsc::Receiver<(Instant, Value)>,
}

impl Session {
    fn start(exe: &Path, args: &[String]) -> Result<Self> {
        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("spawning server")?;
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Ok(v) = serde_json::from_str::<Value>(&line) {
                    if tx.send((Instant::now(), v)).is_err() {
                        break;
                    }
                }
            }
        });
        let mut s = Session { child, stdin, rx };
        s.send(&json!({"jsonrpc":"2.0","id":"init","method":"initialize",
            "params":{"protocolVersion":"2025-11-25","capabilities":{},
                      "clientInfo":{"name":"effect-attest-bench","version":"0"}}}))?;
        let (_, v) =
            s.rx.recv_timeout(Duration::from_secs(60))
                .context("no initialize response (did the server fail to load BPF?)")?;
        if v["result"]["serverInfo"]["name"] != SERVER_NAME {
            bail!("unexpected initialize response: {v}");
        }
        s.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
        Ok(s)
    }

    fn send(&mut self, v: &Value) -> Result<()> {
        writeln!(self.stdin, "{v}")?;
        self.stdin.flush()?;
        Ok(())
    }

    /// Send all calls at once, return (id -> (latency, response)).
    fn round(
        &mut self,
        calls: &[(Value, String, Vec<String>)],
    ) -> Result<HashMap<String, (f64, Value)>> {
        let mut sent = HashMap::new();
        for (id, tool, args) in calls {
            sent.insert(id.to_string(), Instant::now());
            self.send(&json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
                "params":{"name":tool,"arguments":{"args":args}}}))?;
        }
        let mut out = HashMap::new();
        while out.len() < calls.len() {
            let (t, v) = self
                .rx
                .recv_timeout(Duration::from_secs(120))
                .context("timed out waiting for tools/call responses")?;
            let k = v["id"].to_string();
            if let Some(t0) = sent.get(&k) {
                out.insert(k, ((t - *t0).as_secs_f64() * 1e3, v));
            }
        }
        Ok(out)
    }

    fn close(mut self) {
        drop(self.stdin);
        let _ = self.child.wait();
    }
}

fn percentile(v: &mut [f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((p / 100.0) * (v.len() - 1) as f64).round() as usize;
    v[idx]
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub tools: usize,
    pub rounds: usize,
    pub calls: usize,
    pub kernel: String,
    pub ipv6: bool,
    pub expected_effects: usize,
    pub found_effects: usize,
    pub completeness: f64,
    pub misattributions: usize,
    pub calls_with_errors: usize,
    pub calls_not_drained: usize,
    pub verify_us_p50: f64,
    pub verify_us_p99: f64,
    pub latency_ms_p50: f64,
    pub latency_ms_p99: f64,
    pub baseline_latency_ms_p50: Option<f64>,
    pub baseline_latency_ms_p99: Option<f64>,
    pub by_pattern: Vec<(String, usize, usize)>,
    pub failures: Vec<CallEval>,
}

pub fn run(opts: &BenchOpts) -> Result<Report> {
    let exe = std::env::current_exe()?;
    let base = std::env::temp_dir().join(format!("ea-bench-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    let true_bin = which_true()?;
    let v6 = TcpListener::bind("[::1]:0").is_ok();

    let key = crate::dsse::keys::generate()?;
    let key_prefix = base.join("bench");
    crate::dsse::keys::write_pair(&key, &key_prefix)?;
    let catalog = base.join("catalog.json");
    std::fs::write(
        &catalog,
        serde_json::to_vec_pretty(&catalog_json(opts.tools, &opts.workload))?,
    )?;

    // Listeners for every (round, tool): kept open for the whole bench.
    let mut listeners = Vec::new();
    let mut cases: Vec<Vec<CaseCall>> = Vec::new();
    for r in 0..opts.rounds {
        let mut round = Vec::new();
        for i in 0..opts.tools {
            let l4 = TcpListener::bind("127.0.0.1:0")?;
            let l2 = if v6 {
                TcpListener::bind("[::1]:0")?
            } else {
                TcpListener::bind("127.0.0.1:0")?
            };
            let ports = [l4.local_addr()?.port(), l2.local_addr()?.port()];
            listeners.push(l4);
            listeners.push(l2);
            round.push(make_case(
                &base,
                r,
                i,
                ports,
                v6,
                &opts.workload,
                &true_bin,
            )?);
        }
        cases.push(round);
    }

    let s = |p: &Path| p.to_string_lossy().into_owned();
    let mut session = Session::start(
        &exe,
        &[
            "serve".into(),
            "--catalog".into(),
            s(&catalog),
            "--key".into(),
            s(&key_prefix.with_extension("key")),
            "--bpf-object".into(),
            s(&opts.bpf_object),
            "--cgroup-root".into(),
            s(&opts.cgroup_root),
        ],
    )?;
    let mut evals = Vec::new();
    for (r, round) in cases.iter().enumerate() {
        let calls: Vec<(Value, String, Vec<String>)> = round
            .iter()
            .enumerate()
            .map(|(i, c)| (json!(r * 1000 + i), c.tool.clone(), c.args.clone()))
            .collect();
        let resp = session.round(&calls)?;
        for (i, c) in round.iter().enumerate() {
            let id = json!(r * 1000 + i);
            let (lat, v) = &resp[&id.to_string()];
            let mut ev = evaluate(c, round, &id, v, &key.verifying_key());
            ev.round = r;
            ev.latency_ms = *lat;
            evals.push(ev);
        }
    }
    session.close();

    let (mut b50, mut b99) = (None, None);
    if opts.baseline {
        let mut session = Session::start(
            &exe,
            &[
                "serve".into(),
                "--catalog".into(),
                s(&catalog),
                "--unattested".into(),
            ],
        )?;
        let mut lats = Vec::new();
        for (r, round) in cases.iter().enumerate() {
            let calls: Vec<(Value, String, Vec<String>)> = round
                .iter()
                .enumerate()
                .map(|(i, c)| (json!(r * 1000 + i), c.tool.clone(), c.args.clone()))
                .collect();
            lats.extend(session.round(&calls)?.values().map(|(l, _)| *l));
        }
        session.close();
        b50 = Some(percentile(&mut lats.clone(), 50.0));
        b99 = Some(percentile(&mut lats, 99.0));
    }
    drop(listeners);

    let expected: usize = evals.iter().map(|e| e.expected).sum();
    let found: usize = evals.iter().map(|e| e.found).sum();
    let mut verify: Vec<f64> = evals
        .iter()
        .filter(|e| e.error.is_none())
        .map(|e| e.verify_us as f64)
        .collect();
    let mut lat: Vec<f64> = evals.iter().map(|e| e.latency_ms).collect();
    let mut by_pattern = Vec::new();
    for p in PATTERNS {
        let (x, f) = evals
            .iter()
            .filter(|e| e.pattern == p)
            .fold((0, 0), |(x, f), e| (x + e.expected, f + e.found));
        by_pattern.push((p.to_string(), f, x));
    }
    let report = Report {
        tools: opts.tools,
        rounds: opts.rounds,
        calls: evals.len(),
        kernel: crate::server::kernel_release(),
        ipv6: v6,
        expected_effects: expected,
        found_effects: found,
        completeness: if expected == 0 {
            0.0
        } else {
            found as f64 / expected as f64
        },
        misattributions: evals.iter().map(|e| e.misattributed.len()).sum(),
        calls_with_errors: evals.iter().filter(|e| e.error.is_some()).count(),
        calls_not_drained: evals
            .iter()
            .filter(|e| e.error.is_none() && !e.drained)
            .count(),
        verify_us_p50: percentile(&mut verify.clone(), 50.0),
        verify_us_p99: percentile(&mut verify, 99.0),
        latency_ms_p50: percentile(&mut lat.clone(), 50.0),
        latency_ms_p99: percentile(&mut lat, 99.0),
        baseline_latency_ms_p50: b50,
        baseline_latency_ms_p99: b99,
        by_pattern,
        failures: evals
            .into_iter()
            .filter(|e| e.error.is_some() || !e.missing.is_empty() || !e.misattributed.is_empty())
            .collect(),
    };
    if let Some(out) = &opts.out {
        std::fs::write(out, serde_json::to_vec_pretty(&report)?)?;
    }
    let _ = std::fs::remove_dir_all(&base);
    Ok(report)
}

/// Pass/fail against the acceptance criterion.
pub fn check(r: &Report, min_completeness: f64) -> Result<()> {
    let mut errs = Vec::new();
    if r.completeness < min_completeness {
        errs.push(format!(
            "completeness {:.4} < {min_completeness}",
            r.completeness
        ));
    }
    if r.misattributions != 0 {
        errs.push(format!("{} misattributions", r.misattributions));
    }
    if r.calls_with_errors != 0 {
        errs.push(format!("{} calls failed verification", r.calls_with_errors));
    }
    if errs.is_empty() {
        Ok(())
    } else {
        bail!(errs.join("; "))
    }
}

/// Read an envelope file and verify it.
pub fn verify_file(path: &Path, key: &ed25519_dalek::VerifyingKey) -> Result<statement::Statement> {
    let env: Envelope = serde_json::from_slice(&std::fs::read(path)?)
        .with_context(|| format!("parsing {}", path.display()))?;
    statement::verify_envelope(&env, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::Effect;

    fn eff(kind: &str, target: &str, ret: i64) -> Effect {
        Effect {
            kind: kind.into(),
            syscall: "x".into(),
            target: target.into(),
            target_incomplete: false,
            dirfd: None,
            flags: None,
            ret: Some(ret),
            pid: 1,
            tid: 1,
            comm: "c".into(),
            ts_ns: 0,
        }
    }

    #[test]
    fn matching_rules() {
        let x = Expected {
            kind: "open_write",
            target: "/a".into(),
        };
        assert!(effect_matches(&eff("open_write", "/a", 3), &x));
        assert!(
            !effect_matches(&eff("open_write", "/a", -2), &x),
            "failed open is not the effect"
        );
        assert!(!effect_matches(&eff("exec", "/a", 0), &x));
        let c = Expected {
            kind: "connect",
            target: "127.0.0.1:1".into(),
        };
        assert!(effect_matches(&eff("connect", "127.0.0.1:1", -115), &c));
    }

    #[test]
    fn cases_have_disjoint_tokens() {
        let base = std::env::temp_dir().join(format!("ea-case-test-{}", std::process::id()));
        let wl = Path::new("/opt/wl");
        let t = which_true().unwrap();
        let cases: Vec<CaseCall> = (0..12)
            .map(|i| {
                make_case(
                    &base,
                    0,
                    i,
                    [1000 + i as u16, 2000 + i as u16],
                    true,
                    wl,
                    &t,
                )
                .unwrap()
            })
            .collect();
        for (i, a) in cases.iter().enumerate() {
            assert_eq!(a.pattern, PATTERNS[i % 6]);
            assert!(a.expected.len() >= 5);
            for b in &cases[i + 1..] {
                assert!(!a.prefix.starts_with(&b.prefix) && !b.prefix.starts_with(&a.prefix));
                assert!(a.addrs.iter().all(|x| !b.addrs.contains(x)));
            }
        }
        let cat = catalog_json(12, wl);
        crate::config::Catalog::parse(&cat.to_string()).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn percentile_basics() {
        let mut v = vec![5.0, 1.0, 3.0, 2.0, 4.0];
        assert_eq!(percentile(&mut v, 50.0), 3.0);
        assert_eq!(percentile(&mut v, 100.0), 5.0);
        assert!(percentile(&mut [], 50.0).is_nan());
    }

    #[test]
    fn evaluate_detects_misattribution_and_missing() {
        use crate::statement::{Call, Integrity, Observer, Predicate, Statement};
        let base = std::env::temp_dir().join(format!("ea-eval-test-{}", std::process::id()));
        let wl = Path::new("/opt/wl");
        let t = which_true().unwrap();
        let cases: Vec<CaseCall> = (0..2)
            .map(|i| {
                make_case(
                    &base,
                    0,
                    i,
                    [3000 + i as u16, 4000 + i as u16],
                    false,
                    wl,
                    &t,
                )
                .unwrap()
            })
            .collect();
        let me = &cases[0];
        let other = &cases[1];
        // All of tool 0's effects, plus one write that belongs to tool 1.
        let mut effects: Vec<Effect> = me
            .expected
            .iter()
            .map(|x| eff(x.kind, &x.target, 0))
            .collect();
        effects.push(eff("open_write", &other.expected[1].target, 3));
        effects.remove(1);
        let id = json!(0);
        let args = json!({"args": me.args});
        let result = json!({"content": [{"type": "text", "text": "ok"}], "isError": false});
        let st = Statement::new(
            statement::subjects(&me.tool, &id, &args, &result),
            Predicate {
                observer: Observer {
                    mechanism: "m".into(),
                    kernel: "k".into(),
                    syscalls: vec![],
                    version: "0".into(),
                },
                call: Call {
                    tool: me.tool.clone(),
                    request_id: id.clone(),
                    arguments: args,
                    argv: vec![],
                    cgroup_id: 1,
                    started_at: "a".into(),
                    finished_at: "b".into(),
                    exit_code: Some(0),
                    signal: None,
                    killed_leftovers: false,
                },
                effects,
                integrity: Integrity {
                    cgroup_drained: true,
                    ..Default::default()
                },
            },
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let mut resp_result = result.clone();
        resp_result["_meta"] = json!({ META_ENVELOPE: st.sign(&key) });
        let resp = json!({"jsonrpc": "2.0", "id": 0, "result": resp_result});
        let ev = evaluate(me, &cases, &id, &resp, &key.verifying_key());
        assert_eq!(ev.error, None);
        assert_eq!(ev.misattributed.len(), 1, "{ev:?}");
        assert_eq!(ev.missing.len(), 1);
        assert_eq!(ev.found, ev.expected - 1);
        // A different key fails verification and counts nothing as found.
        let ev = evaluate(
            me,
            &cases,
            &id,
            &resp,
            &ed25519_dalek::SigningKey::from_bytes(&[5; 32]).verifying_key(),
        );
        assert!(ev.error.is_some());
        assert_eq!(ev.found, 0);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
