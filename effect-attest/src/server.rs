//! MCP server over stdio. `tools/call` runs the tool's command in its own
//! cgroup, collects the kernel-observed effects, and returns them signed as
//! an in-toto statement in a DSSE envelope under `result._meta`.
use crate::cgroup::{join_from_child, CallCgroup};
use crate::config::{Catalog, ToolDef};
use crate::effects::Effect;
use crate::jsonrpc::{self, Incoming};
use crate::statement::{self, Call, Integrity, Observer, Predicate, Statement};
use crate::tracer::Tracer;
use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{BufRead, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const SERVER_NAME: &str = "cortex9-effect-attest";
pub const SUPPORTED_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
/// Key under `result._meta` holding the DSSE envelope.
pub const META_ENVELOPE: &str = "io.github.federiconbaez/effect-attest.envelope";
/// Key under `result._meta` with the SHA-256 of the statement bytes.
pub const META_DIGEST: &str = "io.github.federiconbaez/effect-attest.statement_sha256";
const MAX_OUTPUT: usize = 64 * 1024;

/// Everything needed to observe and sign calls.
pub struct Attestor {
    pub tracer: Tracer,
    pub cgroup_root: PathBuf,
    pub key: SigningKey,
    pub attest_dir: Option<PathBuf>,
    /// How long to wait for leftover descendants after the main process exits.
    pub grace: Duration,
    pub kernel: String,
}

pub struct Server {
    pub catalog: Catalog,
    pub attestor: Option<Attestor>,
    seq: AtomicU64,
}

/// Result of running one tool command.
pub struct Outcome {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub started_at: String,
    pub finished_at: String,
    /// Present when attested.
    pub observed: Option<Observed>,
}

pub struct Observed {
    pub cgroup_id: u64,
    pub effects: Vec<Effect>,
    pub drained: bool,
    pub killed_leftovers: bool,
    pub drops: u64,
}

fn read_capped(mut r: impl Read) -> String {
    let mut buf = Vec::new();
    let _ = r.by_ref().take(MAX_OUTPUT as u64).read_to_end(&mut buf);
    // Keep draining so the writer never blocks on a full pipe.
    let _ = std::io::copy(&mut r, &mut std::io::sink());
    String::from_utf8_lossy(&buf).into_owned()
}

pub fn kernel_release() -> String {
    // SAFETY: uname fills a zeroed utsname.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut u) } != 0 {
        return "unknown".into();
    }
    let r: Vec<u8> = u
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&r).into_owned()
}

impl Server {
    pub fn new(catalog: Catalog, attestor: Option<Attestor>) -> Self {
        Server {
            catalog,
            attestor,
            seq: AtomicU64::new(0),
        }
    }

    fn tools_list(&self) -> Value {
        let tools: Vec<Value> = self
            .catalog
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "args": {"type": "array", "items": {"type": "string"}}
                        },
                        "additionalProperties": false
                    }
                })
            })
            .collect();
        json!({ "tools": tools })
    }

    fn initialize(&self, params: &Value) -> Value {
        let asked = params.get("protocolVersion").and_then(Value::as_str);
        let version = asked
            .filter(|v| SUPPORTED_VERSIONS.contains(v))
            .unwrap_or(SUPPORTED_VERSIONS[0]);
        json!({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
            "instructions": if self.attestor.is_some() {
                "Each tools/call result carries a signed in-toto statement of its kernel-observed effects in _meta."
            } else {
                "Running WITHOUT attestation: effects are not observed."
            }
        })
    }

    /// Run one tool, attested when an attestor is configured.
    pub fn run_tool(&self, def: &ToolDef, args: &[String]) -> Result<Outcome> {
        let n = self.seq.fetch_add(1, Ordering::Relaxed);
        let mut cmd = Command::new(&def.command[0]);
        cmd.args(&def.command[1..])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let cg = match &self.attestor {
            Some(a) => {
                let cg = CallCgroup::create(
                    &a.cgroup_root,
                    &format!("call-{}-{n}", std::process::id()),
                )?;
                a.tracer.register(cg.id())?;
                let fd = cg.procs_fd();
                // SAFETY: the hook only calls write(2), which is
                // async-signal-safe.
                unsafe { cmd.pre_exec(move || join_from_child(fd)) };
                Some(cg)
            }
            None => None,
        };
        let drops_before = self.attestor.as_ref().map(|a| a.tracer.dropped());
        let started_at = crate::timefmt::now();
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                if let (Some(a), Some(cg)) = (&self.attestor, &cg) {
                    let _ = a.tracer.finish(cg.id());
                }
                return Err(e).with_context(|| format!("spawning {:?}", def.command));
            }
        };
        let out = child
            .stdout
            .take()
            .map(|s| std::thread::spawn(|| read_capped(s)));
        let err = child
            .stderr
            .take()
            .map(|s| std::thread::spawn(|| read_capped(s)));

        let deadline = Instant::now() + Duration::from_millis(def.timeout_ms);
        let mut timed_out = false;
        let status = loop {
            if let Some(st) = child.try_wait()? {
                break st;
            }
            if Instant::now() >= deadline {
                timed_out = true;
                match &cg {
                    Some(cg) => cg.kill_all(),
                    None => {
                        let _ = child.kill();
                    }
                }
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(1));
        };

        let observed = match (&self.attestor, &cg) {
            (Some(a), Some(cg)) => {
                let mut killed = false;
                let mut drained = cg.wait_empty(a.grace);
                if !drained {
                    killed = true;
                    cg.kill_all();
                    drained = cg.wait_empty(Duration::from_secs(2));
                }
                let effects = a.tracer.finish(cg.id());
                Some(Observed {
                    cgroup_id: cg.id(),
                    effects,
                    drained,
                    killed_leftovers: killed,
                    drops: a.tracer.dropped() - drops_before.unwrap_or(0),
                })
            }
            _ => None,
        };
        drop(cg);
        let stdout = out
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        let stderr = err
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        Ok(Outcome {
            stdout,
            stderr,
            exit_code: status.code(),
            signal: status.signal(),
            timed_out,
            started_at,
            finished_at: crate::timefmt::now(),
            observed,
        })
    }

    fn tools_call(&self, id: &Value, params: &Value) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, "missing tool name");
        };
        let Some(def) = self.catalog.get(name) else {
            return jsonrpc::error(id, jsonrpc::INVALID_PARAMS, &format!("unknown tool {name}"));
        };
        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
        let args: Vec<String> = match arguments.get("args") {
            None => vec![],
            Some(Value::Array(a)) if a.iter().all(Value::is_string) => {
                a.iter().map(|v| v.as_str().unwrap().to_string()).collect()
            }
            Some(_) => {
                return jsonrpc::error(
                    id,
                    jsonrpc::INVALID_PARAMS,
                    "arguments.args must be an array of strings",
                )
            }
        };
        let outcome = match self.run_tool(def, &args) {
            Ok(o) => o,
            Err(e) => return jsonrpc::error(id, jsonrpc::INTERNAL_ERROR, &format!("{e:#}")),
        };
        let mut content = vec![json!({"type": "text", "text": outcome.stdout})];
        if !outcome.stderr.is_empty() {
            content.push(json!({"type": "text", "text": format!("stderr:\n{}", outcome.stderr)}));
        }
        let mut result = json!({
            "content": content,
            "isError": outcome.timed_out || outcome.exit_code != Some(0),
        });
        if let (Some(a), Some(obs)) = (&self.attestor, outcome.observed) {
            let incomplete = obs.effects.iter().filter(|e| e.target_incomplete).count() as u64;
            let mut argv = def.command.clone();
            argv.extend(args.iter().cloned());
            let pred = Predicate {
                observer: Observer {
                    mechanism: "ebpf:raw_syscalls+cgroup_v2".into(),
                    kernel: a.kernel.clone(),
                    syscalls: crate::syscalls::table()
                        .iter()
                        .map(|(_, n, _)| n.to_string())
                        .collect(),
                    version: env!("CARGO_PKG_VERSION").into(),
                },
                call: Call {
                    tool: name.into(),
                    request_id: id.clone(),
                    arguments: arguments.clone(),
                    argv,
                    cgroup_id: obs.cgroup_id,
                    started_at: outcome.started_at,
                    finished_at: outcome.finished_at,
                    exit_code: outcome.exit_code,
                    signal: outcome.signal,
                    killed_leftovers: obs.killed_leftovers,
                },
                effects: obs.effects,
                integrity: Integrity {
                    cgroup_drained: obs.drained,
                    ring_drops_during_call: obs.drops,
                    incomplete_targets: incomplete,
                },
            };
            let st = Statement::new(statement::subjects(name, id, &arguments, &result), pred);
            let env = st.sign(&a.key);
            let digest = crate::dsse::b64decode(&env.payload)
                .map(|b| statement::sha256_hex(&b))
                .unwrap_or_default();
            if let Some(dir) = &a.attest_dir {
                let path = dir.join(format!("{}.dsse.json", &digest[..16]));
                if let Err(e) = std::fs::write(&path, serde_json::to_vec_pretty(&env).unwrap()) {
                    eprintln!("effect-attest: writing {}: {e}", path.display());
                }
            }
            result["_meta"] = json!({ META_ENVELOPE: env, META_DIGEST: digest });
        }
        jsonrpc::response(id, result)
    }

    /// Serve until EOF on `input`. `tools/call` requests run concurrently.
    pub fn serve(self: Arc<Self>, input: impl BufRead, output: Arc<Mutex<dyn Write + Send>>) {
        let send = |out: &Arc<Mutex<dyn Write + Send>>, v: Value| {
            let mut w = out.lock().unwrap();
            let _ = writeln!(w, "{v}");
            let _ = w.flush();
        };
        let mut workers = Vec::new();
        for line in input.lines() {
            let Ok(line) = line else { break };
            if line.trim().is_empty() {
                continue;
            }
            match jsonrpc::parse_line(&line) {
                Incoming::Invalid(err) => send(&output, err),
                Incoming::Notification { .. } => {}
                Incoming::Request { id, method, params } => match method.as_str() {
                    "initialize" => send(&output, jsonrpc::response(&id, self.initialize(&params))),
                    "ping" => send(&output, jsonrpc::response(&id, json!({}))),
                    "tools/list" => send(&output, jsonrpc::response(&id, self.tools_list())),
                    "tools/call" => {
                        let me = Arc::clone(&self);
                        let out = Arc::clone(&output);
                        workers.push(std::thread::spawn(move || {
                            let resp = me.tools_call(&id, &params);
                            send(&out, resp);
                        }));
                    }
                    other => send(
                        &output,
                        jsonrpc::error(
                            &id,
                            jsonrpc::METHOD_NOT_FOUND,
                            &format!("method not found: {other}"),
                        ),
                    ),
                },
            }
        }
        for w in workers {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> Arc<Server> {
        let catalog = Catalog::parse(
            r#"{"tools":[
                {"name":"echo","command":["/bin/sh","-c","echo \"$@\"","sh"]},
                {"name":"fail","command":["/bin/sh","-c","echo oops >&2; exit 3"]},
                {"name":"slow","command":["/bin/sh","-c","sleep 5"],"timeout_ms":100}
            ]}"#,
        )
        .unwrap();
        Arc::new(Server::new(catalog, None))
    }

    fn roundtrip(lines: &[&str]) -> Vec<Value> {
        let out: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let input = lines.join("\n");
        server().serve(std::io::Cursor::new(input), out.clone());
        let bytes = out.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn by_id(v: &[Value], id: i64) -> &Value {
        v.iter().find(|r| r["id"] == id).expect("response")
    }

    #[test]
    fn initialize_negotiates_version() {
        let r = roundtrip(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        ]);
        assert_eq!(r.len(), 2, "notifications get no response");
        assert_eq!(by_id(&r, 1)["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(
            by_id(&r, 2)["result"]["protocolVersion"],
            SUPPORTED_VERSIONS[0]
        );
        assert_eq!(by_id(&r, 1)["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn list_ping_and_unknown() {
        let r = roundtrip(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"resources/list"}"#,
            r#"not json"#,
        ]);
        assert_eq!(by_id(&r, 1)["result"]["tools"].as_array().unwrap().len(), 3);
        assert_eq!(by_id(&r, 2)["result"], json!({}));
        assert_eq!(by_id(&r, 3)["error"]["code"], jsonrpc::METHOD_NOT_FOUND);
        assert!(r.iter().any(|v| v["error"]["code"] == jsonrpc::PARSE_ERROR));
    }

    #[test]
    fn unattested_calls_have_no_envelope() {
        let r = roundtrip(&[
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"args":["hola"]}}}"#,
            r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fail"}}"#,
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope"}}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"args":[1]}}}"#,
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"slow"}}"#,
        ]);
        let ok = &by_id(&r, 1)["result"];
        assert_eq!(ok["content"][0]["text"], "hola\n");
        assert_eq!(ok["isError"], false);
        assert!(ok.get("_meta").is_none());
        let fail = &by_id(&r, 2)["result"];
        assert_eq!(fail["isError"], true);
        assert!(fail["content"][1]["text"]
            .as_str()
            .unwrap()
            .contains("oops"));
        assert_eq!(by_id(&r, 3)["error"]["code"], jsonrpc::INVALID_PARAMS);
        assert_eq!(by_id(&r, 4)["error"]["code"], jsonrpc::INVALID_PARAMS);
        assert_eq!(
            by_id(&r, 5)["result"]["isError"],
            true,
            "timeout is an error"
        );
    }

    #[test]
    fn kernel_release_is_not_empty() {
        assert!(!kernel_release().is_empty());
    }
}
