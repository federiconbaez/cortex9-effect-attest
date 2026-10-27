//! `effect-attest` CLI: `keygen`, `serve`, `verify`, `bench`.
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use effect_attest::{bench, config::Catalog, dsse::keys, server, statement};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_OBJECT: &str =
    "effect-attest-ebpf/target/bpfel-unknown-none/release/effect-attest-ebpf";
const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup/effect-attest";

#[derive(Parser)]
#[command(
    name = "effect-attest",
    version,
    about = "Kernel-observed, signed effects of MCP tools/call"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an Ed25519 key pair: <PREFIX>.key (0600) and <PREFIX>.pub.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// MCP server over stdio.
    Serve {
        /// Tool catalog (JSON).
        #[arg(long)]
        catalog: PathBuf,
        /// Signing key (hex seed, from `keygen`).
        #[arg(long, required_unless_present = "unattested")]
        key: Option<PathBuf>,
        /// eBPF object.
        #[arg(long, env = "EFFECT_ATTEST_BPF_OBJ", default_value = DEFAULT_OBJECT)]
        bpf_object: PathBuf,
        /// Parent directory for per-call cgroups (cgroup v2).
        #[arg(long, default_value = DEFAULT_CGROUP_ROOT)]
        cgroup_root: PathBuf,
        /// Also write every envelope to this directory.
        #[arg(long)]
        attest_dir: Option<PathBuf>,
        /// Wait this long for descendants after the main process exits.
        #[arg(long, default_value_t = 2000)]
        grace_ms: u64,
        /// Run tools without observing or signing anything.
        #[arg(long)]
        unattested: bool,
    },
    /// Verify DSSE envelopes and print their statements.
    Verify {
        /// Public key (hex, from `keygen`).
        #[arg(long)]
        pubkey: PathBuf,
        /// Fail unless the cgroup was drained and no record was dropped.
        #[arg(long)]
        require_complete: bool,
        /// Print the verified statement JSON.
        #[arg(long)]
        print: bool,
        #[arg(required = true)]
        envelopes: Vec<PathBuf>,
    },
    /// Completeness / misattribution bench (root, loads BPF).
    Bench {
        #[arg(long, default_value_t = 50)]
        tools: usize,
        #[arg(long, default_value_t = 3)]
        rounds: usize,
        #[arg(long, env = "EFFECT_ATTEST_BPF_OBJ", default_value = DEFAULT_OBJECT)]
        bpf_object: PathBuf,
        #[arg(long, default_value = DEFAULT_CGROUP_ROOT)]
        cgroup_root: PathBuf,
        /// ea-workload binary (default: next to this binary).
        #[arg(long)]
        workload: Option<PathBuf>,
        /// Write the full JSON report here.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Exit 1 below this completeness, or on any misattribution.
        #[arg(long, default_value_t = 0.99)]
        min_completeness: f64,
        /// Also run the same calls without attestation and report latency.
        #[arg(long)]
        baseline: bool,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("effect-attest: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::Keygen { out } => {
            let k = keys::generate()?;
            keys::write_pair(&k, &out)?;
            println!("{}", effect_attest::dsse::keyid(&k.verifying_key()));
        }
        Cmd::Serve {
            catalog,
            key,
            bpf_object,
            cgroup_root,
            attest_dir,
            grace_ms,
            unattested,
        } => {
            let catalog = Catalog::load(&catalog)?;
            let attestor = if unattested {
                eprintln!("effect-attest: running WITHOUT attestation (--unattested)");
                None
            } else {
                let key = keys::read_signing(key.as_deref().context("--key is required")?)?;
                if let Some(d) = &attest_dir {
                    std::fs::create_dir_all(d)?;
                }
                let tracer = effect_attest::tracer::Tracer::start(&bpf_object).context(
                    "cannot observe effects: BPF did not load (needs root / CAP_BPF+CAP_PERFMON)",
                )?;
                Some(server::Attestor {
                    tracer,
                    cgroup_root,
                    key,
                    attest_dir,
                    grace: Duration::from_millis(grace_ms),
                    kernel: server::kernel_release(),
                })
            };
            let srv = Arc::new(server::Server::new(catalog, attestor));
            let stdin = std::io::stdin();
            let out: Arc<Mutex<dyn std::io::Write + Send>> =
                Arc::new(Mutex::new(std::io::stdout()));
            srv.serve(stdin.lock(), out);
        }
        Cmd::Verify {
            pubkey,
            require_complete,
            print,
            envelopes,
        } => {
            let key = keys::read_verifying(&pubkey)?;
            let policy = statement::Policy {
                require_complete,
                expect_request: None,
            };
            let mut failed = 0;
            for path in &envelopes {
                let t0 = std::time::Instant::now();
                match bench::verify_file(path, &key)
                    .and_then(|st| statement::check_policy(&st, &policy).map(|_| st))
                {
                    Ok(st) => {
                        let us = t0.elapsed().as_micros();
                        eprintln!(
                            "OK {} tool={} effects={} drained={} ({us} us)",
                            path.display(),
                            st.predicate.call.tool,
                            st.predicate.effects.len(),
                            st.predicate.integrity.cgroup_drained
                        );
                        if print {
                            println!("{}", serde_json::to_string_pretty(&st)?);
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        eprintln!("FAIL {}: {e:#}", path.display());
                    }
                }
            }
            if failed > 0 {
                bail!("{failed} of {} envelopes failed", envelopes.len());
            }
        }
        Cmd::Bench {
            tools,
            rounds,
            bpf_object,
            cgroup_root,
            workload,
            out,
            min_completeness,
            baseline,
        } => {
            let workload = match workload {
                Some(w) => w,
                None => std::env::current_exe()?
                    .parent()
                    .context("exe dir")?
                    .join("ea-workload"),
            };
            let workload = std::fs::canonicalize(&workload)
                .with_context(|| format!("workload {}", workload.display()))?;
            let bpf_object = std::fs::canonicalize(&bpf_object)
                .with_context(|| format!("eBPF object {}", bpf_object.display()))?;
            let opts = bench::BenchOpts {
                tools,
                rounds,
                bpf_object,
                cgroup_root,
                workload,
                out,
                min_completeness,
                baseline,
            };
            let r = bench::run(&opts)?;
            println!(
                "calls={} expected={} found={} completeness={:.4} misattributions={} errors={} not_drained={}",
                r.calls, r.expected_effects, r.found_effects, r.completeness, r.misattributions,
                r.calls_with_errors, r.calls_not_drained
            );
            println!(
                "verify_us p50={:.0} p99={:.0}  call_latency_ms p50={:.1} p99={:.1}  kernel={} ipv6={}",
                r.verify_us_p50, r.verify_us_p99, r.latency_ms_p50, r.latency_ms_p99, r.kernel, r.ipv6
            );
            if let (Some(b50), Some(b99)) = (r.baseline_latency_ms_p50, r.baseline_latency_ms_p99) {
                println!("baseline (unattested) call_latency_ms p50={b50:.1} p99={b99:.1}");
            }
            for (p, f, x) in &r.by_pattern {
                println!("  {p:<9} {f}/{x}");
            }
            for f in &r.failures {
                println!(
                    "  FAIL {} r{} seen={} missing={:?} misattributed={:?} tool_error={:?} error={:?}",
                    f.tool, f.round, f.effects_seen, f.missing, f.misattributed, f.tool_error, f.error
                );
            }
            bench::check(&r, min_completeness)?;
        }
    }
    Ok(())
}
