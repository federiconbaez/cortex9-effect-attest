//! `ea-workload`: performs a scripted list of effects so the bench has an
//! exact ground truth. Actions run in order; `--fork`, `--thread` and
//! `--daemon` move the rest of the script into a child process, a thread,
//! or a detached grandchild (double fork + setsid, parent exits at once).
//!
//! ```text
//! ea-workload --write /tmp/a --fork --exec /tmp/bin/x --connect 127.0.0.1:8080
//! ```
use std::ffi::CString;
use std::io::Write;

#[derive(Debug, Clone)]
enum Action {
    Write(String),
    Creat(String),
    Openat2(String),
    Read(String),
    Exec(String),
    Execveat(String),
    Connect(String),
    SleepMs(u64),
    Fork,
    Thread,
    Daemon,
}

fn parse(args: &[String]) -> Result<Vec<Action>, String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        out.push(match a.as_str() {
            "--write" => Action::Write(val()?),
            "--creat" => Action::Creat(val()?),
            "--openat2" => Action::Openat2(val()?),
            "--read" => Action::Read(val()?),
            "--exec" => Action::Exec(val()?),
            "--execveat" => Action::Execveat(val()?),
            "--connect" => Action::Connect(val()?),
            "--sleep" => Action::SleepMs(val()?.parse().map_err(|e| format!("--sleep: {e}"))?),
            "--fork" => Action::Fork,
            "--thread" => Action::Thread,
            "--daemon" => Action::Daemon,
            other => return Err(format!("unknown argument {other}")),
        });
    }
    Ok(out)
}

fn c(s: &str) -> CString {
    CString::new(s).expect("no NUL in argument")
}

fn check(what: &str, r: libc::c_long) {
    if r < 0 {
        eprintln!("{what}: {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
}

fn spawn_exec(path: &str, at: bool) {
    let p = c(path);
    let argv = [p.as_ptr(), std::ptr::null()];
    let envp: [*const libc::c_char; 1] = [std::ptr::null()];
    // SAFETY: fork + exec; the child only calls async-signal-safe functions.
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            if at {
                libc::syscall(
                    libc::SYS_execveat,
                    libc::AT_FDCWD,
                    p.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    0,
                );
            } else {
                libc::execve(p.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            libc::_exit(127);
        }
        check("fork", pid as libc::c_long);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        if !(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0) {
            eprintln!("exec {path}: status {st}");
            std::process::exit(1);
        }
    }
}

fn run(actions: &[Action]) {
    for (i, a) in actions.iter().enumerate() {
        let rest = &actions[i + 1..];
        match a {
            Action::Write(p) => {
                let mut f = std::fs::File::create(p).unwrap_or_else(|e| {
                    eprintln!("write {p}: {e}");
                    std::process::exit(1)
                });
                let _ = f.write_all(b"effect\n");
            }
            Action::Creat(p) => {
                // SAFETY: creat(2) + close(2) with a valid C string.
                let fd = unsafe { libc::creat(c(p).as_ptr(), 0o644) };
                check("creat", fd as libc::c_long);
                unsafe { libc::close(fd) };
            }
            Action::Openat2(p) => {
                #[repr(C)]
                struct OpenHow {
                    flags: u64,
                    mode: u64,
                    resolve: u64,
                }
                let how = OpenHow {
                    flags: (libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC) as u64,
                    mode: 0o644,
                    resolve: 0,
                };
                // SAFETY: openat2(2) with a valid open_how of the right size.
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_openat2,
                        libc::AT_FDCWD,
                        c(p).as_ptr(),
                        &how as *const OpenHow,
                        std::mem::size_of::<OpenHow>(),
                    )
                };
                check("openat2", fd);
                unsafe { libc::close(fd as i32) };
            }
            Action::Read(p) => {
                let _ = std::fs::read(p);
            }
            Action::Exec(p) => spawn_exec(p, false),
            Action::Execveat(p) => spawn_exec(p, true),
            Action::Connect(addr) => {
                if let Err(e) = std::net::TcpStream::connect(addr.as_str()) {
                    eprintln!("connect {addr}: {e}");
                    std::process::exit(1);
                }
            }
            Action::SleepMs(ms) => std::thread::sleep(std::time::Duration::from_millis(*ms)),
            Action::Thread => {
                let rest = rest.to_vec();
                std::thread::spawn(move || run(&rest))
                    .join()
                    .expect("thread");
                return;
            }
            Action::Fork => {
                // SAFETY: the process is single threaded here unless a
                // previous --thread started one, which has already joined.
                let pid = unsafe { libc::fork() };
                check("fork", pid as libc::c_long);
                if pid == 0 {
                    run(rest);
                    std::process::exit(0);
                }
                let mut st = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
                if !(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0) {
                    std::process::exit(1);
                }
                return;
            }
            Action::Daemon => {
                // SAFETY: classic double fork; the intermediate child exits
                // right away so the grandchild is reparented.
                unsafe {
                    let pid = libc::fork();
                    check("fork", pid as libc::c_long);
                    if pid == 0 {
                        libc::setsid();
                        let pid2 = libc::fork();
                        if pid2 == 0 {
                            // Detach from the caller's pipes like a daemon.
                            let null = libc::open(c("/dev/null").as_ptr(), libc::O_RDWR);
                            libc::dup2(null, 1);
                            libc::dup2(null, 2);
                            run(rest);
                            libc::_exit(0);
                        }
                        libc::_exit(0);
                    }
                    let mut st = 0;
                    libc::waitpid(pid, &mut st, 0);
                }
                return;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!(
            "usage: ea-workload [--write P|--creat P|--openat2 P|--read P|--exec P|--execveat P|--connect ADDR|--sleep MS|--fork|--thread|--daemon]..."
        );
        return;
    }
    match parse(&args) {
        Ok(actions) => run(&actions),
        Err(e) => {
            eprintln!("ea-workload: {e}");
            std::process::exit(2);
        }
    }
    println!("ok");
}
