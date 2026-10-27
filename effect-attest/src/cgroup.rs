//! One cgroup v2 per tool call.
//!
//! The child moves itself into the call cgroup between fork and exec (it
//! writes `0` to an already open `cgroup.procs`), so its first `execve` and
//! every descendant are inside it. The cgroup id seen by eBPF
//! (`bpf_get_current_cgroup_id`) is the inode number of the directory.
use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub struct CallCgroup {
    path: PathBuf,
    id: u64,
    procs: File,
}

impl CallCgroup {
    /// Create `<root>/<name>`. `root` is created if missing.
    pub fn create(root: &Path, name: &str) -> Result<Self> {
        fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
        let path = root.join(name);
        fs::create_dir(&path).with_context(|| format!("creating {}", path.display()))?;
        let id = fs::metadata(&path)?.ino();
        let procs = OpenOptions::new()
            .write(true)
            .open(path.join("cgroup.procs"))
            .with_context(|| format!("opening {}/cgroup.procs", path.display()))?;
        Ok(CallCgroup { path, id, procs })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Raw fd of `cgroup.procs`, for the pre-exec hook.
    pub fn procs_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// `populated` from `cgroup.events`.
    pub fn populated(&self) -> Result<bool> {
        let s = fs::read_to_string(self.path.join("cgroup.events"))?;
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("populated ") {
                return Ok(v.trim() != "0");
            }
        }
        bail!("no populated key in cgroup.events")
    }

    /// Wait until no process is left, up to `timeout`. Returns whether the
    /// cgroup is empty.
    pub fn wait_empty(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match self.populated() {
                Ok(false) => return true,
                Ok(true) => {}
                Err(_) => return false,
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    /// SIGKILL everything in the cgroup (`cgroup.kill`, Linux 5.14+, with a
    /// per-pid fallback).
    pub fn kill_all(&self) {
        if fs::write(self.path.join("cgroup.kill"), "1").is_ok() {
            return;
        }
        if let Ok(s) = fs::read_to_string(self.path.join("cgroup.procs")) {
            for pid in s.lines().filter_map(|l| l.trim().parse::<i32>().ok()) {
                // SAFETY: plain kill(2).
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
        }
    }
}

impl Drop for CallCgroup {
    fn drop(&mut self) {
        for _ in 0..50 {
            if fs::remove_dir(&self.path).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Move the calling process into the cgroup whose `cgroup.procs` is `fd`.
/// Async-signal-safe: meant for `CommandExt::pre_exec`.
pub fn join_from_child(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: write(2) of a static buffer to an open fd.
    let n = unsafe { libc::write(fd, b"0".as_ptr().cast(), 1) };
    if n == 1 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
