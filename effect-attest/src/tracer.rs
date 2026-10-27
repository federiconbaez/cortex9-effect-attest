//! Loads the eBPF object, attaches the tracepoints and routes ring buffer
//! records to the call whose cgroup produced them.
use crate::effects::{parse, Effect, Joiner, Record};
use anyhow::{Context, Result};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, RingBuf};
use aya::programs::TracePoint;
use aya::Ebpf;
use effect_attest_common::{drop_slot, maps, programs, SyscallSpec};
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// `SyscallSpec` is plain data shared with the kernel.
#[derive(Clone, Copy)]
#[repr(transparent)]
struct Spec(SyscallSpec);
// SAFETY: #[repr(C)] struct of integers with no padding holes.
unsafe impl aya::Pod for Spec {}

struct Inner {
    /// Keeps programs attached for the lifetime of the tracer.
    _ebpf: Mutex<Ebpf>,
    ring: Mutex<RingBuf<MapData>>,
    calls: Mutex<BpfHashMap<MapData, u64, u8>>,
    dropped: Array<MapData, u64>,
    buckets: Mutex<HashMap<u64, Joiner>>,
    unrouted: AtomicU64,
    stop: AtomicBool,
}

/// Cheap to clone handle.
#[derive(Clone)]
pub struct Tracer {
    inner: Arc<Inner>,
}

fn bump_memlock() {
    let r = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit with a valid struct; failure is non-fatal (kernels
    // >= 5.11 account BPF memory to the cgroup instead).
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) };
}

impl Tracer {
    /// Load `object`, program the syscall specs and attach. Fails if the
    /// kernel refuses (no privileges, verifier rejection, no tracefs).
    pub fn start(object: &Path) -> Result<Self> {
        bump_memlock();
        let mut ebpf =
            Ebpf::load_file(object).with_context(|| format!("loading {}", object.display()))?;
        {
            let mut specs: BpfHashMap<&mut MapData, u32, Spec> =
                BpfHashMap::try_from(ebpf.map_mut(maps::SPECS).context("SPECS map")?)?;
            for (nr, _, spec) in crate::syscalls::table() {
                specs.insert(nr, Spec(*spec), 0)?;
            }
        }
        let ring = RingBuf::try_from(ebpf.take_map(maps::EVENTS).context("EVENTS map")?)?;
        let calls = BpfHashMap::try_from(
            ebpf.take_map(maps::CALL_CGROUPS)
                .context("CALL_CGROUPS map")?,
        )?;
        let dropped = Array::try_from(ebpf.take_map(maps::DROPPED).context("DROPPED map")?)?;
        for (prog, tp) in [
            (programs::SYS_EXIT, "sys_exit"),
            (programs::SYS_ENTER, "sys_enter"),
        ] {
            let p: &mut TracePoint = ebpf
                .program_mut(prog)
                .with_context(|| format!("program {prog}"))?
                .try_into()?;
            p.load()
                .with_context(|| format!("loading {prog} (verifier or privileges)"))?;
            p.attach("raw_syscalls", tp)
                .with_context(|| format!("attaching raw_syscalls/{tp}"))?;
        }
        let tracer = Tracer {
            inner: Arc::new(Inner {
                _ebpf: Mutex::new(ebpf),
                ring: Mutex::new(ring),
                calls: Mutex::new(calls),
                dropped,
                buckets: Mutex::new(HashMap::new()),
                unrouted: AtomicU64::new(0),
                stop: AtomicBool::new(false),
            }),
        };
        let t = tracer.clone();
        std::thread::Builder::new()
            .name("ring-reader".into())
            .spawn(move || t.reader_loop())?;
        Ok(tracer)
    }

    fn reader_loop(&self) {
        let fd = self.inner.ring.lock().unwrap().as_raw_fd();
        while !self.inner.stop.load(Ordering::Relaxed) {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut pfd, 1, 20) };
            self.drain();
        }
    }

    /// Read everything currently in the ring buffer and route it.
    ///
    /// The ring lock is held until the batch is routed: otherwise a
    /// concurrent `finish` could see an empty ring and remove the bucket
    /// while this thread still holds that call's records.
    pub fn drain(&self) {
        let mut ring = self.inner.ring.lock().unwrap();
        let mut batch: Vec<Record> = Vec::new();
        while let Some(item) = ring.next() {
            if let Some(r) = parse(&item) {
                batch.push(r);
            }
        }
        if batch.is_empty() {
            return;
        }
        let mut buckets = self.inner.buckets.lock().unwrap();
        for r in batch {
            let cg = match &r {
                Record::Enter(e) => e.cgroup_id,
                Record::Exit(x) => x.cgroup_id,
            };
            match buckets.get_mut(&cg) {
                Some(j) => j.push(r),
                None => {
                    self.inner.unrouted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        drop(buckets);
        drop(ring);
    }

    /// Start collecting for `cgroup_id`.
    pub fn register(&self, cgroup_id: u64) -> Result<()> {
        self.inner
            .buckets
            .lock()
            .unwrap()
            .insert(cgroup_id, Joiner::default());
        self.inner
            .calls
            .lock()
            .unwrap()
            .insert(cgroup_id, 1, 0)
            .context("registering call cgroup")?;
        Ok(())
    }

    /// Stop collecting for `cgroup_id` and return its effects. Call only
    /// after the cgroup is empty, so every record it produced is already in
    /// the ring buffer.
    pub fn finish(&self, cgroup_id: u64) -> Vec<Effect> {
        self.drain();
        let _ = self.inner.calls.lock().unwrap().remove(&cgroup_id);
        self.drain();
        self.inner
            .buckets
            .lock()
            .unwrap()
            .remove(&cgroup_id)
            .map(Joiner::finish)
            .unwrap_or_default()
    }

    /// Records lost because the ring buffer was full (enter + exit).
    pub fn dropped(&self) -> u64 {
        [drop_slot::ENTER, drop_slot::EXIT]
            .iter()
            .map(|s| self.inner.dropped.get(s, 0).unwrap_or(0))
            .sum()
    }

    /// Records whose cgroup had no registered call (should stay 0).
    pub fn unrouted(&self) -> u64 {
        self.inner.unrouted.load(Ordering::Relaxed)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
