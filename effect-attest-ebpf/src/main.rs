//! eBPF program for effect-attest.
//!
//! `raw_syscalls/sys_enter`: if the current task's cgroup v2 id is in
//! `CALL_CGROUPS` and the syscall number is in `SPECS`, decode the argument
//! (path string or sockaddr bytes) from user memory and push an
//! [`EnterEvent`]. Opens without write intent are dropped here.
//!
//! `raw_syscalls/sys_exit`: if an enter was emitted for this thread, push an
//! [`ExitEvent`] with the return value.
//!
//! Everything outside a registered cgroup costs one hash lookup per syscall.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_ktime_get_ns, bpf_probe_read_user, bpf_probe_read_user_buf,
        bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::{Array, HashMap, LruHashMap, RingBuf},
    programs::TracePointContext,
};
use effect_attest_common::{
    drop_slot, flags_src, kind, tag, tp, EnterEvent, ExitEvent, SyscallSpec, ARG_COUNT, COMM_LEN,
    MAX_CALLS, MAX_PENDING, MAX_SPECS, NO_DIRFD, OPEN_WRITE_MASK, RING_BUF_BYTES,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_BYTES, 0);

#[map]
static CALL_CGROUPS: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CALLS, 0);

#[map]
static SPECS: HashMap<u32, SyscallSpec> = HashMap::with_max_entries(MAX_SPECS, 0);

#[map]
static PENDING: LruHashMap<u64, u8> = LruHashMap::with_max_entries(MAX_PENDING, 0);

#[map]
static DROPPED: Array<u64> = Array::with_max_entries(drop_slot::LEN, 0);

const AT_FDCWD: i32 = -100;

#[inline(always)]
fn bump_dropped(slot: u32) {
    if let Some(counter) = DROPPED.get_ptr_mut(slot) {
        // SAFETY: single u64 slot; an approximate counter is enough.
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn arg(args: &[u64; ARG_COUNT], idx: u8) -> u64 {
    match idx {
        0 => args[0],
        1 => args[1],
        2 => args[2],
        3 => args[3],
        4 => args[4],
        5 => args[5],
        _ => 0,
    }
}

#[tracepoint(category = "raw_syscalls", name = "sys_enter")]
pub fn effect_sys_enter(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter(&ctx);
    0
}

fn try_sys_enter(ctx: &TracePointContext) -> Result<(), i64> {
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    // SAFETY: read-only lookups; values are copied out immediately.
    if unsafe { CALL_CGROUPS.get(&cgroup_id) }.is_none() {
        return Ok(());
    }
    // SAFETY: offsets come from the stable raw_syscalls tracepoint format.
    let nr: i64 = unsafe { ctx.read_at(tp::ID) }.map_err(i64::from)?;
    if nr < 0 {
        return Ok(());
    }
    let nr = nr as u32;
    let Some(spec) = (unsafe { SPECS.get(&nr) }).copied() else {
        return Ok(());
    };
    let args: [u64; ARG_COUNT] = unsafe { ctx.read_at(tp::ARGS) }.map_err(i64::from)?;

    let mut open_flags: u32 = 0;
    if spec.kind == kind::OPEN {
        open_flags = match spec.flags_arg {
            flags_src::FIXED => spec.fixed_flags,
            flags_src::OPEN_HOW => {
                let how = arg(&args, 2) as *const u64;
                // SAFETY: bpf_probe_read_user validates the user pointer.
                unsafe { bpf_probe_read_user(how) }.unwrap_or(0) as u32
            }
            i => arg(&args, i) as u32,
        };
        if open_flags & OPEN_WRITE_MASK == 0 {
            return Ok(());
        }
    }

    let Some(mut slot) = EVENTS.reserve::<EnterEvent>(0) else {
        bump_dropped(drop_slot::ENTER);
        return Ok(());
    };
    let pid_tgid = bpf_get_current_pid_tgid();
    let ev = slot.as_mut_ptr();
    // SAFETY: `ev` points to a reserved, exclusively owned ring buffer slot
    // of size_of::<EnterEvent>() bytes. Every field is written below before
    // submit, so no uninitialized byte reaches userspace.
    unsafe {
        (*ev).tag = tag::ENTER;
        (*ev).kind = spec.kind as u32;
        (*ev).ts_ns = bpf_ktime_get_ns();
        (*ev).cgroup_id = cgroup_id;
        (*ev).pid = (pid_tgid >> 32) as u32;
        (*ev).tid = pid_tgid as u32;
        (*ev).nr = nr;
        (*ev).open_flags = open_flags;
        (*ev).dirfd = if spec.dirfd_arg == NO_DIRFD {
            AT_FDCWD
        } else {
            arg(&args, spec.dirfd_arg) as i32
        };
        (*ev).comm = bpf_get_current_comm().unwrap_or([0u8; COMM_LEN]);
        (*ev).addr_len = 0;
        (*ev)._pad = 0;
        (*ev).data = [0u8; effect_attest_common::DATA_LEN];
        let ptr = arg(&args, spec.ptr_arg) as *const u8;
        if spec.kind == kind::CONNECT {
            let len = arg(&args, 2) as u32;
            (*ev).addr_len = len;
            // Read a fixed prefix: sockaddr_un is 110 bytes, sockaddr_in6 28.
            // A short buffer near the end of a mapping fails the long read,
            // so fall back to the inet6 size.
            let data = &mut (*ev).data;
            (*ev).data_len = match bpf_probe_read_user_buf(ptr, &mut data[..110]) {
                Ok(()) => 110,
                Err(_) => match bpf_probe_read_user_buf(ptr, &mut data[..28]) {
                    Ok(()) => 28,
                    Err(e) => e as i32,
                },
            };
        } else {
            let data = &mut (*ev).data;
            (*ev).data_len = match bpf_probe_read_user_str_bytes(ptr, data) {
                Ok(s) => s.len() as i32,
                Err(e) => e as i32,
            };
        }
    }
    slot.submit(0);
    let _ = PENDING.insert(&pid_tgid, &1u8, 0);
    Ok(())
}

#[tracepoint(category = "raw_syscalls", name = "sys_exit")]
pub fn effect_sys_exit(ctx: TracePointContext) -> u32 {
    let _ = try_sys_exit(&ctx);
    0
}

fn try_sys_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    // SAFETY: read-only lookup.
    if unsafe { PENDING.get(&pid_tgid) }.is_none() {
        return Ok(());
    }
    let _ = PENDING.remove(&pid_tgid);
    let nr: i64 = unsafe { ctx.read_at(tp::ID) }.map_err(i64::from)?;
    let ret: i64 = unsafe { ctx.read_at(tp::RET) }.map_err(i64::from)?;
    let event = ExitEvent {
        tag: tag::EXIT,
        nr: nr as u32,
        ts_ns: unsafe { bpf_ktime_get_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        pid: (pid_tgid >> 32) as u32,
        tid: pid_tgid as u32,
        ret,
    };
    if EVENTS.output::<ExitEvent>(&event, 0).is_err() {
        bump_dropped(drop_slot::EXIT);
    }
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
