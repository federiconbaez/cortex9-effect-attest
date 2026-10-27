//! Types shared between the eBPF program (`no_std`, `bpfel-unknown-none`)
//! and the userspace collector.
//!
//! The kernel side emits two record types into one ring buffer:
//!
//! - [`EnterEvent`] at `sys_enter` of a tracked syscall made by a task whose
//!   cgroup v2 id is registered in `CALL_CGROUPS`. It carries the decoded
//!   argument (path or `sockaddr` bytes) read from user memory at entry.
//! - [`ExitEvent`] at the matching `sys_exit`, with the return value.
//!
//! Userspace joins them per thread. All structs are `#[repr(C)]` with
//! explicit padding; userspace decodes field by field from [`enter_off`] and
//! [`exit_off`], never by casting.
#![cfg_attr(not(test), no_std)]

/// Length of `task_struct::comm` (TASK_COMM_LEN).
pub const COMM_LEN: usize = 16;

/// Bytes of user data copied per event (path or sockaddr).
pub const DATA_LEN: usize = 256;

/// Number of raw syscall arguments in the tracepoint record.
pub const ARG_COUNT: usize = 6;

/// Ring buffer size in bytes (power of two, multiple of the page size).
pub const RING_BUF_BYTES: u32 = 8 << 20;

/// Max concurrently registered call cgroups.
pub const MAX_CALLS: u32 = 4_096;

/// Max syscall numbers in `SPECS`.
pub const MAX_SPECS: u32 = 64;

/// Max threads with a pending tracked syscall.
pub const MAX_PENDING: u32 = 65_536;

/// Record tags (first `u32` of every ring buffer record).
pub mod tag {
    pub const ENTER: u32 = 1;
    pub const EXIT: u32 = 2;
}

/// Effect kinds ([`SyscallSpec::kind`], [`EnterEvent::kind`]).
pub mod kind {
    pub const EXEC: u8 = 1;
    pub const OPEN: u8 = 2;
    pub const CONNECT: u8 = 3;
}

/// Special values of [`SyscallSpec::flags_arg`].
pub mod flags_src {
    /// The syscall has no flags argument; use [`super::SyscallSpec::fixed_flags`].
    pub const FIXED: u8 = 0xff;
    /// `openat2`: argument 2 points to `struct open_how`, flags are its first `u64`.
    pub const OPEN_HOW: u8 = 0xfe;
}

/// Special value of [`SyscallSpec::dirfd_arg`]: no dirfd argument.
pub const NO_DIRFD: u8 = 0xff;

/// `open(2)` flag bits that mean "this open can modify the file system"
/// (`O_WRONLY | O_RDWR | O_CREAT | O_TRUNC`, generic Linux values used by
/// x86_64 and aarch64). Opens without any of these bits are not reported.
pub const OPEN_WRITE_MASK: u32 = 0o1 | 0o2 | 0o100 | 0o1000;

/// Map names, as seen by the loader.
pub mod maps {
    /// `RingBuf` with [`super::EnterEvent`] / [`super::ExitEvent`] records.
    pub const EVENTS: &str = "EVENTS";
    /// `HashMap<u64, u8>`: cgroup v2 ids of in-flight tool calls.
    pub const CALL_CGROUPS: &str = "CALL_CGROUPS";
    /// `HashMap<u32, SyscallSpec>`: syscall number -> how to decode it.
    pub const SPECS: &str = "SPECS";
    /// `LruHashMap<u64, u8>`: pid_tgid with an emitted enter and no exit yet.
    pub const PENDING: &str = "PENDING";
    /// `Array<u64>` with [`super::drop_slot`] counters.
    pub const DROPPED: &str = "DROPPED";
}

/// Slots of the `DROPPED` array.
pub mod drop_slot {
    /// Enter records lost because the ring buffer was full.
    pub const ENTER: u32 = 0;
    /// Exit records lost because the ring buffer was full.
    pub const EXIT: u32 = 1;
    pub const LEN: u32 = 2;
}

/// Program names, as seen by the loader.
pub mod programs {
    pub const SYS_ENTER: &str = "effect_sys_enter";
    pub const SYS_EXIT: &str = "effect_sys_exit";
}

/// How the kernel side decodes one syscall number. Filled by userspace for
/// the running architecture, so the eBPF object has no syscall table.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyscallSpec {
    /// One of [`kind`].
    pub kind: u8,
    /// Index of the argument holding the user pointer (path or sockaddr).
    pub ptr_arg: u8,
    /// Index of the flags argument, or one of [`flags_src`].
    pub flags_arg: u8,
    /// Index of the dirfd argument, or [`NO_DIRFD`].
    pub dirfd_arg: u8,
    /// Flags used when `flags_arg == flags_src::FIXED` (e.g. `creat`).
    pub fixed_flags: u32,
}

/// Emitted at `sys_enter`. 328 bytes, 8-byte aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnterEvent {
    /// [`tag::ENTER`].
    pub tag: u32,
    /// One of [`kind`] (widened).
    pub kind: u32,
    /// `bpf_ktime_get_ns()`.
    pub ts_ns: u64,
    /// `bpf_get_current_cgroup_id()`.
    pub cgroup_id: u64,
    /// Thread-group id (init PID namespace).
    pub pid: u32,
    /// Thread id (init PID namespace).
    pub tid: u32,
    /// Syscall number.
    pub nr: u32,
    /// Open flags (open kinds only).
    pub open_flags: u32,
    /// dirfd argument, `AT_FDCWD` (-100) when the syscall has none.
    pub dirfd: i32,
    /// Bytes copied into `data` (>0), or the negative error of the read.
    pub data_len: i32,
    /// `comm` of the calling thread.
    pub comm: [u8; COMM_LEN],
    /// NUL-terminated path, or raw `sockaddr` bytes for connect.
    pub data: [u8; DATA_LEN],
    /// Length argument of connect (`addrlen`), 0 otherwise.
    pub addr_len: u32,
    /// Padding, always zero.
    pub _pad: u32,
}

/// Emitted at `sys_exit` when an [`EnterEvent`] was emitted for the thread.
/// 40 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitEvent {
    /// [`tag::EXIT`].
    pub tag: u32,
    /// Syscall number.
    pub nr: u32,
    /// `bpf_ktime_get_ns()`.
    pub ts_ns: u64,
    /// `bpf_get_current_cgroup_id()`.
    pub cgroup_id: u64,
    /// Thread-group id.
    pub pid: u32,
    /// Thread id.
    pub tid: u32,
    /// Raw return value.
    pub ret: i64,
}

pub const ENTER_SIZE: usize = core::mem::size_of::<EnterEvent>();
pub const EXIT_SIZE: usize = core::mem::size_of::<ExitEvent>();

/// Byte offsets of [`EnterEvent`] fields.
pub mod enter_off {
    pub const TAG: usize = 0;
    pub const KIND: usize = 4;
    pub const TS_NS: usize = 8;
    pub const CGROUP_ID: usize = 16;
    pub const PID: usize = 24;
    pub const TID: usize = 28;
    pub const NR: usize = 32;
    pub const OPEN_FLAGS: usize = 36;
    pub const DIRFD: usize = 40;
    pub const DATA_LEN: usize = 44;
    pub const COMM: usize = 48;
    pub const DATA: usize = 64;
    pub const ADDR_LEN: usize = 320;
}

/// Byte offsets of [`ExitEvent`] fields.
pub mod exit_off {
    pub const TAG: usize = 0;
    pub const NR: usize = 4;
    pub const TS_NS: usize = 8;
    pub const CGROUP_ID: usize = 16;
    pub const PID: usize = 24;
    pub const TID: usize = 28;
    pub const RET: usize = 32;
}

/// Offsets inside the `raw_syscalls` tracepoint records (stable ABI, see
/// `/sys/kernel/tracing/events/raw_syscalls/*/format`).
pub mod tp {
    pub const ID: usize = 8;
    pub const ARGS: usize = 16;
    pub const RET: usize = 16;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn enter_layout_is_stable() {
        assert_eq!(size_of::<EnterEvent>(), 328);
        assert_eq!(align_of::<EnterEvent>(), 8);
        assert_eq!(offset_of!(EnterEvent, tag), enter_off::TAG);
        assert_eq!(offset_of!(EnterEvent, kind), enter_off::KIND);
        assert_eq!(offset_of!(EnterEvent, ts_ns), enter_off::TS_NS);
        assert_eq!(offset_of!(EnterEvent, cgroup_id), enter_off::CGROUP_ID);
        assert_eq!(offset_of!(EnterEvent, pid), enter_off::PID);
        assert_eq!(offset_of!(EnterEvent, tid), enter_off::TID);
        assert_eq!(offset_of!(EnterEvent, nr), enter_off::NR);
        assert_eq!(offset_of!(EnterEvent, open_flags), enter_off::OPEN_FLAGS);
        assert_eq!(offset_of!(EnterEvent, dirfd), enter_off::DIRFD);
        assert_eq!(offset_of!(EnterEvent, data_len), enter_off::DATA_LEN);
        assert_eq!(offset_of!(EnterEvent, comm), enter_off::COMM);
        assert_eq!(offset_of!(EnterEvent, data), enter_off::DATA);
        assert_eq!(offset_of!(EnterEvent, addr_len), enter_off::ADDR_LEN);
    }

    #[test]
    fn exit_layout_is_stable() {
        assert_eq!(size_of::<ExitEvent>(), 40);
        assert_eq!(offset_of!(ExitEvent, tag), exit_off::TAG);
        assert_eq!(offset_of!(ExitEvent, nr), exit_off::NR);
        assert_eq!(offset_of!(ExitEvent, ts_ns), exit_off::TS_NS);
        assert_eq!(offset_of!(ExitEvent, cgroup_id), exit_off::CGROUP_ID);
        assert_eq!(offset_of!(ExitEvent, pid), exit_off::PID);
        assert_eq!(offset_of!(ExitEvent, tid), exit_off::TID);
        assert_eq!(offset_of!(ExitEvent, ret), exit_off::RET);
    }

    #[test]
    fn spec_is_8_bytes() {
        assert_eq!(size_of::<SyscallSpec>(), 8);
    }

    #[test]
    fn ring_buf_size_is_power_of_two() {
        assert!(RING_BUF_BYTES.is_power_of_two());
        assert_eq!(RING_BUF_BYTES % 4096, 0);
    }

    #[test]
    fn write_mask_matches_linux_bits() {
        // O_WRONLY=1, O_RDWR=2, O_CREAT=0100, O_TRUNC=01000 (octal).
        assert_eq!(OPEN_WRITE_MASK, 0x1 | 0x2 | 0x40 | 0x200);
    }
}
