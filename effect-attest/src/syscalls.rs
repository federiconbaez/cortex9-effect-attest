//! Syscalls tracked per architecture and how the kernel side decodes them.
use effect_attest_common::{flags_src, kind, SyscallSpec, NO_DIRFD};

/// `O_WRONLY | O_CREAT | O_TRUNC`, what `creat(2)` implies.
const CREAT_FLAGS: u32 = 0o1 | 0o100 | 0o1000;

const fn spec(kind: u8, ptr_arg: u8, flags_arg: u8, dirfd_arg: u8, fixed: u32) -> SyscallSpec {
    SyscallSpec {
        kind,
        ptr_arg,
        flags_arg,
        dirfd_arg,
        fixed_flags: fixed,
    }
}

/// `(number, name, spec)` for the running architecture.
pub fn table() -> &'static [(u32, &'static str, SyscallSpec)] {
    #[cfg(target_arch = "x86_64")]
    {
        const T: &[(u32, &str, SyscallSpec)] = &[
            (
                59,
                "execve",
                spec(kind::EXEC, 0, flags_src::FIXED, NO_DIRFD, 0),
            ),
            (322, "execveat", spec(kind::EXEC, 1, flags_src::FIXED, 0, 0)),
            (2, "open", spec(kind::OPEN, 0, 1, NO_DIRFD, 0)),
            (
                85,
                "creat",
                spec(kind::OPEN, 0, flags_src::FIXED, NO_DIRFD, CREAT_FLAGS),
            ),
            (257, "openat", spec(kind::OPEN, 1, 2, 0, 0)),
            (
                437,
                "openat2",
                spec(kind::OPEN, 1, flags_src::OPEN_HOW, 0, 0),
            ),
            (
                42,
                "connect",
                spec(kind::CONNECT, 1, flags_src::FIXED, NO_DIRFD, 0),
            ),
        ];
        T
    }
    #[cfg(target_arch = "aarch64")]
    {
        const T: &[(u32, &str, SyscallSpec)] = &[
            (
                221,
                "execve",
                spec(kind::EXEC, 0, flags_src::FIXED, NO_DIRFD, 0),
            ),
            (281, "execveat", spec(kind::EXEC, 1, flags_src::FIXED, 0, 0)),
            (56, "openat", spec(kind::OPEN, 1, 2, 0, 0)),
            (
                437,
                "openat2",
                spec(kind::OPEN, 1, flags_src::OPEN_HOW, 0, 0),
            ),
            (
                203,
                "connect",
                spec(kind::CONNECT, 1, flags_src::FIXED, NO_DIRFD, 0),
            ),
        ];
        T
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        &[]
    }
}

/// Name of a tracked syscall number.
pub fn name(nr: u32) -> &'static str {
    table()
        .iter()
        .find(|(n, _, _)| *n == nr)
        .map(|(_, name, _)| *name)
        .unwrap_or("?")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_consistent() {
        let t = table();
        assert!(!t.is_empty());
        let mut nrs: Vec<u32> = t.iter().map(|(n, _, _)| *n).collect();
        nrs.sort_unstable();
        nrs.dedup();
        assert_eq!(nrs.len(), t.len(), "duplicate syscall numbers");
        for (_, n, s) in t {
            assert!(s.ptr_arg < 6, "{n}");
            assert!([kind::EXEC, kind::OPEN, kind::CONNECT].contains(&s.kind));
        }
        assert!(t.len() < effect_attest_common::MAX_SPECS as usize);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x86_64_numbers() {
        assert_eq!(name(59), "execve");
        assert_eq!(name(257), "openat");
        assert_eq!(name(42), "connect");
        assert_eq!(name(0), "?");
    }
}
