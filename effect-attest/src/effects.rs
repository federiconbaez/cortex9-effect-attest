//! Decoding of ring buffer records and joining them into [`Effect`]s.
use effect_attest_common::{
    enter_off, exit_off, kind, tag, COMM_LEN, DATA_LEN, ENTER_SIZE, EXIT_SIZE,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Decoded [`effect_attest_common::EnterEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enter {
    pub kind: u8,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub nr: u32,
    pub open_flags: u32,
    pub dirfd: i32,
    pub data_len: i32,
    pub comm: String,
    pub data: Vec<u8>,
    pub addr_len: u32,
}

/// Decoded [`effect_attest_common::ExitEvent`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exit {
    pub nr: u32,
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub pid: u32,
    pub tid: u32,
    pub ret: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Enter(Enter),
    Exit(Exit),
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Parse one ring buffer record. `None` for unknown tags or short records.
pub fn parse(b: &[u8]) -> Option<Record> {
    if b.len() < 4 {
        return None;
    }
    match u32_at(b, 0) {
        tag::ENTER if b.len() >= ENTER_SIZE => Some(Record::Enter(Enter {
            kind: u32_at(b, enter_off::KIND) as u8,
            ts_ns: u64_at(b, enter_off::TS_NS),
            cgroup_id: u64_at(b, enter_off::CGROUP_ID),
            pid: u32_at(b, enter_off::PID),
            tid: u32_at(b, enter_off::TID),
            nr: u32_at(b, enter_off::NR),
            open_flags: u32_at(b, enter_off::OPEN_FLAGS),
            dirfd: i32_at(b, enter_off::DIRFD),
            data_len: i32_at(b, enter_off::DATA_LEN),
            comm: cstr(&b[enter_off::COMM..enter_off::COMM + COMM_LEN]),
            data: b[enter_off::DATA..enter_off::DATA + DATA_LEN].to_vec(),
            addr_len: u32_at(b, enter_off::ADDR_LEN),
        })),
        tag::EXIT if b.len() >= EXIT_SIZE => Some(Record::Exit(Exit {
            nr: u32_at(b, exit_off::NR),
            ts_ns: u64_at(b, exit_off::TS_NS),
            cgroup_id: u64_at(b, exit_off::CGROUP_ID),
            pid: u32_at(b, exit_off::PID),
            tid: u32_at(b, exit_off::TID),
            ret: u64_at(b, exit_off::RET) as i64,
        })),
        _ => None,
    }
}

/// One observed effect, as it appears in the attestation predicate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    /// `exec`, `open_write` or `connect`.
    pub kind: String,
    /// Syscall name (`execve`, `openat`, ...).
    pub syscall: String,
    /// Path as passed to the syscall (may be relative to `dirfd`), or the
    /// decoded socket address for connect.
    pub target: String,
    /// The user-memory read at syscall entry failed or was truncated.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub target_incomplete: bool,
    /// dirfd argument (`-100` = AT_FDCWD); only for open/exec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirfd: Option<i32>,
    /// Open flags; only for open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<u32>,
    /// Return value; `None` if the exit was not observed (e.g. the task was
    /// killed inside the syscall, or a successful exec from a non-leader
    /// thread changed its thread id).
    pub ret: Option<i64>,
    /// Process and thread ids (init PID namespace).
    pub pid: u32,
    pub tid: u32,
    pub comm: String,
    /// Monotonic kernel time at entry.
    pub ts_ns: u64,
}

impl Effect {
    /// The syscall returned success (`ret >= 0`).
    pub fn succeeded(&self) -> bool {
        matches!(self.ret, Some(r) if r >= 0)
    }
}

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Human-readable form of a `sockaddr` prefix: `127.0.0.1:80`, `[::1]:80`,
/// `unix:/path`, `unix:@abstract`, or `family=N`.
pub fn decode_sockaddr(b: &[u8], addr_len: u32) -> (String, bool) {
    if b.len() < 2 {
        return ("unreadable".into(), true);
    }
    let fam = u16::from_le_bytes([b[0], b[1]]);
    match fam {
        AF_INET if b.len() >= 8 => {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip = Ipv4Addr::new(b[4], b[5], b[6], b[7]);
            (format!("{ip}:{port}"), false)
        }
        AF_INET6 if b.len() >= 24 => {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip: [u8; 16] = b[8..24].try_into().unwrap();
            (format!("[{}]:{port}", Ipv6Addr::from(ip)), false)
        }
        AF_UNIX => {
            let max = (addr_len as usize).min(b.len());
            let path = if max > 2 { &b[2..max] } else { &[][..] };
            let truncated = (addr_len as usize) > b.len();
            if path.first() == Some(&0) {
                (format!("unix:@{}", cstr(&path[1..])), truncated)
            } else {
                (format!("unix:{}", cstr(path)), truncated)
            }
        }
        f => (format!("family={f}"), false),
    }
}

/// Build an effect from an enter record and its (optional) exit.
pub fn to_effect(e: &Enter, ret: Option<i64>) -> Effect {
    let syscall = crate::syscalls::name(e.nr).to_string();
    match e.kind {
        kind::CONNECT => {
            let (target, mut incomplete) = if e.data_len > 0 {
                decode_sockaddr(&e.data[..e.data_len as usize], e.addr_len)
            } else {
                ("unreadable".into(), true)
            };
            if e.data_len <= 0 {
                incomplete = true;
            }
            Effect {
                kind: "connect".into(),
                syscall,
                target,
                target_incomplete: incomplete,
                dirfd: None,
                flags: None,
                ret,
                pid: e.pid,
                tid: e.tid,
                comm: e.comm.clone(),
                ts_ns: e.ts_ns,
            }
        }
        k => {
            // bpf_probe_read_user_str returns the length including the NUL;
            // the aya wrapper returns the string without it. A string that
            // fills the whole buffer was probably truncated.
            let (target, incomplete) = if e.data_len >= 0 {
                let len = (e.data_len as usize).min(DATA_LEN);
                (
                    String::from_utf8_lossy(&e.data[..len]).into_owned(),
                    len >= DATA_LEN - 1,
                )
            } else {
                (String::new(), true)
            };
            Effect {
                kind: if k == kind::EXEC {
                    "exec"
                } else {
                    "open_write"
                }
                .into(),
                syscall,
                target,
                target_incomplete: incomplete,
                dirfd: Some(e.dirfd),
                flags: (k == kind::OPEN).then_some(e.open_flags),
                ret,
                pid: e.pid,
                tid: e.tid,
                comm: e.comm.clone(),
                ts_ns: e.ts_ns,
            }
        }
    }
}

/// Joins enter/exit records of one call cgroup into effects, in order.
#[derive(Default, Debug)]
pub struct Joiner {
    pending: HashMap<u32, Enter>,
    done: Vec<Effect>,
}

impl Joiner {
    pub fn push(&mut self, r: Record) {
        match r {
            Record::Enter(e) => {
                // A previous enter on the same thread without exit (the
                // thread was killed or exec'd from another thread): flush it.
                if let Some(prev) = self.pending.insert(e.tid, e) {
                    self.done.push(to_effect(&prev, None));
                }
            }
            Record::Exit(x) => {
                let matched = match self.pending.remove(&x.tid) {
                    Some(e) => Some(e),
                    // Successful execve from a non-leader thread: the exit is
                    // reported on the leader's tid (== pid).
                    None => {
                        let key = self
                            .pending
                            .iter()
                            .find(|(_, e)| e.pid == x.pid && e.kind == kind::EXEC && e.nr == x.nr)
                            .map(|(k, _)| *k);
                        key.and_then(|k| self.pending.remove(&k))
                    }
                };
                if let Some(e) = matched {
                    self.done.push(to_effect(&e, Some(x.ret)));
                }
            }
        }
    }

    /// All effects, including enters whose exit was never seen.
    pub fn finish(mut self) -> Vec<Effect> {
        let mut rest: Vec<Enter> = self.pending.drain().map(|(_, e)| e).collect();
        rest.sort_by_key(|e| e.ts_ns);
        for e in rest {
            self.done.push(to_effect(&e, None));
        }
        self.done.sort_by_key(|e| e.ts_ns);
        self.done
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use effect_attest_common::{EnterEvent, ExitEvent};

    fn bytes_of<T: Copy>(v: &T) -> Vec<u8> {
        // SAFETY: test-only view of a plain #[repr(C)] value with no padding
        // holes (all fields are explicit).
        unsafe { std::slice::from_raw_parts(v as *const T as *const u8, std::mem::size_of::<T>()) }
            .to_vec()
    }

    fn enter(kind: u8, tid: u32, data: &[u8]) -> EnterEvent {
        let mut d = [0u8; DATA_LEN];
        d[..data.len()].copy_from_slice(data);
        let mut comm = [0u8; COMM_LEN];
        comm[..2].copy_from_slice(b"sh");
        EnterEvent {
            tag: tag::ENTER,
            kind: kind as u32,
            ts_ns: 10 + tid as u64,
            cgroup_id: 99,
            pid: 1000,
            tid,
            nr: 257,
            open_flags: 0o101,
            dirfd: -100,
            data_len: data.len() as i32,
            comm,
            data: d,
            addr_len: 0,
            _pad: 0,
        }
    }

    fn exit(tid: u32, ret: i64) -> ExitEvent {
        ExitEvent {
            tag: tag::EXIT,
            nr: 257,
            ts_ns: 50,
            cgroup_id: 99,
            pid: 1000,
            tid,
            ret,
        }
    }

    #[test]
    fn parse_enter_and_exit() {
        let e = enter(kind::OPEN, 1001, b"/tmp/x");
        let Some(Record::Enter(p)) = parse(&bytes_of(&e)) else {
            panic!("not an enter")
        };
        assert_eq!(p.cgroup_id, 99);
        assert_eq!(p.comm, "sh");
        assert_eq!(&p.data[..6], b"/tmp/x");
        let x = exit(1001, 3);
        assert_eq!(
            parse(&bytes_of(&x)),
            Some(Record::Exit(Exit {
                nr: 257,
                ts_ns: 50,
                cgroup_id: 99,
                pid: 1000,
                tid: 1001,
                ret: 3
            }))
        );
    }

    #[test]
    fn parse_rejects_short_and_unknown() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&[9, 0, 0, 0, 1, 2]), None);
        let x = exit(1, 0);
        assert_eq!(parse(&bytes_of(&x)[..20]), None);
    }

    #[test]
    fn joiner_pairs_per_thread() {
        let mut j = Joiner::default();
        let push = |j: &mut Joiner, v: Vec<u8>| j.push(parse(&v).unwrap());
        push(&mut j, bytes_of(&enter(kind::OPEN, 1, b"/a")));
        push(&mut j, bytes_of(&enter(kind::OPEN, 2, b"/b")));
        push(&mut j, bytes_of(&exit(2, -13)));
        push(&mut j, bytes_of(&exit(1, 4)));
        let fx = j.finish();
        assert_eq!(fx.len(), 2);
        let a = fx.iter().find(|f| f.target == "/a").unwrap();
        let b = fx.iter().find(|f| f.target == "/b").unwrap();
        assert_eq!(a.ret, Some(4));
        assert!(a.succeeded());
        assert_eq!(b.ret, Some(-13));
        assert!(!b.succeeded());
        assert_eq!(a.kind, "open_write");
        assert_eq!(a.flags, Some(0o101));
    }

    #[test]
    fn joiner_keeps_unfinished() {
        let mut j = Joiner::default();
        j.push(parse(&bytes_of(&enter(kind::OPEN, 1, b"/a"))).unwrap());
        j.push(parse(&bytes_of(&enter(kind::OPEN, 1, b"/b"))).unwrap());
        let fx = j.finish();
        assert_eq!(fx.len(), 2);
        assert!(fx.iter().all(|f| f.ret.is_none()));
    }

    #[test]
    fn exec_exit_on_leader_tid() {
        let mut e = enter(kind::EXEC, 1005, b"/bin/true");
        e.nr = 59;
        let mut x = exit(1000, 0);
        x.nr = 59;
        let mut j = Joiner::default();
        j.push(parse(&bytes_of(&e)).unwrap());
        j.push(parse(&bytes_of(&x)).unwrap());
        let fx = j.finish();
        assert_eq!(fx.len(), 1);
        assert_eq!(fx[0].kind, "exec");
        assert_eq!(fx[0].ret, Some(0));
    }

    #[test]
    fn sockaddr_inet() {
        let mut b = vec![2u8, 0, 0x1f, 0x90, 127, 0, 0, 1];
        b.resize(16, 0);
        assert_eq!(decode_sockaddr(&b, 16), ("127.0.0.1:8080".into(), false));
    }

    #[test]
    fn sockaddr_inet6() {
        let mut b = vec![10u8, 0, 0, 80, 0, 0, 0, 0];
        let mut ip = [0u8; 16];
        ip[15] = 1;
        b.extend_from_slice(&ip);
        b.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(decode_sockaddr(&b, 28), ("[::1]:80".into(), false));
    }

    #[test]
    fn sockaddr_unix() {
        let mut b = vec![1u8, 0];
        b.extend_from_slice(b"/run/x.sock\0");
        assert_eq!(decode_sockaddr(&b, 14), ("unix:/run/x.sock".into(), false));
        let mut a = vec![1u8, 0, 0];
        a.extend_from_slice(b"abs");
        assert_eq!(decode_sockaddr(&a, 6), ("unix:@abs".into(), false));
        assert!(decode_sockaddr(&a, 200).1, "truncated when addrlen > read");
    }

    #[test]
    fn sockaddr_other() {
        assert_eq!(decode_sockaddr(&[16, 0, 1, 2], 4).0, "family=16");
        assert!(decode_sockaddr(&[1], 1).1);
    }

    #[test]
    fn failed_read_marks_incomplete() {
        let mut e = enter(kind::OPEN, 1, b"");
        e.data_len = -14;
        let Some(Record::Enter(p)) = parse(&bytes_of(&e)) else {
            panic!()
        };
        let f = to_effect(&p, Some(3));
        assert!(f.target_incomplete);
        assert_eq!(f.target, "");
    }
}
