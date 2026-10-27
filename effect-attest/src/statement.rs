//! in-toto Statement v1 for one MCP `tools/call`.
//!
//! Layout follows the in-toto attestation framework (Statement layer,
//! `spec/v1/statement.md`): `_type`, `subject` (each with a `digest`),
//! `predicateType`, `predicate`. The predicate type is defined by this
//! project; it is not an in-toto vetted predicate.
use crate::dsse::{self, Envelope};
use crate::effects::Effect;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str =
    "https://github.com/federiconbaez/cortex9-effect-attest/predicate/mcp-call-effects/v0.1";

/// in-toto ResourceDescriptor subset used here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    pub name: String,
    pub digest: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    #[serde(rename = "_type")]
    pub type_: String,
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Predicate,
}

/// How the effects were observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observer {
    /// Fixed: `ebpf:raw_syscalls+cgroup_v2`.
    pub mechanism: String,
    /// `uname -r` of the observing kernel.
    pub kernel: String,
    /// Syscalls the observer decodes.
    pub syscalls: Vec<String>,
    /// Version of this tool.
    pub version: String,
}

/// The call the effects are attributed to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Call {
    pub tool: String,
    /// JSON-RPC id of the `tools/call` request.
    pub request_id: Value,
    /// Arguments as received.
    pub arguments: Value,
    /// Command the tool ran.
    pub argv: Vec<String>,
    /// cgroup v2 id the call ran in (all its descendants stay there unless
    /// they have the privilege to move out).
    pub cgroup_id: u64,
    /// Wall clock, RFC 3339 UTC.
    pub started_at: String,
    pub finished_at: String,
    /// Exit status of the main process (`None` if killed by a signal).
    pub exit_code: Option<i32>,
    /// Signal that ended the main process, if any.
    pub signal: Option<i32>,
    /// Processes still alive in the cgroup at the deadline were killed.
    pub killed_leftovers: bool,
}

/// Completeness signals the verifier can enforce.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrity {
    /// The cgroup was empty when collection stopped, so no process of the
    /// call could still produce effects.
    pub cgroup_drained: bool,
    /// Ring buffer records dropped (whole host) while the call ran. Non-zero
    /// means effects may be missing.
    pub ring_drops_during_call: u64,
    /// Effects whose path/address could not be fully read.
    pub incomplete_targets: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    pub observer: Observer,
    pub call: Call,
    pub effects: Vec<Effect>,
    pub integrity: Integrity,
}

/// SHA-256 of a JSON value serialized with sorted object keys and no
/// whitespace (`serde_json` default map is ordered). Not RFC 8785.
pub fn json_digest(v: &Value) -> String {
    dsse::hex(&Sha256::digest(
        serde_json::to_vec(v).expect("JSON value serializes"),
    ))
}

pub fn sha256_hex(b: &[u8]) -> String {
    dsse::hex(&Sha256::digest(b))
}

/// Subjects: the request (`tool`, `arguments`, `request_id`) and the
/// result returned to the client.
pub fn subjects(tool: &str, request_id: &Value, arguments: &Value, result: &Value) -> Vec<Subject> {
    let req = serde_json::json!({"tool": tool, "arguments": arguments, "request_id": request_id});
    vec![
        Subject {
            name: format!("mcp:tools/call:{tool}:request"),
            digest: BTreeMap::from([("sha256".to_string(), json_digest(&req))]),
        },
        Subject {
            name: format!("mcp:tools/call:{tool}:result"),
            digest: BTreeMap::from([("sha256".to_string(), json_digest(result))]),
        },
    ]
}

impl Statement {
    pub fn new(subject: Vec<Subject>, predicate: Predicate) -> Self {
        Statement {
            type_: STATEMENT_TYPE.into(),
            subject,
            predicate_type: PREDICATE_TYPE.into(),
            predicate,
        }
    }

    pub fn sign(&self, key: &SigningKey) -> Envelope {
        let body = serde_json::to_vec(self).expect("statement serializes");
        dsse::sign(key, dsse::IN_TOTO_PAYLOAD_TYPE, &body)
    }
}

/// Verify an envelope and parse the statement from the verified bytes.
pub fn verify_envelope(env: &Envelope, key: &VerifyingKey) -> Result<Statement> {
    let body = dsse::verify(env, key, dsse::IN_TOTO_PAYLOAD_TYPE)?;
    let st: Statement = serde_json::from_slice(&body).context("parsing statement")?;
    if st.type_ != STATEMENT_TYPE {
        bail!("unexpected _type {:?}", st.type_);
    }
    if st.predicate_type != PREDICATE_TYPE {
        bail!("unexpected predicateType {:?}", st.predicate_type);
    }
    if st.subject.is_empty() || st.subject.iter().any(|s| s.digest.is_empty()) {
        bail!("every subject must have a digest");
    }
    Ok(st)
}

/// Checks the verifier can apply on top of the signature.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Require `integrity.cgroup_drained` and zero ring drops.
    pub require_complete: bool,
    /// The request subject must match this (tool, arguments, request id).
    pub expect_request: Option<(String, Value, Value)>,
}

pub fn check_policy(st: &Statement, p: &Policy) -> Result<()> {
    if p.require_complete {
        let i = &st.predicate.integrity;
        if !i.cgroup_drained {
            bail!("cgroup was not drained: effects may be missing");
        }
        if i.ring_drops_during_call != 0 {
            bail!(
                "{} ring buffer drops during the call",
                i.ring_drops_during_call
            );
        }
    }
    if let Some((tool, args, id)) = &p.expect_request {
        let want = subjects(tool, id, args, &Value::Null).remove(0);
        if !st.subject.contains(&want) {
            bail!("request subject does not match {tool}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn sample(tool: &str) -> Statement {
        let pred = Predicate {
            observer: Observer {
                mechanism: "ebpf:raw_syscalls+cgroup_v2".into(),
                kernel: "test".into(),
                syscalls: vec!["openat".into()],
                version: "0.1.0".into(),
            },
            call: Call {
                tool: tool.into(),
                request_id: json!(7),
                arguments: json!({"args": ["x"]}),
                argv: vec!["/bin/true".into()],
                cgroup_id: 42,
                started_at: "2026-01-01T00:00:00Z".into(),
                finished_at: "2026-01-01T00:00:01Z".into(),
                exit_code: Some(0),
                signal: None,
                killed_leftovers: false,
            },
            effects: vec![],
            integrity: Integrity {
                cgroup_drained: true,
                ..Default::default()
            },
        };
        Statement::new(
            subjects(
                tool,
                &json!(7),
                &json!({"args": ["x"]}),
                &json!({"content": []}),
            ),
            pred,
        )
    }

    #[test]
    fn statement_shape() {
        let v = serde_json::to_value(sample("t")).unwrap();
        assert_eq!(v["_type"], STATEMENT_TYPE);
        assert_eq!(v["predicateType"], PREDICATE_TYPE);
        assert_eq!(v["subject"].as_array().unwrap().len(), 2);
        assert_eq!(
            v["subject"][0]["digest"]["sha256"].as_str().unwrap().len(),
            64
        );
    }

    #[test]
    fn json_digest_is_key_order_independent() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":[1,{"d":2,"c":3}]}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"a":[1,{"c":3,"d":2}],"b":1}"#).unwrap();
        assert_eq!(json_digest(&a), json_digest(&b));
        assert_ne!(json_digest(&a), json_digest(&json!({"a":1})));
    }

    #[test]
    fn sign_verify_and_policy() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let st = sample("t");
        let env = st.sign(&k);
        let back = verify_envelope(&env, &k.verifying_key()).unwrap();
        assert_eq!(back, st);
        let p = Policy {
            require_complete: true,
            expect_request: Some(("t".into(), json!({"args": ["x"]}), json!(7))),
        };
        check_policy(&back, &p).unwrap();
        let wrong = Policy {
            expect_request: Some(("t".into(), json!({"args": ["y"]}), json!(7))),
            ..Default::default()
        };
        assert!(check_policy(&back, &wrong).is_err());
    }

    #[test]
    fn incomplete_fails_strict_policy() {
        let mut st = sample("t");
        st.predicate.integrity.cgroup_drained = false;
        let p = Policy {
            require_complete: true,
            ..Default::default()
        };
        assert!(check_policy(&st, &p).is_err());
        st.predicate.integrity.cgroup_drained = true;
        st.predicate.integrity.ring_drops_during_call = 1;
        assert!(check_policy(&st, &p).is_err());
    }

    #[test]
    fn other_predicate_type_rejected() {
        let k = SigningKey::from_bytes(&[1; 32]);
        let mut st = sample("t");
        st.predicate_type = "https://slsa.dev/provenance/v1".into();
        let env = st.sign(&k);
        assert!(verify_envelope(&env, &k.verifying_key()).is_err());
    }
}
