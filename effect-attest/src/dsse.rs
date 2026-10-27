//! DSSE (Dead Simple Signing Envelope) v1 with Ed25519.
//!
//! Implements the protocol as written in the DSSE spec (protocol.md and
//! envelope.md, v1.0.2): the signature covers
//! `PAE(payloadType, payload)`, never the raw payload, and the verifier
//! returns the exact bytes it verified so callers cannot re-parse a
//! different payload afterwards.
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Payload type of in-toto statements inside DSSE.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`.
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let t = payload_type.as_bytes();
    let mut out = Vec::with_capacity(32 + t.len() + body.len());
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(t.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(t);
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(body);
    out
}

/// One signature in an envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeSignature {
    /// Unauthenticated hint; never used for security decisions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keyid: String,
    pub sig: String,
}

/// The standard DSSE JSON envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<EnvelopeSignature>,
}

/// Key id used in envelopes: hex SHA-256 of the raw 32-byte public key.
pub fn keyid(key: &VerifyingKey) -> String {
    hex(&Sha256::digest(key.as_bytes()))
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// Sign `body` as `payload_type`.
pub fn sign(key: &SigningKey, payload_type: &str, body: &[u8]) -> Envelope {
    let sig = key.sign(&pae(payload_type, body));
    Envelope {
        payload: STANDARD.encode(body),
        payload_type: payload_type.to_string(),
        signatures: vec![EnvelopeSignature {
            keyid: keyid(&key.verifying_key()),
            sig: STANDARD.encode(sig.to_bytes()),
        }],
    }
}

/// Base64 decoding that accepts standard and URL-safe alphabets, as the
/// spec requires of verifiers.
pub fn b64decode(s: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .map_err(|e| anyhow!("invalid base64: {e}"))
}

/// Verify `env` against `key` and return the verified payload bytes.
///
/// Rejects: bad base64, unexpected payload type, no signature from `key`.
/// The keyid is only used to skip signatures that announce another key.
pub fn verify(env: &Envelope, key: &VerifyingKey, expected_type: &str) -> Result<Vec<u8>> {
    let body = b64decode(&env.payload).context("payload")?;
    let msg = pae(&env.payload_type, &body);
    let want_id = keyid(key);
    let mut tried = 0;
    for s in &env.signatures {
        if !s.keyid.is_empty() && s.keyid != want_id {
            continue;
        }
        tried += 1;
        let Ok(raw) = b64decode(&s.sig) else { continue };
        let Ok(sig) = Signature::from_slice(&raw) else {
            continue;
        };
        if key.verify(&msg, &sig).is_ok() {
            if env.payload_type != expected_type {
                bail!(
                    "unsupported payloadType {:?} (expected {expected_type:?})",
                    env.payload_type
                );
            }
            return Ok(body);
        }
    }
    if tried == 0 {
        bail!("no signature for keyid {want_id}");
    }
    bail!("signature verification failed")
}

/// Ed25519 key material on disk: 32-byte seed as 64 hex chars (private) and
/// 32-byte public key as 64 hex chars.
pub mod keys {
    use super::*;
    use std::path::Path;

    fn unhex32(s: &str) -> Result<[u8; 32]> {
        let s = s.trim();
        if s.len() != 64 {
            bail!("expected 64 hex characters, got {}", s.len());
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .context("non-hex character")?;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .context("non-hex character")?;
            out[i] = (hi * 16 + lo) as u8;
        }
        Ok(out)
    }

    /// New random key from the OS RNG.
    pub fn generate() -> Result<SigningKey> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(|e| anyhow!("getrandom: {e}"))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    pub fn signing_from_hex(s: &str) -> Result<SigningKey> {
        Ok(SigningKey::from_bytes(&unhex32(s)?))
    }

    pub fn verifying_from_hex(s: &str) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&unhex32(s)?).map_err(|e| anyhow!("invalid public key: {e}"))
    }

    pub fn read_signing(path: &Path) -> Result<SigningKey> {
        signing_from_hex(
            &std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
    }

    pub fn read_verifying(path: &Path) -> Result<VerifyingKey> {
        verifying_from_hex(
            &std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
    }

    /// Write `<prefix>.key` (mode 0600) and `<prefix>.pub`.
    pub fn write_pair(key: &SigningKey, prefix: &Path) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let priv_path = prefix.with_extension("key");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&priv_path)
            .with_context(|| format!("creating {}", priv_path.display()))?;
        writeln!(f, "{}", hex(key.as_bytes()))?;
        let pub_path = prefix.with_extension("pub");
        std::fs::write(
            &pub_path,
            format!("{}\n", hex(key.verifying_key().as_bytes())),
        )
        .with_context(|| format!("writing {}", pub_path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    #[test]
    fn pae_matches_spec_vector() {
        // Test vector from the DSSE protocol spec.
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
        );
    }

    #[test]
    fn pae_empty() {
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    #[test]
    fn spec_envelope_payload_decodes() {
        // `payload` of the spec's example envelope.
        assert_eq!(b64decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
    }

    #[test]
    fn roundtrip() {
        let k = key(7);
        let env = sign(&k, IN_TOTO_PAYLOAD_TYPE, b"{\"a\":1}");
        let body = verify(&env, &k.verifying_key(), IN_TOTO_PAYLOAD_TYPE).unwrap();
        assert_eq!(body, b"{\"a\":1}");
        assert_eq!(env.signatures[0].keyid, keyid(&k.verifying_key()));
    }

    #[test]
    fn tampered_payload_rejected() {
        let k = key(7);
        let mut env = sign(&k, IN_TOTO_PAYLOAD_TYPE, b"{\"a\":1}");
        env.payload = STANDARD.encode(b"{\"a\":2}");
        assert!(verify(&env, &k.verifying_key(), IN_TOTO_PAYLOAD_TYPE).is_err());
    }

    #[test]
    fn tampered_type_rejected() {
        // The type is inside PAE, so changing it breaks the signature.
        let k = key(7);
        let mut env = sign(&k, IN_TOTO_PAYLOAD_TYPE, b"x");
        env.payload_type = "application/json".into();
        let err = verify(&env, &k.verifying_key(), "application/json").unwrap_err();
        assert!(err.to_string().contains("verification failed"), "{err}");
    }

    #[test]
    fn unexpected_type_rejected_even_if_signed() {
        let k = key(7);
        let env = sign(&k, "application/x-other", b"x");
        let err = verify(&env, &k.verifying_key(), IN_TOTO_PAYLOAD_TYPE).unwrap_err();
        assert!(err.to_string().contains("unsupported payloadType"), "{err}");
    }

    #[test]
    fn wrong_key_rejected() {
        let env = sign(&key(7), IN_TOTO_PAYLOAD_TYPE, b"x");
        let mut env2 = env.clone();
        env2.signatures[0].keyid.clear();
        assert!(verify(&env, &key(8).verifying_key(), IN_TOTO_PAYLOAD_TYPE).is_err());
        assert!(verify(&env2, &key(8).verifying_key(), IN_TOTO_PAYLOAD_TYPE).is_err());
    }

    #[test]
    fn url_safe_base64_accepted() {
        let k = key(9);
        let body = vec![0xfbu8, 0xff, 0xfe, 0x3e, 0x3f];
        let mut env = sign(&k, IN_TOTO_PAYLOAD_TYPE, &body);
        env.payload = URL_SAFE_NO_PAD.encode(&body);
        env.signatures[0].sig = URL_SAFE.encode(b64decode(&env.signatures[0].sig).unwrap());
        assert_eq!(
            verify(&env, &k.verifying_key(), IN_TOTO_PAYLOAD_TYPE).unwrap(),
            body
        );
    }

    #[test]
    fn missing_keyid_is_tried() {
        let k = key(3);
        let mut env = sign(&k, IN_TOTO_PAYLOAD_TYPE, b"x");
        env.signatures[0].keyid.clear();
        assert!(verify(&env, &k.verifying_key(), IN_TOTO_PAYLOAD_TYPE).is_ok());
        let json = serde_json::to_string(&env).unwrap();
        assert!(!json.contains("keyid"), "{json}");
    }

    #[test]
    fn hex_keys_roundtrip() {
        let k = key(5);
        let s = keys::signing_from_hex(&hex(k.as_bytes())).unwrap();
        assert_eq!(s.as_bytes(), k.as_bytes());
        let v = keys::verifying_from_hex(&hex(k.verifying_key().as_bytes())).unwrap();
        assert_eq!(v, k.verifying_key());
        assert!(keys::signing_from_hex("abcd").is_err());
        assert!(keys::signing_from_hex(&"zz".repeat(32)).is_err());
    }
}
