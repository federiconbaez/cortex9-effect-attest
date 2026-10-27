//! Minimal JSON-RPC 2.0 framing for MCP over stdio (one message per line).
use serde_json::{json, Value};

pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

#[derive(Debug, PartialEq)]
pub enum Incoming {
    /// Has an id: needs a response.
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    /// No id: never answered.
    Notification { method: String },
    /// Could not be understood; answer with this error response.
    Invalid(Value),
}

pub fn response(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

pub fn error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Classify one line.
pub fn parse_line(line: &str) -> Incoming {
    let v: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => return Incoming::Invalid(error(&Value::Null, PARSE_ERROR, &e.to_string())),
    };
    let Some(obj) = v.as_object() else {
        return Incoming::Invalid(error(&Value::Null, INVALID_REQUEST, "not an object"));
    };
    let id = obj.get("id").cloned();
    let valid_id = matches!(id, None | Some(Value::String(_)) | Some(Value::Number(_)));
    if obj.get("jsonrpc") != Some(&json!("2.0")) || !valid_id {
        return Incoming::Invalid(error(
            &id.filter(|_| valid_id).unwrap_or(Value::Null),
            INVALID_REQUEST,
            "invalid JSON-RPC 2.0 request",
        ));
    }
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return Incoming::Invalid(error(
            &id.unwrap_or(Value::Null),
            INVALID_REQUEST,
            "missing method",
        ));
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);
    match id {
        Some(id) => Incoming::Request {
            id,
            method: method.to_string(),
            params,
        },
        None => Incoming::Notification {
            method: method.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_and_notification() {
        assert_eq!(
            parse_line(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            Incoming::Request {
                id: json!(1),
                method: "ping".into(),
                params: Value::Null
            }
        );
        assert_eq!(
            parse_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            Incoming::Notification {
                method: "notifications/initialized".into()
            }
        );
    }

    #[test]
    fn errors() {
        let code = |s: &str| match parse_line(s) {
            Incoming::Invalid(v) => v["error"]["code"].as_i64().unwrap(),
            other => panic!("{other:?}"),
        };
        assert_eq!(code("{"), PARSE_ERROR);
        assert_eq!(code("[]"), INVALID_REQUEST);
        assert_eq!(
            code(r#"{"jsonrpc":"1.0","id":1,"method":"x"}"#),
            INVALID_REQUEST
        );
        assert_eq!(
            code(r#"{"jsonrpc":"2.0","id":{},"method":"x"}"#),
            INVALID_REQUEST
        );
        assert_eq!(code(r#"{"jsonrpc":"2.0","id":3}"#), INVALID_REQUEST);
    }

    #[test]
    fn error_keeps_valid_id() {
        let Incoming::Invalid(v) = parse_line(r#"{"jsonrpc":"2.0","id":"a"}"#) else {
            panic!()
        };
        assert_eq!(v["id"], "a");
    }
}
