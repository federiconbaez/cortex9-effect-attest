//! Tool catalog: each tool runs a fixed command, plus the string arguments
//! the client passes in `arguments.args`.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ToolDef {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// argv; the first element is the program.
    pub command: Vec<String>,
    /// Kill the call after this many milliseconds.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}

fn default_timeout() -> u64 {
    30_000
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub tools: Vec<ToolDef>,
}

impl Catalog {
    pub fn parse(s: &str) -> Result<Self> {
        let c: Catalog = serde_json::from_str(s).context("parsing tool catalog")?;
        c.validate()?;
        Ok(c)
    }

    pub fn load(path: &Path) -> Result<Self> {
        Self::parse(
            &std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?,
        )
    }

    fn validate(&self) -> Result<()> {
        let mut names = std::collections::HashSet::new();
        for t in &self.tools {
            if t.name.is_empty() || t.name.len() > 64 {
                bail!("tool name must have 1..=64 characters: {:?}", t.name);
            }
            if !t
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c))
            {
                bail!("tool name may only use [A-Za-z0-9_.-]: {:?}", t.name);
            }
            if t.command.is_empty() {
                bail!("tool {} has an empty command", t.name);
            }
            if !names.insert(t.name.as_str()) {
                bail!("duplicate tool {}", t.name);
            }
        }
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<&ToolDef> {
        self.tools.iter().find(|t| t.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_defaults() {
        let c = Catalog::parse(r#"{"tools":[{"name":"t1","command":["/bin/true"]}]}"#).unwrap();
        assert_eq!(c.tools[0].timeout_ms, 30_000);
        assert!(c.get("t1").is_some());
        assert!(c.get("t2").is_none());
    }

    #[test]
    fn rejects_bad_catalogs() {
        for bad in [
            r#"{"tools":[{"name":"","command":["x"]}]}"#,
            r#"{"tools":[{"name":"a b","command":["x"]}]}"#,
            r#"{"tools":[{"name":"a","command":[]}]}"#,
            r#"{"tools":[{"name":"a","command":["x"]},{"name":"a","command":["y"]}]}"#,
            r#"{"tools":[{"name":"a","command":["x"],"extra":1}]}"#,
            r#"{"tools":"nope"}"#,
        ] {
            assert!(Catalog::parse(bad).is_err(), "{bad}");
        }
    }
}
