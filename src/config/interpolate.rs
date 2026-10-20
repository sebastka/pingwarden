//! `${VAR}`, `${VAR:-default}` and `${file:/path}` substitution in string values.
//!
//! Substitution runs on parsed YAML scalars, never on raw text, so a secret
//! containing YAML syntax cannot change the document structure.

use std::collections::HashMap;
use std::env;
use std::fs;

use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum InterpolateError {
    #[error("{path}: environment variable {name} is not set")]
    MissingVar { path: String, name: String },
    #[error("{path}: cannot read secret file {file}: {source}")]
    File {
        path: String,
        file: String,
        source: std::io::Error,
    },
    #[error("{path}: unterminated \"${{\" in {value:?}")]
    Unterminated { path: String, value: String },
}

/// Walk a JSON tree and substitute every string scalar in place.
///
/// Values that were exactly one reference are offered as numbers or booleans;
/// their resolved text is recorded in `originals` (keyed by path) so that the
/// caller can restore it when a string was expected.
pub fn interpolate_tree(
    value: &mut Value,
    path: &mut String,
    originals: &mut HashMap<String, String>,
) -> Result<(), InterpolateError> {
    match value {
        Value::String(s) => {
            let whole_reference = s.starts_with("${") && s.ends_with('}') && s.matches("${").count() == 1;
            let replaced = interpolate_str(s, path)?;
            // A value that was exactly one reference may become a number or a
            // boolean, so that `port: ${PORT}` works as expected.
            *value = if whole_reference {
                let typed = scalar_from_str(&replaced);
                if !typed.is_string() {
                    originals.insert(path.clone(), replaced);
                }
                typed
            } else {
                Value::String(replaced)
            };
        }
        Value::Array(items) => {
            for (i, item) in items.iter_mut().enumerate() {
                let len = path.len();
                path.push_str(&format!("[{i}]"));
                interpolate_tree(item, path, originals)?;
                path.truncate(len);
            }
        }
        Value::Object(map) => {
            for (key, item) in map.iter_mut() {
                let len = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                interpolate_tree(item, path, originals)?;
                path.truncate(len);
            }
        }
        _ => {}
    }
    Ok(())
}

fn scalar_from_str(s: &str) -> Value {
    match s {
        "true" => return Value::Bool(true),
        "false" => return Value::Bool(false),
        _ => {}
    }
    if let Ok(i) = s.parse::<i64>() {
        return Value::from(i);
    }
    if let Ok(f) = s.parse::<f64>()
        && f.is_finite()
    {
        return Value::from(f);
    }
    Value::String(s.to_owned())
}

pub fn interpolate_str(input: &str, path: &str) -> Result<String, InterpolateError> {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        if let Some(stripped) = rest.strip_prefix("$$") {
            out.push('$');
            rest = stripped;
            continue;
        }
        let Some(body_start) = rest.strip_prefix("${") else {
            out.push('$');
            rest = &rest[1..];
            continue;
        };
        let Some(end) = body_start.find('}') else {
            return Err(InterpolateError::Unterminated {
                path: path.to_owned(),
                value: input.to_owned(),
            });
        };
        out.push_str(&resolve(&body_start[..end], path)?);
        rest = &body_start[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn resolve(expr: &str, path: &str) -> Result<String, InterpolateError> {
    if let Some(file) = expr.strip_prefix("file:") {
        return fs::read_to_string(file)
            .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
            .map_err(|source| InterpolateError::File {
                path: path.to_owned(),
                file: file.to_owned(),
                source,
            });
    }
    let (name, default) = match expr.split_once(":-") {
        Some((name, default)) => (name, Some(default)),
        None => (expr, None),
    };
    match (env::var(name), default) {
        (Ok(v), _) => Ok(v),
        (Err(_), Some(d)) => Ok(d.to_owned()),
        (Err(_), None) => Err(InterpolateError::MissingVar {
            path: path.to_owned(),
            name: name.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn substitutes_defaults_and_escapes() {
        let s = interpolate_str("a ${PINGWARDEN_TEST_UNSET:-b} $$ c $x", "p").unwrap();
        assert_eq!(s, "a b $ c $x");
    }

    #[test]
    fn missing_variable_is_an_error() {
        let e = interpolate_str("${PINGWARDEN_TEST_UNSET_2}", "server.listen").unwrap_err();
        assert!(e.to_string().contains("server.listen"));
    }

    #[test]
    fn unterminated_is_an_error() {
        assert!(interpolate_str("${oops", "p").is_err());
    }

    #[test]
    fn whole_reference_becomes_typed_scalar() {
        let mut v = json!({"port": "${PINGWARDEN_TEST_UNSET_3:-8080}", "s": "x${PINGWARDEN_TEST_UNSET_3:-1}", "b": "${PINGWARDEN_TEST_UNSET_3:-true}"});
        let mut originals = HashMap::new();
        interpolate_tree(&mut v, &mut String::new(), &mut originals).unwrap();
        assert_eq!(v, json!({"port": 8080, "s": "x1", "b": true}));
        assert_eq!(originals.get("port").map(String::as_str), Some("8080"));
    }

    #[test]
    fn reads_secret_files() {
        let dir = std::env::temp_dir().join(format!("pw-interp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("secret");
        std::fs::write(&f, "hunter2\n").unwrap();
        let s = interpolate_str(&format!("${{file:{}}}", f.display()), "p").unwrap();
        assert_eq!(s, "hunter2");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
