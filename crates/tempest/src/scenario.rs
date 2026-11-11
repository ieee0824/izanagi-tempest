use serde::de::IntoDeserializer;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempest_model::{Diagnostic, ScenarioInput, ValidatedScenario};

#[derive(Debug)]
pub struct LoadedScenario {
    pub raw: Vec<u8>,
    pub sha256: String,
    pub validated: ValidatedScenario,
}

/// Parse once through native YAML Value so duplicate keys cannot be overwritten.
/// JSON conversion then enforces strict scalar types at the shared DTO endpoint.
pub fn load(raw: &[u8]) -> Result<LoadedScenario, Vec<Diagnostic>> {
    let native: yaml_serde::Value = yaml_serde::from_slice(raw)
        .map_err(|e| vec![Diagnostic::new("$", format!("YAML parse error: {e}"))])?;
    let value = json_compatible(native, "$").map_err(|e| vec![e])?;
    let input: ScenarioInput = serde_path_to_error::deserialize(value.into_deserializer())
        .map_err(|e| vec![Diagnostic::new(e.path().to_string(), e.inner().to_string())])?;
    let validated = input.validate()?;
    Ok(LoadedScenario {
        raw: raw.to_vec(),
        sha256: format!("{:x}", Sha256::digest(raw)),
        validated,
    })
}

fn json_compatible(value: yaml_serde::Value, path: &str) -> Result<Value, Diagnostic> {
    use yaml_serde::Value as Y;
    match value {
        Y::Tagged(_) => Err(Diagnostic::new(path, "custom YAML tags are unsupported")),
        Y::Number(n) if n.as_f64().is_some_and(|v| !v.is_finite()) => Err(Diagnostic::new(
            path,
            "non-finite YAML numbers are unsupported",
        )),
        Y::Mapping(mapping) => {
            let mut out = serde_json::Map::new();
            for (key, value) in mapping {
                let Y::String(key) = key else {
                    return Err(Diagnostic::new(path, "mapping keys must be strings"));
                };
                if key == "<<" {
                    return Err(Diagnostic::new(path, "YAML merge keys are unsupported"));
                }
                let next = format!("{path}.{key}");
                out.insert(key, json_compatible(value, &next)?);
            }
            Ok(Value::Object(out))
        }
        Y::Sequence(values) => values
            .into_iter()
            .enumerate()
            .map(|(i, v)| json_compatible(v, &format!("{path}[{i}]")))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        other => serde_json::to_value(other).map_err(|e| Diagnostic::new(path, e.to_string())),
    }
}
