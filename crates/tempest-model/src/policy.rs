use crate::validation::Diagnostic;
use serde::{Deserialize, Deserializer, de};
use std::{fmt, marker::PhantomData};

/// LWS accepts either one value or an array, without coercing scalar types.
#[derive(Debug, Clone, PartialEq)]
pub struct OneOrMany<T>(pub Vec<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for OneOrMany<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Values<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Values<T> {
            type Value = OneOrMany<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a single value or array")
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element()? {
                    values.push(value);
                }
                Ok(OneOrMany(values))
            }
            fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                T::deserialize(de::value::MapAccessDeserializer::new(map))
                    .map(|v| OneOrMany(vec![v]))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                T::deserialize(de::value::StrDeserializer::<E>::new(value))
                    .map(|v| OneOrMany(vec![v]))
            }
        }
        deserializer.deserialize_any(Values(PhantomData))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Policy {
    #[serde(default)]
    pub version: Option<String>,
    pub statement: OneOrMany<Statement>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "PascalCase")]
pub struct Statement {
    #[serde(default)]
    pub sid: Option<String>,
    pub effect: String,
    pub action: OneOrMany<String>,
    pub resource: OneOrMany<String>,
}

impl Policy {
    /// Syntax only, matched to LWS src/iam.rs Policy::parse. No IAM evaluation.
    pub fn validate(&self, path: &str, errors: &mut Vec<Diagnostic>) {
        if self
            .version
            .as_deref()
            .is_some_and(|v| !matches!(v, "2012-10-17" | "2008-10-17"))
        {
            errors.push(Diagnostic::new(
                format!("{path}.Version"),
                "unsupported policy version",
            ));
        }
        for (i, statement) in self.statement.0.iter().enumerate() {
            let p = format!("{path}.Statement[{i}]");
            if !matches!(statement.effect.as_str(), "Allow" | "Deny") {
                errors.push(Diagnostic::new(
                    format!("{p}.Effect"),
                    "expected Allow or Deny",
                ));
            }
            for (name, patterns) in [
                ("Action", &statement.action.0),
                ("Resource", &statement.resource.0),
            ] {
                if patterns.is_empty() {
                    errors.push(Diagnostic::new(
                        format!("{p}.{name}"),
                        "empty pattern array is unsupported",
                    ));
                }
                for (j, pattern) in patterns.iter().enumerate() {
                    if pattern.is_empty() || pattern.contains("${") {
                        errors.push(Diagnostic::new(
                            format!("{p}.{name}[{j}]"),
                            "empty patterns and policy variables (${...}) are unsupported",
                        ));
                    }
                }
            }
        }
    }
}
