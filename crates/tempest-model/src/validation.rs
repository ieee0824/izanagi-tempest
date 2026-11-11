use crate::{
    capability::{self, ResourceKind, Support},
    scenario::*,
};
use std::{collections::HashSet, fmt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub path: String,
    pub reason: String,
}
impl Diagnostic {
    pub fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            reason: reason.into(),
        }
    }
}
impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.reason)
    }
}
impl std::error::Error for Diagnostic {}

impl ScenarioInput {
    pub fn validate(mut self) -> Result<ValidatedScenario, Vec<Diagnostic>> {
        let mut errors = Vec::new();
        let parts: Vec<_> = self.id.split('-').collect();
        if parts.len() < 3
            || parts
                .last()
                .is_none_or(|p| p.len() != 3 || !p.bytes().all(|b| b.is_ascii_digit()))
            || parts[..parts.len().saturating_sub(1)].iter().any(|p| {
                p.is_empty()
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            })
        {
            errors.push(Diagnostic::new(
                "id",
                "expected descriptive <service>-<topic>-<nnn> ID",
            ));
        }
        for (path, value) in [("title", &self.title), ("task", &self.task)] {
            if value.trim().is_empty() {
                errors.push(Diagnostic::new(path, "must not be empty"));
            }
        }
        if self.target != "lws" {
            errors.push(Diagnostic::new("target", "only lws is supported"));
        }
        if self.auth_mode != "strict" {
            errors.push(Diagnostic::new(
                "auth_mode",
                "only strict mode is supported",
            ));
        }
        if self.setup.users.is_empty() {
            errors.push(Diagnostic::new(
                "setup.users",
                "at least one user is required",
            ));
        }
        let mut users = HashSet::new();
        for (i, u) in self.setup.users.iter().enumerate() {
            let path = format!("setup.users[{i}]");
            unique(&mut users, &u.name, &format!("{path}.name"), &mut errors);
            if u.name.len() > 64
                || !u
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"+=,.@_-".contains(&c))
            {
                errors.push(Diagnostic::new(
                    format!("{path}.name"),
                    "invalid IAM user name (1..64 ASCII IAM characters)",
                ));
            }
            u.policy.validate(&format!("{path}.policy"), &mut errors);
        }
        let mut buckets = HashSet::new();
        for (i, b) in self.setup.buckets.iter().enumerate() {
            let p = format!("setup.buckets[{i}]");
            unique(&mut buckets, &b.name, &format!("{p}.name"), &mut errors);
            if b.name.contains('/')
                || b.name
                    .chars()
                    .any(|c| c.is_whitespace() || "*?:".contains(c))
            {
                errors.push(Diagnostic::new(
                    format!("{p}.name"),
                    "expected a concrete bucket name",
                ));
            }
            let mut objects = HashSet::new();
            for (j, o) in b.objects.iter().enumerate() {
                unique(
                    &mut objects,
                    &o.key,
                    &format!("{p}.objects[{j}].key"),
                    &mut errors,
                );
            }
        }
        let mut queues = HashSet::new();
        for (i, q) in self.setup.queues.iter().enumerate() {
            let p = format!("setup.queues[{i}].name");
            unique(&mut queues, &q.name, &p, &mut errors);
            let stem = q.name.strip_suffix(".fifo").unwrap_or(&q.name);
            if q.name.len() > 80
                || stem.is_empty()
                || !stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            {
                errors.push(Diagnostic::new(
                    p,
                    "invalid SQS queue name (1..80 ASCII letters/digits/_/-, optional .fifo)",
                ));
            }
        }
        checks(&self.expect, "expect", &self.setup, &mut errors);
        if let Some(finding) = &self.expected_finding {
            if finding.description.trim().is_empty() {
                errors.push(Diagnostic::new(
                    "expected_finding.description",
                    "must not be empty",
                ));
            }
            check(
                &finding.evidence,
                "expected_finding.evidence",
                &self.setup,
                &mut errors,
            );
            if finding.evidence.result != Outcome::Allow {
                errors.push(Diagnostic::new(
                    "expected_finding.evidence.result",
                    "finding evidence must be allow",
                ));
            }
        }
        if let Some(retest) = &mut self.retest {
            if retest.user.is_none() && self.setup.users.len() == 1 {
                retest.user = Some(self.setup.users[0].name.clone());
            }
            match &retest.user {
                None => errors.push(Diagnostic::new(
                    "retest.user",
                    "explicit user is required with multiple users",
                )),
                Some(user) if !users.contains(user.as_str()) => {
                    errors.push(Diagnostic::new("retest.user", "unknown setup user"))
                }
                _ => {}
            }
            retest.policy.validate("retest.policy", &mut errors);
            checks(&retest.expect, "retest.expect", &self.setup, &mut errors);
        }
        for (i, c) in self.success_criteria.iter().enumerate() {
            if let Criterion::Named(m) = c {
                if m.len() != 1 {
                    errors.push(Diagnostic::new(
                        format!("success_criteria[{i}]"),
                        "named criterion requires exactly one label",
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(ValidatedScenario { scenario: self })
        } else {
            Err(errors)
        }
    }
}
fn unique<'a>(
    set: &mut HashSet<&'a str>,
    value: &'a str,
    path: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if value.is_empty() || !set.insert(value) {
        errors.push(Diagnostic::new(path, "empty or duplicate name/key"));
    }
}
fn checks(checks: &[Check], path: &str, setup: &Setup, errors: &mut Vec<Diagnostic>) {
    for (i, c) in checks.iter().enumerate() {
        check(c, &format!("{path}[{i}]"), setup, errors);
    }
}
fn check(c: &Check, path: &str, setup: &Setup, errors: &mut Vec<Diagnostic>) {
    let Some(capability) = capability::lookup(&c.api) else {
        errors.push(Diagnostic::new(
            format!("{path}.api"),
            "unknown API or unmapped operation in pinned LWS strict mode",
        ));
        return;
    };
    match capability.support {
        Support::Unsupported(reason) => errors.push(Diagnostic::new(
            format!("{path}.api"),
            format!("LWS strict unsupported: {reason}"),
        )),
        Support::Unrepresentable(reason) => errors.push(Diagnostic::new(
            format!("{path}.api"),
            format!("input representation error: {reason}"),
        )),
        Support::Static => {}
    }
    if let Err(reason) = resource(&c.resource, capability.resource, setup) {
        errors.push(Diagnostic::new(format!("{path}.resource"), reason));
    }
}
pub fn resource(arn: &str, kind: ResourceKind, setup: &Setup) -> Result<(), &'static str> {
    if kind == ResourceKind::Global {
        return if arn == "*" {
            Ok(())
        } else {
            Err("this API requires global resource *")
        };
    }
    if arn.contains(['*', '?']) {
        return Err("expected a concrete ARN, not a policy wildcard");
    }
    let fields: Vec<_> = arn.splitn(6, ':').collect();
    if fields.len() != 6 || fields[0] != "arn" || fields[1] != "aws" {
        return Err("invalid ARN (expected arn:aws:service:region:account:resource)");
    }
    match kind {
        ResourceKind::Bucket | ResourceKind::Object => {
            if fields[2] != "s3" || !fields[3].is_empty() || !fields[4].is_empty() {
                return Err("expected S3 ARN with empty region/account");
            }
            let (bucket, key) = fields[5]
                .split_once('/')
                .map_or((fields[5], None), |(b, k)| (b, Some(k)));
            let b = setup
                .buckets
                .iter()
                .find(|b| b.name == bucket)
                .ok_or("bucket is not defined in setup.buckets")?;
            match (kind, key) {
                (ResourceKind::Bucket, None) => Ok(()),
                (ResourceKind::Object, Some(k)) if b.objects.iter().any(|o| o.key == k) => Ok(()),
                (ResourceKind::Object, Some(_)) => Err("object is not defined in setup bucket"),
                _ => Err("ARN resource kind does not match API (bucket/object)"),
            }
        }
        ResourceKind::Queue => {
            if fields[2] != "sqs"
                || fields[3] != capability::REGION
                || fields[4] != capability::ACCOUNT
            {
                return Err("expected SQS ARN in us-east-1 account 000000000000");
            }
            if setup.queues.iter().any(|q| q.name == fields[5]) {
                Ok(())
            } else {
                Err("queue is not defined in setup.queues")
            }
        }
        ResourceKind::Identity => Err("SES identity setup is not represented by ScenarioInput"),
        ResourceKind::Global => unreachable!(),
    }
}
