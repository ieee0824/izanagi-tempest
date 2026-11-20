//! Offline handoff verification fixture. The manual login entry remains disabled.
use super::login_permit::Scope;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::Deserialize;
use std::io;

const DOMAIN: &[u8] = b"izanagi-tempest:manual-login-handoff:fixture-v1\0";

#[derive(Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
struct Handoff {
    permit_id: String,
    approval_pair_sha256: String,
    expires_unix_seconds: u64,
    target_id: String,
    executable_sha256: String,
    arguments: [String; 2],
    authority: String,
    approved_ips_revision: u64,
}

pub(super) fn verify_handoff(
    trusted_key: &[u8; 32],
    signed: &[u8],
    signature: &[u8],
    expected: Scope<'_>,
    policy_expires_unix_seconds: u64,
    now_unix_seconds: u64,
) -> io::Result<u128> {
    if signed.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized handoff",
        ));
    }
    UnparsedPublicKey::new(&ED25519, trusted_key)
        .verify(signed, signature)
        .map_err(|_| {
            io::Error::new(io::ErrorKind::PermissionDenied, "invalid handoff signature")
        })?;
    let payload = signed
        .strip_prefix(DOMAIN)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "wrong handoff purpose"))?;
    let handoff: Handoff = serde_json::from_slice(payload)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid handoff payload"))?;
    let lowercase_hex = |value: &str, len| {
        value.len() == len
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if !lowercase_hex(&handoff.permit_id, 32) || !lowercase_hex(&handoff.approval_pair_sha256, 64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid handoff identifiers",
        ));
    }
    let permit_id = u128::from_str_radix(&handoff.permit_id, 16)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid handoff permit ID"))?;
    if handoff
        .expires_unix_seconds
        .min(policy_expires_unix_seconds)
        <= now_unix_seconds
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "handoff expired",
        ));
    }
    let arguments = handoff.arguments.each_ref().map(String::as_str);
    let scope = Scope {
        executable_sha256: &handoff.executable_sha256,
        arguments: &arguments,
        authority: &handoff.authority,
        target_id: &handoff.target_id,
        approved_ips_revision: handoff.approved_ips_revision,
    };
    if scope != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "handoff scope mismatch",
        ));
    }
    Ok(permit_id)
}

#[cfg(test)]
pub(super) fn signed_fixture(
    key: &ring::signature::Ed25519KeyPair,
    permit_id: u128,
    scope: Scope<'_>,
    expires_unix_seconds: u64,
) -> (Vec<u8>, ring::signature::Signature) {
    let arguments = scope.arguments.try_into().expect("fixed login arguments");
    let [first, second]: [&str; 2] = arguments;
    let handoff = Handoff {
        permit_id: format!("{permit_id:032x}"),
        approval_pair_sha256: "a".repeat(64),
        expires_unix_seconds,
        target_id: scope.target_id.into(),
        executable_sha256: scope.executable_sha256.into(),
        arguments: [first.into(), second.into()],
        authority: scope.authority.into(),
        approved_ips_revision: scope.approved_ips_revision,
    };
    let mut signed = DOMAIN.to_vec();
    signed.extend(serde_json::to_vec(&handoff).unwrap());
    let signature = key.sign(&signed);
    (signed, signature)
}

#[test]
fn offline_handoff_checks_signature_expiry_and_scope() {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let key = Ed25519KeyPair::from_seed_unchecked(&[1; 32]).unwrap();
    let other = Ed25519KeyPair::from_seed_unchecked(&[2; 32]).unwrap();
    let trusted = key.public_key().as_ref().try_into().unwrap();
    let expected = Scope {
        executable_sha256: "test-cli-digest",
        arguments: &["auth", "login"],
        authority: "auth.example.invalid:443",
        target_id: "registered-fixture",
        approved_ips_revision: 7,
    };
    let handoff = Handoff {
        permit_id: format!("{:032x}", 42),
        approval_pair_sha256: "a".repeat(64),
        expires_unix_seconds: 120,
        target_id: expected.target_id.into(),
        executable_sha256: expected.executable_sha256.into(),
        arguments: ["auth".into(), "login".into()],
        authority: expected.authority.into(),
        approved_ips_revision: expected.approved_ips_revision,
    };
    let mut signed = DOMAIN.to_vec();
    signed.extend(serde_json::to_vec(&handoff).unwrap());
    let signature = key.sign(&signed);
    let verify = |bytes: &[u8], signature: &[u8], scope, now| {
        verify_handoff(trusted, bytes, signature, scope, 130, now)
            .map_err(|error| error.to_string())
    };
    assert_eq!(
        verify(&signed, signature.as_ref(), expected, 119).unwrap(),
        42
    );
    assert_eq!(
        verify(&signed, signature.as_ref(), expected, 120).unwrap_err(),
        "handoff expired"
    );
    assert_eq!(
        verify_handoff(trusted, &signed, signature.as_ref(), expected, 110, 109).unwrap(),
        42
    );
    assert_eq!(
        verify_handoff(trusted, &signed, signature.as_ref(), expected, 110, 110)
            .unwrap_err()
            .to_string(),
        "handoff expired"
    );
    assert_eq!(
        verify(&signed, other.sign(&signed).as_ref(), expected, 119).unwrap_err(),
        "invalid handoff signature"
    );
    for (field, malformed) in [
        ("permit_id", "2a".to_owned()),
        ("permit_id", format!("{:032X}", 42)),
        ("approval_pair_sha256", "a".repeat(63)),
        ("approval_pair_sha256", "A".repeat(64)),
        ("approval_pair_sha256", "g".repeat(64)),
    ] {
        let mut body = serde_json::to_value(&handoff).unwrap();
        body[field] = malformed.into();
        let mut malformed = DOMAIN.to_vec();
        malformed.extend(serde_json::to_vec(&body).unwrap());
        assert_eq!(
            verify(&malformed, key.sign(&malformed).as_ref(), expected, 119).unwrap_err(),
            "invalid handoff identifiers"
        );
    }
    let mut altered = signed.clone();
    altered[DOMAIN.len()] ^= 1;
    assert_eq!(
        verify(&altered, signature.as_ref(), expected, 119).unwrap_err(),
        "invalid handoff signature"
    );
    for scope in [
        Scope {
            target_id: "other-fixture",
            ..expected
        },
        Scope {
            executable_sha256: "other-digest",
            ..expected
        },
        Scope {
            arguments: &["auth", "status"],
            ..expected
        },
        Scope {
            authority: "other.example.invalid:443",
            ..expected
        },
        Scope {
            approved_ips_revision: 8,
            ..expected
        },
    ] {
        assert_eq!(
            verify(&signed, signature.as_ref(), scope, 119).unwrap_err(),
            "handoff scope mismatch"
        );
    }
}
