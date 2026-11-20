"""Offline fixture for binding a signed manual login approval to a registered target."""

from dataclasses import asdict, dataclass, replace
import json
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


DOMAIN = b"izanagi-tempest:manual-login-approval:fixture-v1\0"
PURPOSE = "manual-login"


@dataclass(frozen=True)
class Scope:
    executable_sha256: str
    arguments: tuple[str, ...]
    target_id: str
    authority: str
    approved_ips_revision: int


@dataclass(frozen=True)
class Approval:
    permit_id: str
    expires_unix_seconds: int
    environment: str
    scope: Scope


@dataclass(frozen=True)
class Approver:
    public_key: Ed25519PublicKey
    allowed_purposes: frozenset[str]


def signed_bytes(approval):
    return DOMAIN + json.dumps(
        asdict(approval), sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def verify(approval, signature, signer_id, approvers, registered_scope, environment, now):
    signer = approvers.get(signer_id)
    if signer is None or PURPOSE not in signer.allowed_purposes:
        raise PermissionError("signer is not authorized for manual login")
    try:
        signer.public_key.verify(signature, signed_bytes(approval))
    except InvalidSignature as error:
        raise PermissionError("invalid manual login signature") from error
    if approval.environment != environment or approval.scope != registered_scope:
        raise PermissionError("approval does not match the registered target and settings")
    if approval.expires_unix_seconds <= now:
        raise PermissionError("approval expired")


class ManualLoginApprovalFixture(unittest.TestCase):
    def setUp(self):
        self.owner = Ed25519PrivateKey.generate()
        self.reader = Ed25519PrivateKey.generate()
        self.approvers = {
            "owner": Approver(self.owner.public_key(), frozenset({PURPOSE})),
            "reader": Approver(self.reader.public_key(), frozenset()),
        }
        self.scope = Scope(
            "a" * 64, ("auth", "login"), "registered-test-vm", "auth.example.invalid:443", 3
        )
        self.approval = Approval("dummy-permit", 145, "offline-fixture", self.scope)

    def check(self, approval, signature, signer="owner", scope=None, now=100):
        verify(
            approval, signature, signer, self.approvers,
            scope if scope is not None else self.scope, "offline-fixture", now,
        )

    def test_accepts_signed_approval_for_exact_registration(self):
        self.check(self.approval, self.owner.sign(signed_bytes(self.approval)))

    def test_rejects_tampering_and_signature_from_another_key(self):
        signature = self.owner.sign(signed_bytes(self.approval))
        with self.assertRaisesRegex(PermissionError, "invalid manual login signature"):
            self.check(replace(self.approval, expires_unix_seconds=146), signature)
        with self.assertRaisesRegex(PermissionError, "invalid manual login signature"):
            self.check(self.approval, self.reader.sign(signed_bytes(self.approval)))

    def test_rejects_valid_signature_from_signer_without_authority(self):
        signature = self.reader.sign(signed_bytes(self.approval))
        for signer in ("reader", "unregistered"):
            with self.subTest(signer=signer):
                with self.assertRaisesRegex(PermissionError, "signer is not authorized"):
                    self.check(self.approval, signature, signer=signer)

    def test_rejects_valid_signature_for_mismatched_target_or_settings(self):
        for scope in (
            replace(self.scope, target_id="different-test-vm"),
            replace(self.scope, executable_sha256="b" * 64),
            replace(self.scope, arguments=("auth", "status")),
            replace(self.scope, authority="other.example.invalid:443"),
            replace(self.scope, approved_ips_revision=4),
        ):
            with self.subTest(scope=scope):
                approval = replace(self.approval, scope=scope)
                with self.assertRaisesRegex(PermissionError, "registered target and settings"):
                    self.check(approval, self.owner.sign(signed_bytes(approval)))

    def test_rejects_other_environment_and_expiry(self):
        other = replace(self.approval, environment="other-environment")
        with self.assertRaisesRegex(PermissionError, "registered target and settings"):
            self.check(other, self.owner.sign(signed_bytes(other)))
        with self.assertRaisesRegex(PermissionError, "approval expired"):
            self.check(self.approval, self.owner.sign(signed_bytes(self.approval)), now=145)
