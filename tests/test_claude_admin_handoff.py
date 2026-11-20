"""Exercise the administrator handoff decision with synthetic verifier results."""

import unittest
from dataclasses import dataclass, replace
from hashlib import sha256


@dataclass(frozen=True)
class VerifiedPair:
    request_verified: bool = True
    decision_verified: bool = True
    target_verified: bool = True
    request_id: int = 20
    decision_reply_to: int = 20
    request_digest: str = sha256(b"fixture request").hexdigest()
    decision_request_digest: str = request_digest
    choice_id: str = "fixture-approve"
    approver_key_id: str = "fixture-approver"
    target_id: str = "fixture-target"


@dataclass(frozen=True)
class RegistrySnapshot:
    checked_at: int = 100
    approver_key_id: str = "fixture-approver"
    authorized: bool = True
    revoked: bool | None = False
    target_id: str = "fixture-target"


def handoff_candidate(
    pair: VerifiedPair, registry: RegistrySnapshot, now: int
) -> dict[str, str]:
    if not (pair.request_verified and pair.decision_verified and pair.target_verified):
        raise ValueError("unverified approval pair")
    if pair.choice_id != "fixture-approve":
        raise ValueError("approval choice mismatch")
    if (
        pair.request_id != pair.decision_reply_to
        or not pair.request_digest
        or pair.request_digest != pair.decision_request_digest
    ):
        raise ValueError("approval request mismatch")
    if pair.target_id != registry.target_id or not registry.target_id:
        raise ValueError("unregistered target")
    if pair.approver_key_id != registry.approver_key_id or not registry.authorized:
        raise ValueError("unauthorized approver")
    if registry.checked_at != now or registry.revoked is not False:
        raise ValueError("revocation state unavailable or revoked")
    return {"target_id": registry.target_id, "request_digest": pair.request_digest}


class AdminHandoffTest(unittest.TestCase):
    def test_all_checks_required_before_generating_a_candidate(self):
        pair = VerifiedPair()
        registry = RegistrySnapshot()
        self.assertEqual(
            handoff_candidate(pair, registry, 100),
            {"target_id": registry.target_id, "request_digest": pair.request_digest},
        )

        for field, value, error in [
            ("request_verified", False, "unverified approval pair"),
            ("decision_verified", False, "unverified approval pair"),
            ("target_verified", False, "unverified approval pair"),
            ("choice_id", "", "approval choice mismatch"),
            ("choice_id", "fixture-decline", "approval choice mismatch"),
            ("decision_reply_to", 21, "approval request mismatch"),
            ("decision_request_digest", "", "approval request mismatch"),
            ("decision_request_digest", "0" * 64, "approval request mismatch"),
        ]:
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, error):
                handoff_candidate(replace(pair, **{field: value}), registry, 100)

        for field, value, error in [
            ("target_id", "", "unregistered target"),
            ("target_id", "another-target", "unregistered target"),
            ("approver_key_id", "another-key", "unauthorized approver"),
            ("authorized", False, "unauthorized approver"),
            ("checked_at", 99, "revocation state unavailable"),
            ("revoked", None, "revocation state unavailable"),
            ("revoked", True, "revocation state unavailable"),
        ]:
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, error):
                handoff_candidate(pair, replace(registry, **{field: value}), 100)
