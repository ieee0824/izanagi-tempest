"""Exercise the administrator handoff decision with synthetic verifier results."""

import json
import os
import unittest
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from threading import Lock


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
    checked_at: int | None = 100
    revision: int | None = 1
    approver_key_id: str = "fixture-approver"
    authorized: bool = True
    revoked: bool | None = False
    target_id: str = "fixture-target"


def handoff_candidate(
    pair: VerifiedPair,
    registry: RegistrySnapshot,
    now: int,
    approved_choice: str = "fixture-approve",
    *,
    current_revision: int | None,
) -> dict[str, str]:
    if not (pair.request_verified and pair.decision_verified and pair.target_verified):
        raise ValueError("unverified approval pair")
    if not approved_choice or pair.choice_id != approved_choice:
        raise ValueError("approval choice mismatch")
    if (
        pair.request_id != pair.decision_reply_to
        or not pair.request_digest
        or pair.request_digest != pair.decision_request_digest
    ):
        raise ValueError("approval request mismatch")
    if pair.target_id != registry.target_id or not registry.target_id:
        raise ValueError("unregistered target")
    if (
        not pair.approver_key_id
        or pair.approver_key_id != registry.approver_key_id
        or not registry.authorized
    ):
        raise ValueError("unauthorized approver")
    if registry.revoked is not False or registry.checked_at is None:
        raise ValueError("revocation state unavailable or revoked")
    if registry.revision is None or current_revision is None:
        raise ValueError("registry revision unavailable")
    if registry.revision != current_revision:
        raise ValueError("registry changed since lookup")
    if not 0 <= now - registry.checked_at < 5:
        raise ValueError("registry lookup outside freshness window")
    return {"target_id": registry.target_id, "request_digest": pair.request_digest}


class AdminHandoffTest(unittest.TestCase):
    def test_all_checks_required_before_generating_a_candidate(self):
        pair = VerifiedPair()
        registry = RegistrySnapshot()
        self.assertEqual(
            handoff_candidate(pair, registry, 100, current_revision=1),
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
                handoff_candidate(replace(pair, **{field: value}), registry, 100, current_revision=1)

        for field, value, error in [
            ("target_id", "", "unregistered target"),
            ("target_id", "another-target", "unregistered target"),
            ("approver_key_id", "another-key", "unauthorized approver"),
            ("authorized", False, "unauthorized approver"),
            ("checked_at", None, "revocation state unavailable"),
            ("revoked", None, "revocation state unavailable"),
            ("revoked", True, "revocation state unavailable"),
        ]:
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, error):
                handoff_candidate(pair, replace(registry, **{field: value}), 100, current_revision=1)


    def test_requires_fresh_lookup_at_current_revision(self):
        pair = VerifiedPair()
        snapshot = RegistrySnapshot()
        expected = {"target_id": snapshot.target_id, "request_digest": pair.request_digest}
        self.assertEqual(handoff_candidate(pair, snapshot, 104, current_revision=1), expected)

        published = []
        for lookup, now, revision, error in [
            (snapshot, 105, 1, "outside freshness window"),
            (snapshot, 99, 1, "outside freshness window"),
            (snapshot, 104, 2, "changed since lookup"),
            (snapshot, 104, None, "revision unavailable"),
            (replace(snapshot, revision=None), 104, 1, "revision unavailable"),
            (replace(snapshot, checked_at=None), 104, 1, "state unavailable"),
        ]:
            with self.subTest(now=now, revision=revision, lookup=lookup):
                with self.assertRaisesRegex(ValueError, error):
                    published.append(
                        handoff_candidate(pair, lookup, now, current_revision=revision)
                    )
                self.assertEqual(published, [])

        refreshed = replace(snapshot, revision=2, checked_at=104)
        published.append(handoff_candidate(pair, refreshed, 104, current_revision=2))
        self.assertEqual(published, [expected])


class IssuanceFixture:
    """Serialize management updates with the final publication check."""

    def __init__(self):
        self.lock = Lock()
        self.revision = 1
        self.artifact = None

    def update(self):
        with self.lock:
            self.revision += 1

    def issue(self, pair, snapshot, clock, sign):
        with self.lock:
            candidate = handoff_candidate(
                pair, snapshot, clock(), current_revision=self.revision
            )
        signed = sign(candidate)
        with self.lock:
            handoff_candidate(pair, snapshot, clock(), current_revision=self.revision)
            self.artifact = signed

    def retrieve(self):
        with self.lock:
            return self.artifact


class IssuanceRaceTest(unittest.TestCase):
    def test_update_before_signing_prevents_signing(self):
        issuer = IssuanceFixture()
        issuer.update()
        with self.assertRaisesRegex(ValueError, "changed since lookup"):
            issuer.issue(VerifiedPair(), RegistrySnapshot(), lambda: 100, self.fail)
        self.assertIsNone(issuer.retrieve())

    def test_update_after_signing_prevents_publication(self):
        issuer = IssuanceFixture()
        signing_completed = []

        def sign(candidate):
            artifact = sha256(json.dumps(candidate, sort_keys=True).encode()).digest()
            signing_completed.append(True)
            issuer.update()
            return artifact

        with self.assertRaisesRegex(ValueError, "changed since lookup"):
            issuer.issue(VerifiedPair(), RegistrySnapshot(), lambda: 100, sign)
        self.assertEqual(signing_completed, [True])
        self.assertIsNone(issuer.retrieve())

        snapshot = RegistrySnapshot(revision=2, checked_at=101)
        issuer.issue(VerifiedPair(), snapshot, lambda: 101, lambda _: b"new fixture")
        self.assertEqual(issuer.retrieve(), b"new fixture")


def pair_from_client_detail(detail: dict, target_id: str) -> VerifiedPair:
    request, decision = detail["request"], detail["decision"]
    request_auth, decision_auth = request["auth"], decision["auth"]
    payload = decision["payload"]
    return VerifiedPair(
        request_verified=request_auth.get("approval_verified") is True
        and (request_auth.get("verified") is True
             or request_auth.get("server_authenticated") is True),
        decision_verified=decision_auth.get("approval_verified") is True
        and decision_auth.get("verified") is True
        and decision_auth.get("approval_authorized") is True,
        target_verified=decision_auth.get("approval_target_verified") is True,
        request_id=request["id"],
        decision_reply_to=payload["reply_to"],
        request_digest=request_auth["action_digest"],
        decision_request_digest=payload["request_digest"],
        choice_id=payload["choice_id"],
        approver_key_id=decision_auth["key_id"],
        target_id=target_id,
    )


class FixedClientHandoffTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("TEMPEST_CLIENT_APPROVAL_FIXTURE"), "requires local client fixture")
    def test_loopback_client_detail_feeds_the_handoff_check(self):
        fixture_path = Path(os.environ["TEMPEST_CLIENT_APPROVAL_FIXTURE"])
        fixture = json.loads(fixture_path.read_text())
        registry = RegistrySnapshot(approver_key_id=fixture["registered_key_id"])
        # First option in the client's pinned test vector, independent of the response.
        choice = "85f4ded4-025d-4b71-b44b-298bbca40ad1"
        pair = pair_from_client_detail(fixture["detail"], registry.target_id)
        result = handoff_candidate(pair, registry, 100, choice, current_revision=1)
        self.assertEqual(result["request_digest"], pair.decision_request_digest)
        for invalid in (
            replace(registry, authorized=False),
            replace(registry, checked_at=95),
            replace(registry, revoked=None),
            replace(registry, revoked=True),
        ):
            with self.assertRaises(ValueError):
                handoff_candidate(pair, invalid, 100, choice, current_revision=1)
