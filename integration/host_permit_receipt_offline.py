"""Test the host-side receipt verifier with a deterministic fixture key only."""

from dataclasses import replace
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host_permit_receipt import Checkpoint, Commit, ReceiptVerifier, Scope, receipt_bytes


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.scope = Scope("target-fixture", "permit-fixture", 3)
        self.commit = Commit("ledger-fixture", 7, self.scope, "consumed")
        self.checkpoint = Checkpoint(self.commit.sequence, self.commit.digest())
        self.verifier = ReceiptVerifier(self.signer.public_key(), self.scope)

    def verify_signed(self, commit, checkpoint):
        challenge = self.verifier.challenge
        signature = self.signer.sign(receipt_bytes(challenge, commit))
        return self.verifier.verify(challenge, commit, signature, checkpoint)

    def test_matching_receipt_is_diagnostic_only_and_one_shot(self):
        challenge = self.verifier.challenge
        signature = self.signer.sign(receipt_bytes(challenge, self.commit))
        self.assertTrue(self.verifier.verify(challenge, self.commit, signature, self.checkpoint))
        self.assertFalse(self.verifier.verify(challenge, self.commit, signature, self.checkpoint))

    def test_previous_challenge_cannot_be_replayed_in_new_session(self):
        challenge = self.verifier.challenge
        signature = self.signer.sign(receipt_bytes(challenge, self.commit))
        fresh = ReceiptVerifier(self.signer.public_key(), self.scope)
        self.assertFalse(fresh.verify(challenge, self.commit, signature, self.checkpoint))
        fresh = ReceiptVerifier(self.signer.public_key(), self.scope)
        self.assertFalse(fresh.verify(fresh.challenge, self.commit, signature, self.checkpoint))

    def test_wrong_scope_even_with_matching_checkpoint(self):
        for scope in (replace(self.scope, target_id="other"),
                      replace(self.scope, permit_id="other"),
                      replace(self.scope, generation=4)):
            with self.subTest(scope=scope):
                self.verifier = ReceiptVerifier(self.signer.public_key(), self.scope)
                commit = replace(self.commit, scope=scope)
                self.assertFalse(self.verify_signed(commit, Checkpoint(commit.sequence, commit.digest())))

    def test_refuses_missing_checkpoint(self):
        self.assertFalse(self.verify_signed(self.commit, None))

    def test_refuses_sequence_or_digest_mismatch(self):
        for checkpoint in (replace(self.checkpoint, sequence=8),
                           replace(self.checkpoint, digest=bytes(32))):
            with self.subTest(checkpoint=checkpoint):
                self.verifier = ReceiptVerifier(self.signer.public_key(), self.scope)
                self.assertFalse(self.verify_signed(self.commit, checkpoint))

    def test_refuses_uncommitted_state_even_when_signed(self):
        commit = replace(self.commit, state="pending")
        self.assertFalse(self.verify_signed(commit, Checkpoint(commit.sequence, commit.digest())))

    def test_refuses_signature_from_unpinned_key(self):
        foreign = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        challenge = self.verifier.challenge
        signature = foreign.sign(receipt_bytes(challenge, self.commit))
        self.assertFalse(self.verifier.verify(challenge, self.commit, signature, self.checkpoint))


if __name__ == "__main__":
    unittest.main()
