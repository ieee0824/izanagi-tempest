"""Host-side receipt verifier for the offline permit fixture."""

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


@dataclass(frozen=True)
class Scope:
    target_id: str
    permit_id: str
    generation: int


@dataclass(frozen=True)
class Commit:
    ledger_id: str
    sequence: int
    scope: Scope
    state: str

    def digest(self):
        return sha256(_encode(asdict(self))).digest()


@dataclass(frozen=True)
class Checkpoint:
    """Independent host record, supplied locally by the fixture harness."""

    sequence: int
    digest: bytes


def _encode(fields):
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")


def receipt_bytes(challenge, commit):
    return b"izanagi-tempest:host-permit-receipt:fixture-v1\0" + _encode({
        "challenge": challenge.hex(), "commit": asdict(commit),
    })


class ReceiptVerifier:
    def __init__(self, pinned_key: Ed25519PublicKey, scope: Scope):
        self._key = pinned_key
        self._scope = scope
        self._challenge = secrets.token_bytes(32)

    @property
    def challenge(self):
        return self._challenge

    def verify(self, response_challenge, commit, signature, checkpoint):
        challenge = self._challenge
        self._challenge = None
        if challenge is None or response_challenge != challenge or checkpoint is None:
            return False
        if (commit.scope != self._scope or commit.state != "consumed"
                or commit.sequence <= 0 or commit.sequence != checkpoint.sequence
                or commit.digest() != checkpoint.digest):
            return False
        try:
            self._key.verify(signature, receipt_bytes(challenge, commit))
        except InvalidSignature:
            return False
        return True
