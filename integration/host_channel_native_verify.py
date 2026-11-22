"""Check Python-signed host receipts with the native Rust verifier."""

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools/host_ledger'))
from channel import canonical_json, RECEIPT_DOMAIN


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('verifier', type=Path)
    args = parser.parse_args()
    verifier = args.verifier.resolve()
    key = Ed25519PrivateKey.generate()
    scope = dict(target_id='vm', permit_id='a' * 32, generation=1)
    request = dict(scope, version=1, boot_id='boot1', operation='query', challenge='b' * 64)
    body = dict(request=request, commit=dict(scope=scope, ledger_id='ledger', state='consumed', sequence=2),
                issued_unix_ms=1000, expires_unix_ms=2000)
    response = dict(payload=body, signature=key.sign(RECEIPT_DOMAIN + canonical_json(body)).hex())
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        public = root / 'key'
        public.write_bytes(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        expected = root / 'request.json'
        expected.write_bytes(canonical_json(request))
        def run(value, now, success):
            result = subprocess.run([str(verifier), str(public), str(expected), str(now)],
                                    input=canonical_json(value), capture_output=True)
            if (result.returncode == 0) != success:
                raise RuntimeError(result.stderr.decode())
        run(response, 1500, True)
        run(response, 2000, False)
        run(dict(response, signature='0' * 128), 1500, False)
        expected.write_bytes(canonical_json(dict(request, challenge='c' * 64)))
        run(response, 1500, False)
    print('Native signature verified; expiry, tampering and wrong challenge refused')


if __name__ == '__main__':
    main()
