"""Exercise the integrated synthetic local-auth PTY and the pre-grant failures."""

from concurrent.futures import ThreadPoolExecutor
import errno
import json
import time
import os
from pathlib import Path
import pty
import select
import shutil
import socket
import ssl
import subprocess
import tempfile
import sys

from claude_supervised_pty_smoke import WORK, fixture, live_descendant, read_until
from claude_writable_pty_smoke import CONFIG, REMOVED

POSITIVE = (
    b"local auth: tunnel accepted, other host refused, three direct ports denied; "
    b"listeners and policy closed\n"
)
NEGATIVE = b"local auth: accepts=0,0,0,0 denied=0; listeners and policy closed\n"
FAILURES = {
    "missing-namespace": b"fixed login namespace missing or mismatched",
    "wrong-namespace": b"fixed login namespace missing or mismatched",
    "missing-policy": b"fixed login policy or loopback inspection failed",
    "wrong-policy": b"fixed login policy or loopback inspection failed",
    "missing-gateway": b"fixed gateway unavailable",
    "empty-resolution": b"fixed gateway upstream unavailable or unapproved",
    "unapproved-resolution": b"fixed gateway upstream unavailable or unapproved",
    "expired-permit": b"synthetic permit expired",
    "wrong-permit-scope": b"synthetic permit scope mismatch",
    "wrong-permit-arguments": b"synthetic permit scope mismatch",
    "wrong-permit-authority": b"synthetic permit scope mismatch",
}


def assert_empty():
    if any(WORK.iterdir()) or any(CONFIG.iterdir()):
        raise RuntimeError("trial or configuration generation remains")


def check_pre_grant_denial(binary, case, reason):
    master, slave = pty.openpty()
    try:
        with subprocess.Popen(
            [binary, case], stdin=slave, stdout=slave, stderr=subprocess.PIPE, env={}
        ) as process:
            os.close(slave)
            slave = -1
            _, result = process.communicate(timeout=8)
            if (
                process.returncode != 1
                or NEGATIVE not in result
                or b"work removed" not in result
                or reason not in result
            ):
                raise RuntimeError(f"{case}: pre-grant refusal or recovery failed: {result!r}")
        # The master queue is empty once the slave side has exited.
        try:
            output = os.read(master, 1024)
        except OSError as error:
            if error.errno != errno.EIO:  # Linux PTY hangup.
                raise
        else:
            if output:
                raise RuntimeError(f"{case}: fixed child emitted output before grant")
    finally:
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)
    assert_empty()


def check_terminal_refusals(binary):
    master, slave = pty.openpty()
    other_master, other_slave = pty.openpty()
    try:
        for input_fd, output_fd in (
            (subprocess.DEVNULL, slave),
            (slave, subprocess.PIPE),
            (slave, other_slave),
            (master, master),
        ):
            result = subprocess.run(
                [binary, "match"], stdin=input_fd, stdout=output_fd,
                stderr=subprocess.PIPE, env={}, timeout=5,
            )
            if result.returncode != 1 or result.stdout or result.stderr:
                raise RuntimeError("invalid login terminal was not refused before staging")
            assert_empty()
    finally:
        for fd in (master, slave, other_master, other_slave):
            os.close(fd)


def check_concurrent_refusal(binary):
    original = (set(WORK.iterdir()), set(CONFIG.iterdir()))
    master, slave = pty.openpty()
    try:
        result = subprocess.run(
            [binary, "match"], stdin=slave, stdout=slave,
            stderr=subprocess.PIPE, env={}, timeout=2,
        )
        if result.returncode != 1 or b"dedicated PTY work area already in use" not in result.stderr:
            raise RuntimeError(f"concurrent login was not refused by the lock: {result.stderr!r}")
        os.close(slave)
        slave = -1
        try:
            output = os.read(master, 1024)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
        else:
            if output:
                raise RuntimeError("concurrent login emitted PTY output")
        if (set(WORK.iterdir()), set(CONFIG.iterdir())) != original:
            raise RuntimeError("concurrent login changed an active generation")
    finally:
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)


def check_permit_replay(binary):
    marker = CONFIG / f"{1:032x}"
    policy = CONFIG / ".synthetic-login-policy.json"
    assert_empty()

    def write_settings(expires, **overrides):
        with os.fdopen(os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as out:
            json.dump({
                "policy": {"version": 1, "authority": "platform.claude.com:443"},
                "expires_unix_seconds": expires,
                "executable_sha256": "dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14",
                "arguments": ["auth", "login"],
                "target_id": "synthetic-target",
                "approved_ips_revision": 1,
                **overrides,
            }, out)

    def check_refusal(reason, expected):
        master, slave = pty.openpty()
        try:
            result = subprocess.run(
                [binary, "single-use-permit"], stdin=slave, stdout=slave,
                stderr=subprocess.PIPE, env={}, timeout=2,
            )
            if result.returncode != 1 or reason not in result.stderr:
                raise RuntimeError(f"synthetic permit refusal failed: {result.stderr!r}")
            if any(WORK.iterdir()) or set(CONFIG.iterdir()) != expected:
                raise RuntimeError("rejected permit staged a new generation")
        finally:
            os.close(slave)
            os.close(master)

    try:
        check_refusal(b"No such file or directory", set())
        write_settings(int(time.time()) - 1)
        check_refusal(b"synthetic permit expired", {policy})
        for mismatch in (
            {"executable_sha256": "0" * 64},
            {"arguments": ["auth", "status"]},
            {"target_id": "other-target"},
            {"approved_ips_revision": 2},
        ):
            write_settings(int(time.time()) + 45, **mismatch)
            check_refusal(b"manual login permit scope mismatch", {policy})
        write_settings(int(time.time()) + 45)
        fixture(
            [binary, "single-use-permit"], {},
            complete_probe=True, success=POSITIVE + REMOVED,
        )
        if set(CONFIG.iterdir()) != {marker, policy} or not marker.is_file() or marker.stat().st_size:
            raise RuntimeError("unexpected settings or permit artifacts after cleanup")
        check_refusal(b"manual login permit already consumed or revoked", {marker, policy})
    finally:
        marker.unlink(missing_ok=True)
        policy.unlink(missing_ok=True)
    assert_empty()


def verify_signed_child_environment(supervisor):
    pending = [supervisor]
    while pending:
        pid = pending.pop()
        proc = Path(f"/proc/{pid}")
        try:
            pending.extend(map(int, (proc / f"task/{pid}/children").read_text().split()))
            args = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
            if args[:4] != [b"/bin/busybox", b"sh", b"-eu", b"-c"]:
                continue
            if len(args) != 11 or args[5:7] != [b"fixed-pty", b"writable"]:
                continue
            (work,) = WORK.iterdir()
            if args[7:] != [
                os.fsencode(CONFIG / work.name), b"local-auth", b"auth", b"login",
            ]:
                raise RuntimeError("signed child did not receive the exact fixed arguments")
            expected = {
                b"HOME=/home/fixture", b"CLAUDE_CONFIG_DIR=/home/fixture/config",
                b"HTTPS_PROXY=http://127.0.0.1:39271", b"HTTP_PROXY=http://127.0.0.1:39271",
                b"NO_PROXY=",
            }
            actual = (proc / "environ").read_bytes().rstrip(b"\0").split(b"\0")
            if len(actual) != len(expected) or set(actual) != expected:
                raise RuntimeError("signed child environment was not the fixed set")
            return pid
        except (FileNotFoundError, ProcessLookupError):
            continue
    raise RuntimeError("could not find the fixed signed PTY child")


def connect_response(proxy):
    proxy.sendall(b"CONNECT platform.claude.com:443 HTTP/1.1\r\n"
                  b"Host: platform.claude.com:443\r\n\r\n")
    response = bytearray()
    while not response.endswith(b"\r\n\r\n") and len(response) < 256:
        chunk = proxy.recv(1)
        if not chunk:
            break
        response.extend(chunk)
    return response


def probe_local_tls(cert_pem, expire=False):
    context = ssl.create_default_context(cadata=cert_pem)
    names = (("platform.claude.com", True),)
    if not expire:
        names += (("mismatch.invalid", False),)
    for name, expected in names:
        with socket.create_connection(("127.0.0.1", 39271), timeout=6 if expire else 3) as proxy:
            if connect_response(proxy) != b"HTTP/1.1 200 Connection Established\r\n\r\n":
                raise RuntimeError("fixed TLS CONNECT did not open")
            try:
                with context.wrap_socket(proxy, server_hostname=name) as tls:
                    if not expected or tls.getpeercert(binary_form=True) != ssl.PEM_cert_to_DER_cert(cert_pem):
                        raise RuntimeError("unexpected TLS certificate or accepted wrong name")
                    tls.sendall(b"PING")
                    if tls.recv(1) != b"K":
                        raise RuntimeError("missing TLS fixture response")
                    if expire:
                        if tls.recv(1) != b"":
                            raise RuntimeError("TLS tunnel survived signed freshness expiry")
                    else:
                        tls.unwrap().close()
            except ssl.SSLCertVerificationError as error:
                if expected or error.verify_code != 62:
                    raise

    if expire:
        with socket.create_connection(("127.0.0.1", 39271), timeout=3) as proxy:
            if connect_response(proxy) != b"HTTP/1.1 403 Forbidden\r\n\r\n":
                raise RuntimeError("new CONNECT was not rejected after expiry")


def check_signed_tls(binary, temporary, record, check_evidence, expire=False):
    if any(subprocess.check_output(["ip", family, "route", "show"]).strip()
           for family in ("-4", "-6")):
        raise RuntimeError("signed TLS requires an outer namespace without routes")
    cert = Path(temporary) / "tls-cert.pem"
    private_key = Path(temporary) / "tls-key.pem"
    subprocess.run([
        "/usr/bin/openssl", "req", "-x509", "-newkey", "ed25519", "-nodes", "-days", "1",
        "-subj", "/CN=platform.claude.com", "-addext", "subjectAltName=DNS:platform.claude.com",
        "-keyout", private_key, "-out", cert,
    ], check=True, capture_output=True)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert, private_key)
    cert_pem = cert.read_text()
    identities = {}

    def exchanges(listener):
        for expected in ((True,) if expire else (True, False)):
            client, _ = listener.accept()
            with client:
                client.settimeout(6 if expire else 4)
                try:
                    with server_context.wrap_socket(client, server_side=True) as tls:
                        with tls.makefile("rb") as incoming:
                            if not expected or incoming.read(4) != b"PING":
                                raise RuntimeError("unexpected exchange with the TLS fixture")
                        tls.sendall(b"K")
                        if expire:
                            if tls.recv(1) != b"":
                                raise RuntimeError("TLS upstream survived signed freshness expiry")
                        else:
                            tls.unwrap().close()
                except ssl.SSLError as error:
                    if expected or error.reason != "SSLV3_ALERT_BAD_CERTIFICATE":
                        raise

    def observe_and_probe(pid):
        child = verify_signed_child_environment(pid)
        (work,) = WORK.iterdir()
        for directory in (work, CONFIG / work.name):
            metadata = directory.stat()
            identities[directory] = (metadata.st_dev, metadata.st_ino)
        subprocess.run([
            "/usr/bin/nsenter", "--net=" + str(Path(f"/proc/{child}/ns/net")), "--",
            "/usr/bin/setpriv", "--reuid", "999", "--regid", "988", "--clear-groups",
            sys.executable, str(Path(__file__).resolve()),
            "--probe-expiring-tls" if expire else "--probe-local-tls",
        ], input=cert_pem, text=True, timeout=8 if expire else 5, check=True, env={})

    with socket.create_server(("127.0.0.1", 39275)) as listener, ThreadPoolExecutor(1) as pool:
        listener.settimeout(8)
        served = pool.submit(exchanges, listener)
        fixture(
            [binary, "signed-tls-expiry" if expire else "signed-tls"],
            {}, complete_probe=True, success=POSITIVE + REMOVED,
            observe_child=None if expire else observe_and_probe,
            after_probe=observe_and_probe if expire else None,
            check_evidence=lambda stderr: check_evidence(stderr, record, identities, True),
        )
        served.result()
        listener.setblocking(False)
        try:
            unexpected, _ = listener.accept()
        except BlockingIOError:
            pass
        else:
            unexpected.close()
            raise RuntimeError("unexpected TLS upstream connection")
    if any(directory.exists() for directory in identities):
        raise RuntimeError("TLS fixture generation was not recovered")
    if expire:
        print("signed TLS freshness: both TLS peers closed; next CONNECT denied without upstream; "
              "same permit and generations recovered")
        return
    print("signed TLS: same permit and generation, exact certificate, wrong name refused, "
          "direct ports denied, child and gateway reaped, both generations recovered")


def check_signed_permits(binary, tls=False):
    policy = CONFIG / ".synthetic-login-policy.json"
    payload = CONFIG / ".synthetic-handoff"
    signature = CONFIG / ".synthetic-handoff-signature"
    trust = CONFIG / ".synthetic-handoff-key"
    inputs = {policy, payload, signature, trust}
    used, expired, stopped, later = [CONFIG / f"{value:032x}" for value in (2, 3, 4, 5)]
    mismatches = {f"wrong-grant-{field}": CONFIG / f"{index:032x}"
                  for index, field in enumerate(("id", "ledger", "stage"), 6)}
    closure_cases = (
        ("missing-closure", CONFIG / f"{9:032x}",
         b"synthetic gateway closure unconfirmed: failed to fill whole buffer"),
        ("wrong-closure-generation", CONFIG / f"{10:032x}",
         b"synthetic gateway closure generation mismatch"),
    )
    missing_sync = CONFIG / f"{11:032x}"
    failed_sync = CONFIG / f"{12:032x}"
    tls_record = CONFIG / f"{13:032x}"
    tls_expiry_record = CONFIG / f"{14:032x}"
    closure_records = {record for _, record, _ in closure_cases} | {missing_sync, failed_sync}
    stop_request = CONFIG / ".synthetic-stop-request.json"
    pending_stop = CONFIG / ".synthetic-stop-request.pending"

    scope = {
        "executable_sha256": "dbac288c29ba568459550a2da9e7ae0ded6b1fc728ee9fad3044c44e62d6ac14",
        "arguments": ["auth", "login"],
        "target_id": "synthetic-target",
        "approved_ips_revision": 1,
    }

    def write_private(path, data):
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as out:
            out.write(data)

    def write_handoff(key, record, seconds):
        authority = "platform.claude.com:443"
        now = int(time.time())
        write_private(policy, json.dumps({
            **scope, "policy": {"version": 1, "authority": authority},
            "expires_unix_seconds": now + 45,
        }).encode())
        write_private(payload, b"izanagi-tempest:manual-login-handoff:fixture-v1\0" + json.dumps({
            **scope, "authority": authority, "permit_id": record.name,
            "approval_pair_sha256": "a" * 64, "expires_unix_seconds": now + seconds,
        }).encode())
        write_private(signature, subprocess.check_output([
            "/usr/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", key, "-in", payload,
        ]))

    def assert_denied(case, reason, expected, unused_gateway=False):
        master, slave = pty.openpty()
        try:
            result = subprocess.run([binary, case], stdin=slave, stdout=slave,
                                    stderr=subprocess.PIPE, env={}, timeout=10)
            if (result.returncode != 1 or reason not in result.stderr
                    or (unused_gateway and NEGATIVE not in result.stderr)):
                raise RuntimeError(f"signed permit refusal failed: {result.stderr!r}")
            if any(WORK.iterdir()) or set(CONFIG.iterdir()) != expected:
                raise RuntimeError("unexpected artifacts after signed permit refusal")
        finally:
            os.close(master)
            os.close(slave)

    def check_administrator_stop(record):
        master, slave = pty.openpty()
        descendant = -1
        process = None
        try:
            process = subprocess.Popen(
                [binary, "signed-administrator-stop"], stdin=slave, stdout=slave,
                stderr=subprocess.PIPE, env={},
            )
            os.close(slave)
            slave = -1
            read_until(master, b"fixture-ready", timeout=3)
            prefix, permit_id, device, inode = process.stderr.readline().decode().strip().rsplit(" ", 3)
            if prefix != "synthetic stop target:" or permit_id != record.name:
                raise RuntimeError("supervisor announced an unexpected stop target")
            target = dict(permit_id=permit_id, device=int(device), inode=int(inode))

            def request(fields):
                write_private(pending_stop, json.dumps(fields).encode())
                pending_stop.replace(stop_request)

            for wrong in (dict(target, permit_id=used.name), dict(target, inode=target["inode"] + 1)):
                request(wrong)
                time.sleep(0.1)
                if process.poll() is not None:
                    raise RuntimeError("wrong stop target ended the active run")
            os.write(master, b"probe\n")
            read_until(master, b"fixture-response")
            descendant = live_descendant(process.pid)
            request(target)
            _, result = process.communicate(timeout=6)
            watcher = select.poll()
            watcher.register(descendant, select.POLLIN)
            expected = b"synthetic administrator stop: PID namespace reaped\n" + POSITIVE + REMOVED
            if process.returncode != 0 or result != expected or not watcher.poll(0):
                raise RuntimeError(f"administrator stop and recovery failed: {result!r}")
            if any(WORK.iterdir()):
                raise RuntimeError("work generation remains after administrator stop")
        finally:
            for fd in (master, slave, descendant):
                if fd >= 0:
                    os.close(fd)
            if process is not None:
                process.communicate(timeout=20)
    def check_recovery_evidence(stderr, record, identities, synced):
        prefix = b"synthetic recovery evidence: "
        lines = stderr.splitlines(keepends=True)
        evidence_lines = [line for line in lines if line.startswith(prefix)]
        if len(evidence_lines) != 1:
            raise RuntimeError(f"expected one recovery evidence record: {stderr!r}")
        (evidence,) = evidence_lines
        work, config = identities.values()
        expected = {
            "permit_id": record.name,
            "work_identity": list(work),
            "config_identity": list(config),
            "gateway_closure_confirmed": True,
            "ledger_present": True,
            "ledger_synced": synced,
        }
        if json.loads(evidence[len(prefix):]) != expected:
            raise RuntimeError("recovery evidence does not match the active permit and generation")
        return b"".join(line for line in lines if line != evidence)

    def check_closure_quarantine(case, reason, record=None):
        identities = {}

        def observe():
            (work,) = WORK.iterdir()
            for directory in (work, CONFIG / work.name):
                metadata = directory.stat()
                identities[directory] = (metadata.st_dev, metadata.st_ino)

        def quarantine():
            (work,) = WORK.iterdir()
            for directory in (work, CONFIG / work.name):
                metadata = directory.stat()
                if (metadata.st_dev, metadata.st_ino) != identities.get(directory):
                    raise RuntimeError("closure refusal did not retain the same generation")
            if any((work / "root").iterdir()):
                raise RuntimeError("fixture root still has a mounted filesystem")

        try:
            fixture(
                [binary, case], {}, complete_probe=True, before_probe=observe, quarantine=quarantine,
                check_evidence=(lambda stderr: check_recovery_evidence(stderr, record, identities, None))
                if record is not None else None,
                success=POSITIVE + (
                    b"offline writable PTY fixture failed: offline supervisor failed after CLI grant; "
                    b"work retained; " + reason + b"; child and mount termination confirmed; "
                    b"signal=0; private configuration quarantined\n"
                ),
            )
        finally:
            # This test controls the entire disposable fixture and has no real data.
            for directory, identity in identities.items():
                metadata = directory.stat()
                if (metadata.st_dev, metadata.st_ino) == identity:
                    shutil.rmtree(directory)

    assert_empty()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            key = Path(tmp) / "fixture.pem"
            subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "ED25519", "-out", key], check=True)
            # Ed25519 SubjectPublicKeyInfo ends with the 32 raw public key bytes.
            write_private(trust, subprocess.check_output([
                "/usr/bin/openssl", "pkey", "-in", key, "-pubout", "-outform", "DER",
            ])[-32:])
            write_handoff(key, used, 45)
            write_private(payload, payload.read_bytes() + b" ")
            assert_denied("signed-permit", b"invalid handoff signature", inputs)
            write_handoff(key, used, 45)
            generation = None
            signed_identities = {}

            def observe_signed_generation():
                nonlocal generation
                (work,) = WORK.iterdir()
                generation = CONFIG / work.name
                for directory in (work, generation):
                    metadata = directory.stat()
                    signed_identities[directory] = (metadata.st_dev, metadata.st_ino)
                settings = (generation / "settings.json").stat()
                write_probe = (generation / "write-probe").stat()
                for entry in (settings, write_probe):
                    if (entry.st_uid, entry.st_gid, entry.st_mode & 0o777) != (999, 988, 0o600):
                        raise RuntimeError("signed fixture configuration was not owner-private")

            fixture(
                [binary, "signed-permit"],
                {
                    "HOME": "/dummy-parent-home", "CLAUDE_CONFIG_DIR": "/dummy-parent-config",
                    "HTTPS_PROXY": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:2",
                    "NO_PROXY": "*", "PATH": "/dummy-parent-path",
                    "TEMPEST_SYNTHETIC_PARENT_SENTINEL": "must-not-inherit",
                },
                complete_probe=True, success=POSITIVE + REMOVED,
                before_probe=observe_signed_generation, observe_child=verify_signed_child_environment,
                check_evidence=lambda stderr: check_recovery_evidence(stderr, used, signed_identities, True),
            )
            if generation is None or generation.exists():
                raise RuntimeError("signed fixture configuration did not disappear after disconnect")
            print(
                "signed PTY: exact child environment and arguments; owner-private settings and write probe; fixed local ACK; "
                "other host and three direct ports denied; descendant, tunnel and generations recovered"
            )
            assert_denied("signed-permit", b"already consumed or revoked", inputs | {used})
            recorded = inputs | {used}
            for case, record in mismatches.items():
                write_handoff(key, record, 45)
                recorded.add(record)
                assert_denied(case, b"work removed; synthetic grant identity mismatch",
                              recorded, unused_gateway=True)
                identity = record.stat()
                assert_denied("signed-permit", b"already consumed or revoked", recorded)
                if record.stat().st_ino != identity.st_ino:
                    raise RuntimeError("signed permit replay replaced the consumed record")
            for case, record, reason in closure_cases:
                write_handoff(key, record, 45)
                check_closure_quarantine(case, reason)
                recorded.add(record)
                assert_denied("signed-permit", b"already consumed or revoked", recorded)
                print(f"{case}: child reaped, mount detached, both generations quarantined")
            write_handoff(key, missing_sync, 45)
            check_closure_quarantine("missing-consumption-sync",
                                     b"synthetic consumption sync unconfirmed", missing_sync)
            recorded.add(missing_sync)
            assert_denied("signed-permit", b"already consumed or revoked", recorded)
            write_handoff(key, failed_sync, 45)
            recorded.add(failed_sync)
            assert_denied("failed-consumption-sync", b"synthetic consumption sync failed", recorded)
            assert_denied("signed-permit", b"already consumed or revoked", recorded)
            print("consumption sync: matched receipt recovered; missing receipt quarantined; failed fsync refused")
            write_handoff(key, expired, 4)
            assert_denied("permit-expires-before-grant", b"work removed; synthetic permit expired",
                          inputs | {used, expired} | set(mismatches.values()) | closure_records, unused_gateway=True)
            write_handoff(key, expired, 45)
            assert_denied("signed-permit", b"already consumed or revoked", inputs | {used, expired} | set(mismatches.values()) | closure_records)
            write_handoff(key, stopped, 45)
            check_administrator_stop(stopped)
            assert_denied("signed-administrator-stop", b"already consumed or revoked",
                          inputs | {used, expired, stopped, stop_request} | set(mismatches.values()) | closure_records)
            # Leave the previous stop in place while the successor reaches readiness.
            write_handoff(key, later, 45)
            check_administrator_stop(later)
            if tls:
                write_handoff(key, tls_record, 45)
                check_signed_tls(binary, tmp, tls_record, check_recovery_evidence)
                write_handoff(key, tls_expiry_record, 5)
                check_signed_tls(binary, tmp, tls_expiry_record, check_recovery_evidence, expire=True)
    finally:
        for path in inputs | {used, expired, stopped, later, stop_request, pending_stop, tls_record, tls_expiry_record} | set(mismatches.values()) | closure_records:
            path.unlink(missing_ok=True)
    assert_empty()


def main():
    if len(sys.argv) == 2 and sys.argv[1] in (
        "--probe-local-tls", "--probe-expiring-tls"
    ) and os.geteuid() == 999:
        probe_local_tls(sys.stdin.read(), expire=sys.argv[1] == "--probe-expiring-tls")
        return 0
    if sys.platform != "linux" or os.geteuid() != 0:
        return 2
    if len(sys.argv) < 2 or sys.argv[2:] not in ([], ["--signed-tls"]):
        return 2
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    assert_empty()
    check_terminal_refusals(binary)
    print("invalid terminals: redirected, split and master endpoints refused before staging")
    for case, reason in FAILURES.items():
        check_pre_grant_denial(binary, case, reason)
        print(f"{case}: no launch, no traffic, recovered")
    fixture(
        [binary, "match"],
        {"HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": "*"},
        complete_probe=True,
        success=POSITIVE + REMOVED,
        startup_timeout=20,
        before_probe=lambda: check_concurrent_refusal(binary),
    )
    assert_empty()
    check_permit_replay(binary)
    check_signed_permits(binary, tls=sys.argv[2:] == ["--signed-tls"])
    print("configured permit: missing, expired and replayed settings refused; late expiry recovered without traffic")
    print("concurrent launch: refused before staging")
    print("match: auth accepted, other host and three direct ports denied; disconnect reaped, active tunnel and listeners closed, generation removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
