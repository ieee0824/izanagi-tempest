"""Offline filesystem model for publishing a complete login policy generation."""

import fcntl
import hashlib
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from threading import Event


class Publication:
    def __init__(self, root):
        self.root = root
        self.ledger = root / "ledger"
        self.lock = root / "lock"
        self.current = root / "current"
        self.pending = root / "pending"
        self.files = ("settings", "registration", "handoff", "signature")

    @contextmanager
    def exclusive(self):
        with self.lock.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    @staticmethod
    def sync(directory):
        fd = os.open(directory, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def write(path, content):
        with path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())

    def stage(self, revision):
        generation = self.root / str(revision)
        generation.mkdir()
        manifest = {}
        for name in self.files:
            payload = f"{revision}:{name}".encode()
            self.write(generation / name, payload)
            manifest[name] = hashlib.sha256(payload).hexdigest()
        self.write(generation / "manifest", json.dumps(manifest).encode())
        self.sync(generation)
        self.sync(self.root)

    def verify(self, revision):
        generation = self.root / str(revision)
        manifest = json.loads((generation / "manifest").read_bytes())
        if set(manifest) != set(self.files):
            raise ValueError("incomplete generation")
        payloads = {name: (generation / name).read_bytes() for name in self.files}
        if any(hashlib.sha256(body).hexdigest() != manifest[name]
               for name, body in payloads.items()):
            raise ValueError("mixed generation")
        return payloads

    def current_revision(self):
        return int(self.current.read_bytes()) if self.current.exists() else 0

    def publish(self, revision, sync_commit=None):
        with self.exclusive():
            if self.pending.exists():
                raise ValueError("publication unconfirmed")
            if revision <= self.current_revision():
                raise ValueError("stale generation")
            self.verify(revision)
            self.write(self.pending, str(revision).encode())
            self.sync(self.root)  # Persist the refusal marker before replacing current.
            replacement = self.root / "next"
            self.write(replacement, str(revision).encode())
            replacement.replace(self.current)
            (sync_commit or self.sync)(self.root)
            self.pending.unlink()
            self.sync(self.root)

    def recover(self, minimum_revision):
        with self.exclusive():
            revision = self.current_revision()
            if revision < minimum_revision:
                raise ValueError("revision below management floor")
            if self.pending.exists() and revision != int(self.pending.read_bytes()):
                raise ValueError("current does not match pending publication")
            self.verify(revision)
            self.sync(self.root)  # Confirm the observed complete generation first.
            self.pending.unlink(missing_ok=True)
            self.sync(self.root)

    def consume(self, revision, permit):
        with self.exclusive():
            if self.pending.exists():
                raise ValueError("publication unconfirmed")
            if revision != self.current_revision():
                raise ValueError("stale generation")
            self.verify(revision)
            self.write(self.ledger / permit, b"")
            self.sync(self.ledger)


class PublicationTest(unittest.TestCase):
    def setUp(self):
        storage = tempfile.TemporaryDirectory()
        self.addCleanup(storage.cleanup)
        self.state = Publication(Path(storage.name))
        self.state.ledger.mkdir()
        self.state.stage(1)
        self.state.publish(1)
        self.state.stage(2)

    def test_staging_does_not_publish_and_mixed_generation_is_refused(self):
        self.assertEqual(self.state.current_revision(), 1)
        (self.state.root / "2" / "signature").write_bytes(b"1:signature")
        with self.assertRaisesRegex(ValueError, "mixed generation"):
            self.state.publish(2)
        self.assertEqual(self.state.current_revision(), 1)

    def test_switch_and_consume_have_a_single_order(self):
        self.state.consume(1, "before-switch")
        self.state.publish(2)
        with self.assertRaisesRegex(ValueError, "stale generation"):
            self.state.consume(1, "after-switch")
        with self.assertRaisesRegex(ValueError, "stale generation"):
            self.state.publish(1)
        with self.assertRaises(FileExistsError):
            self.state.consume(2, "before-switch")
        self.state.consume(2, "after-switch")

    def test_consumption_waits_for_an_in_progress_switch(self):
        syncing = Event()
        release = Event()
        consuming = Event()

        def hold_sync(directory):
            syncing.set()
            if not release.wait(timeout=5):
                raise TimeoutError("test did not release publication")
            self.state.sync(directory)

        def consume_old():
            consuming.set()
            self.state.consume(1, "racing")

        with ThreadPoolExecutor(max_workers=2) as workers:
            publishing = workers.submit(self.state.publish, 2, hold_sync)
            try:
                self.assertTrue(syncing.wait(timeout=5))
                consumer = workers.submit(consume_old)
                self.assertTrue(consuming.wait(timeout=5))
                self.assertFalse(consumer.done())
            finally:
                release.set()
            publishing.result(timeout=5)
            with self.assertRaisesRegex(ValueError, "stale generation"):
                consumer.result(timeout=5)
        self.assertFalse((self.state.ledger / "racing").exists())

    def test_uncertain_switch_blocks_until_reopened_and_confirmed(self):
        def sync_failure(_):
            raise OSError("injected parent sync failure")

        with self.assertRaisesRegex(OSError, "injected parent sync failure"):
            self.state.publish(2, sync_failure)
        reopened = Publication(self.state.root)
        for revision in (1, 2):
            with self.assertRaisesRegex(ValueError, "publication unconfirmed"):
                reopened.consume(revision, "blocked")
        self.assertEqual(list(reopened.ledger.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "management floor"):
            reopened.recover(3)
        self.assertTrue(reopened.pending.exists())
        reopened.current.write_bytes(b"1")
        with self.assertRaisesRegex(ValueError, "does not match pending"):
            reopened.recover(1)
        self.assertTrue(reopened.pending.exists())
        reopened.current.write_bytes(b"2")
        reopened.recover(2)
        reopened.consume(2, "confirmed")
