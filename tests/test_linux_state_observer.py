import os
from pathlib import Path
import tempfile
import signal
import time
import unittest
from unittest.mock import patch

from integration.linux_state_observer import CATEGORIES, DIRECTORY_FLAGS, observe_home


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.root.chmod(0o700)
        self.home = self.root / 'host-home'
        self.home.mkdir(mode=0o700)
        for name in CATEGORIES:
            path = self.home / name
            path.write_bytes(b'dummy-host-home')
            path.chmod(0o600)
        self.fd = os.open(self.root, DIRECTORY_FLAGS)
        # Rootless test only: retain real type/mode/devino, substitute owner.
        real_fstat = os.fstat
        def root_owned(fd):
            values = list(real_fstat(fd))
            values[4] = 0
            return os.stat_result(values)
        self.owner = patch('integration.linux_state_observer.os.fstat', side_effect=root_owned)
        self.owner.start()

    def tearDown(self):
        self.owner.stop()
        os.close(self.fd)
        self.directory.cleanup()

    def test_positive_repeated_observation_and_replacement_rejection(self):
        previous = observe_home(self.fd)
        self.assertEqual(len(previous['entries']), 9)
        self.assertEqual(observe_home(self.fd, previous), previous)
        path = self.home / 'settings'
        path.rename(self.home / 'old-settings')
        path.write_bytes(b'dummy-host-home')
        path.chmod(0o600)
        with self.assertRaises(ValueError):
            observe_home(self.fd, previous)

    def test_bad_content_mode_and_symlink_are_rejected(self):
        path = self.home / 'settings'
        path.write_bytes(b'wrong')
        with self.assertRaises(ValueError):
            observe_home(self.fd)
        path.write_bytes(b'dummy-host-home')
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            observe_home(self.fd)
        path.unlink()
        path.symlink_to(self.home / 'hooks')
        with self.assertRaises(OSError):
            observe_home(self.fd)

    def test_writerless_fifo_is_rejected_without_blocking(self):
        path = self.home / 'settings'
        path.unlink()
        os.mkfifo(path, 0o600)
        pid = os.fork()
        if pid == 0:
            try:
                observe_home(self.fd)
            except ValueError:
                os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(1)
        status = None
        try:
            until = time.monotonic() + 1
            while time.monotonic() < until:
                waited, value = os.waitpid(pid, os.WNOHANG)
                if waited:
                    status = value
                    break
                time.sleep(0.001)
        finally:
            if status is None:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
        self.assertIsNotNone(status, 'FIFO observation blocked')
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), 0)
