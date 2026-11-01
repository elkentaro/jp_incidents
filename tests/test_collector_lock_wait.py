"""Collection waits for short maintenance without allowing overlap."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
import operations as ops
import jp_incidents as core


class CollectorLockTests(unittest.TestCase):
    def test_waits_for_short_holder_then_acquires(self):
        with tempfile.TemporaryDirectory() as work:
            path = str(Path(work) / 'db')
            held = threading.Event()
            release = threading.Event()
            def holder():
                with ops.lock(path, 'collector') as acquired:
                    self.assertTrue(acquired)
                    held.set()
                    release.wait(2)
            worker = threading.Thread(target=holder)
            worker.start()
            self.assertTrue(held.wait(1))
            timer = threading.Timer(0.1, release.set)
            timer.start()
            try:
                with ops.lock(path, 'collector', timeout=1) as acquired:
                    self.assertTrue(acquired)
                    with ops.lock(path, 'collector') as overlap:
                        self.assertFalse(overlap)
            finally:
                release.set()
                timer.join()
                worker.join()

    def test_timeout_and_default_remain_nonoverlapping(self):
        with tempfile.TemporaryDirectory() as work:
            path = str(Path(work) / 'db')
            with ops.lock(path, 'collector'):
                with ops.lock(path, 'collector', timeout=0.02) as acquired:
                    self.assertFalse(acquired)
            with ops.lock(path, 'collector') as acquired:
                self.assertTrue(acquired)

    def test_collection_requests_bounded_wait(self):
        with patch.object(core.ops, 'lock') as lock:
            lock.return_value.__enter__.return_value = False
            core.run_cycle(None)
            lock.assert_called_once_with(core.DB_PATH, 'collector', timeout=30)
