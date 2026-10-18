"""Private whole-file refusals retain their original cause and one close error."""
import os
import unittest
from unittest.mock import patch

import test_prepare as preparation_fixture
from fixture_pg import PrivatePG


class ReaderCleanupTests(unittest.TestCase):
    def exercise(self, prep, target, replacement, read):
        original_bytes = target.read_bytes()
        realread, realclose, realopen = os.read, os.close, os.open
        closing = prep.close_descriptor
        fault = OSError('injected after descriptor retirement')
        observed, changed, closed, reused = [], [], [], []
        identity = target.stat().st_dev, target.stat().st_ino
        def reading(fd, count):
            raw = realread(fd, count)
            info = os.fstat(fd)
            if raw and (info.st_dev, info.st_ino) == identity and not changed:
                changed.append(fd); target.chmod(0o640)
            return raw
        def retire(fd, cause):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == identity:
                observed.append(cause)
            return closing(fd, cause)
        def close(fd):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity:
                return realclose(fd)
            closed.append(fd); realclose(fd)
            other = realopen(replacement, os.O_RDONLY)
            if other != fd:
                os.dup2(other, fd); realclose(other)
            reused.append(fd)
            raise fault
        try:
            with patch.object(prep.os, 'read', side_effect=reading), \
                 patch.object(prep.os, 'close', side_effect=close), \
                 patch.object(prep, 'close_descriptor', side_effect=retire), \
                 self.assertRaises(prep.CleanupFailure) as caught:
                read()
            self.assertEqual(len(observed), 1)
            self.assertIs(type(observed[0]), prep.Pending)
            self.assertIn('changed', str(observed[0]))
            self.assertIs(caught.exception.cause, observed[0])
            self.assertIs(caught.exception.__cause__, observed[0])
            self.assertEqual(caught.exception.cleanup, (fault,))
            self.assertEqual(closed, changed); self.assertEqual(closed, reused)
            self.assertEqual(os.read(reused[0], 4), b'root')
            self.assertEqual(target.read_bytes(), original_bytes)
        finally:
            for fd in reused: realclose(fd)

    def test_protected_configuration_drift_retains_real_refusal_and_close_failure(self):
        h = preparation_fixture.PreparationTests('runTest')
        self.addCleanup(h.doCleanups); h.setUp()
        self.exercise(h.m, h.m.INPUT, h.m.PASSWD, h.prepare)

    def test_postgres_owned_data_drift_retains_real_refusal_and_close_failure(self):
        h = PrivatePG(); self.addCleanup(h.close)
        context = h.context(); context.__enter__(); self.addCleanup(context.close)
        target = h.m.DATA/'PG_VERSION'
        self.exercise(h.m.PREP, target, h.m.PREP.PASSWD,
            lambda: h.m.data_read(target, h.m.KERNEL.now()+3))


if __name__ == '__main__':
    unittest.main()
