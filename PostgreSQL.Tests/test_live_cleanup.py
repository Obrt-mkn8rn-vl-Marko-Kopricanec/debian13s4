"""Actual private capture children with explicitly delivered cleanup faults."""
import os
import signal
import unittest
from unittest.mock import patch

from fixture_pg import PrivatePG


class LiveCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixture = PrivatePG(); self.addCleanup(self.fixture.close)
        context = self.fixture.context(); context.__enter__(); self.addCleanup(context.close)
        self.m = self.fixture.m
        self.children = []
        self.popen = self.m.subprocess.Popen
        self.addCleanup(self.cleanup_children)

    def entered(self, *args, **kwargs):
        child = self.popen(*args, **kwargs)
        self.children.append((child, (child.stdout, child.stderr), child.wait))
        return child

    def cleanup_children(self):
        # Test-owned fallback does not count as successful production cleanup.
        for child, streams, wait in self.children:
            if child.returncode is None:
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                wait(timeout=1)
            for stream in streams:
                if not stream.closed: stream.close()

    def test_postentry_buffer_and_selector_allocation_faults_keep_cause_and_reap(self):
        for allocation in ('buffers', 'selector'):
            fault = MemoryError('injected '+allocation+' allocation')
            target = (patch.object(self.m, 'bytearray', side_effect=fault, create=True)
                      if allocation == 'buffers' else
                      patch.object(self.m.selectors, 'DefaultSelector', side_effect=fault))
            with self.subTest(allocation=allocation), target, \
                 patch.object(self.m.subprocess, 'Popen', side_effect=self.entered), \
                 self.assertRaises(MemoryError) as caught:
                self.m.native('catalog', self.m.KERNEL.now()+3)
            self.assertIs(caught.exception, fault)
            child, streams, _ = self.children[-1]
            self.assertIsNotNone(child.returncode)
            self.assertIsNone(child.stdout); self.assertIsNone(child.stderr)
            self.assertTrue(all(stream.closed for stream in streams))
        self.assertEqual(len(self.children), 2)

    def test_primary_failure_keeps_all_cleanup_errors_and_reused_channels(self):
        original = OSError('capture channel setup')
        faults = tuple(OSError(name) for name in ('signal', 'wait', 'selector', 'stdout', 'stderr'))
        kill, selector_factory = os.killpg, self.m.selectors.DefaultSelector
        realopen, realclose = os.open, os.close
        other = self.fixture.root/'replacement'; other.write_bytes(b'keep')
        events, reused = [], []
        def retired():
            child = self.children[0][0]
            self.assertIsNone(child.stdout); self.assertIsNone(child.stderr)
        class Pipe:
            def __init__(self, stream, index): self.stream, self.index = stream, index
            def fileno(self): return self.stream.fileno()
            def close(self):
                retired(); events.append(('close', self.index))
                fd = self.stream.fileno(); self.stream.close()
                replacement = realopen(other, os.O_RDONLY)
                if replacement != fd:
                    os.dup2(replacement, fd); realclose(replacement)
                reused.append(fd)
                raise faults[3+self.index]
        def entered(*args, **kwargs):
            child = self.entered(*args, **kwargs)
            child.stdout, child.stderr = Pipe(child.stdout, 0), Pipe(child.stderr, 1)
            realwait = child.wait
            def wait(*args, **kwargs):
                retired(); events.append(('wait', kwargs.get('timeout')))
                realwait(*args, **kwargs)
                raise faults[1]
            child.wait = wait
            return child
        def signal_child(pid, value):
            retired(); self.assertEqual(pid, self.children[0][0].pid)
            events.append(('signal', value)); kill(pid, value); raise faults[0]
        def selector():
            value = selector_factory(); close = value.close
            def closing():
                retired(); events.append(('selector',)); close(); raise faults[2]
            value.close = closing
            return value
        try:
            with patch.object(self.m.subprocess, 'Popen', side_effect=entered), \
                 patch.object(self.m.os, 'set_blocking', side_effect=original), \
                 patch.object(self.m.os, 'killpg', side_effect=signal_child), \
                 patch.object(self.m.selectors, 'DefaultSelector', side_effect=selector), \
                 self.assertRaises(self.m.CleanupFailure) as caught:
                self.m.native('catalog', self.m.KERNEL.now()+3)
            self.assertIs(caught.exception.cause, original)
            self.assertIs(caught.exception.__cause__, original)
            self.assertEqual(caught.exception.cleanup, faults)
            self.assertEqual([event[0] for event in events], ['signal', 'wait', 'selector', 'close', 'close'])
            self.assertEqual(events[1][1], self.m.KERNEL.CLEANUP_SECONDS)
            self.assertEqual(len(self.children), 1)
            child, streams, _ = self.children[0]
            self.assertIsNotNone(child.returncode)
            self.assertTrue(all(stream.closed for stream in streams))
            self.assertEqual(len(set(reused)), 2)
            for fd in reused: self.assertEqual(os.read(fd, 4), b'keep')
        finally:
            for fd in reused: realclose(fd)

    def test_completed_capture_still_refuses_selector_close_failure(self):
        fault = OSError('completed capture selector close')
        selector_factory = self.m.selectors.DefaultSelector
        states = []
        def selector():
            value = selector_factory(); close = value.close
            def closing():
                child = self.children[0][0]
                states.append((child.returncode, child.stdout, child.stderr))
                close(); raise fault
            value.close = closing
            return value
        with patch.object(self.m.subprocess, 'Popen', side_effect=self.entered), \
             patch.object(self.m.selectors, 'DefaultSelector', side_effect=selector), \
             self.assertRaises(OSError) as caught:
            self.m.native('catalog', self.m.KERNEL.now()+3)
        self.assertIs(caught.exception, fault)
        self.assertEqual(states, [(0, None, None)])
        self.assertIs(type(states[0][0]), int)
        self.assertEqual(len(self.children), 1)
        self.assertTrue(all(stream.closed for stream in self.children[0][1]))


if __name__ == '__main__':
    unittest.main()
