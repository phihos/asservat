#!/usr/bin/env python3
"""Synthetic saved JSON output only: no Go command or external service."""
from copy import deepcopy
from pathlib import Path
import json
import importlib.util
import signal
from unittest.mock import patch
import sys
import unittest

sys.dont_write_bytecode = True
import events

FIXTURE = json.loads(Path(__file__).with_name('synthetic-events.json').read_text())


def encode(rows):
    return '\n'.join(json.dumps(r) for r in rows)


class SavedGoOutput(unittest.TestCase):
    def test_complete_packages_parents_children_fuzz_example_and_fixed_skip(self):
        case = FIXTURE['execution']
        result = events.execution(encode(case['events']), case['expected'], {('p', 'TestNative'): 'owned fixture required'})
        self.assertEqual(result['parents'], 4)
        self.assertEqual(result['namedTests'], 5)
        self.assertEqual(result['skips'], [{'package': 'p', 'test': 'TestNative', 'reason': 'owned fixture required'}])
        self.assertEqual(len(result['passedParents']), 3)

    def test_missing_duplicate_and_foreign_events_fail(self):
        case = FIXTURE['execution']
        bad = []
        for action, name in [('run', 'TestA'), ('pass', 'TestA'), ('pass', 'FuzzA/seed#0'), ('start', None), ('pass', None)]:
            rows = deepcopy(case['events'])
            index = next(i for i, e in enumerate(rows) if e.get('Action') == action and e.get('Test') == name)
            bad.append(rows[:index] + rows[index+1:])
            bad.append(rows + [deepcopy(rows[index])])
        bad.extend([
            case['events'] + [{'Package': 'other', 'Action': 'pass'}],
            case['events'] + [{'Package': 'p', 'Action': 'fail', 'Test': 'TestA'}],
            case['events'] + [{'ImportPath': 'dependency', 'Action': 'build-fail'}],
            case['events'] + [{'Package': 'p', 'Action': 'run', 'Test': 'TestUnexpected'}],
            case['events'] + [{'Package': 'p', 'Action': 'run', 'Test': 'TestA/unfinished'}],
        ])
        for rows in bad:
            with self.subTest(rows=rows[-2:]), self.assertRaises(ValueError):
                events.execution(encode(rows), case['expected'], {('p', 'TestNative'): 'owned fixture required'})

    def test_skip_is_exact_package_name_and_original_reason(self):
        case = FIXTURE['execution']
        for allow in ({}, {('other', 'TestNative'): 'owned fixture required'}, {('p', 'TestNative'): 'different reason'}):
            with self.subTest(allow=allow), self.assertRaises(ValueError):
                events.execution(encode(case['events']), case['expected'], allow)
        rows = [e for e in case['events'] if not (e.get('Test') == 'TestNative' and e['Action'] == 'output')]
        with self.assertRaises(ValueError):
            events.execution(encode(rows), case['expected'], {('p', 'TestNative'): 'owned fixture required'})

    def test_allowing_parent_does_not_allow_child_skip(self):
        rows = [{'Package': 'p', 'Action': 'start'}, {'Package': 'p', 'Action': 'run', 'Test': 'TestA'},
                {'Package': 'p', 'Action': 'run', 'Test': 'TestA/child'},
                {'Package': 'p', 'Action': 'output', 'Test': 'TestA/child', 'Output': '    fixture_test.go:9: owned fixture required\n'},
                {'Package': 'p', 'Action': 'skip', 'Test': 'TestA/child'},
                {'Package': 'p', 'Action': 'pass', 'Test': 'TestA'}, {'Package': 'p', 'Action': 'pass'}]
        with self.assertRaises(ValueError):
            events.execution(encode(rows), {'p': ['TestA']}, {('p', 'TestA'): 'owned fixture required'})
        result = events.execution(encode(rows), {'p': ['TestA']}, {('p', 'TestA/child'): 'owned fixture required'})
        self.assertEqual(result['namedTests'], 2)

    def test_package_skip_is_only_for_empty_source_inventory(self):
        rows = [{'Package': 'p', 'Action': 'start'}, {'Package': 'p', 'Action': 'skip'}]
        self.assertEqual(events.execution(encode(rows), {'p': []}, {})['parents'], 0)
        with self.assertRaises(ValueError):
            events.execution(encode(rows), {'p': ['TestA']}, {})

    def test_discovery_requires_every_source_name_once(self):
        case = FIXTURE['discovery']
        self.assertEqual(events.discovery(encode(case['events']), case['expected']), case['expected'])
        bad = [case['events'][:-1], case['events'] + [case['events'][0]],
               case['events'] + [{'Package': 'p', 'Action': 'output', 'Output': 'TestA\n'}],
               case['events'] + [{'Package': 'p', 'Action': 'run', 'Test': 'TestA'}]]
        for rows in bad:
            with self.subTest(rows=rows[-1:]), self.assertRaises(ValueError):
                events.discovery(encode(rows), case['expected'])
        expected = dict(case['expected'], p=case['expected']['p'] + ['TestNewSplitParent'])
        with self.assertRaises(ValueError):
            events.discovery(encode(case['events']), expected)

    def test_sequential_whole_parent_groups_are_exact_and_bounded(self):
        names = ['Test' + str(i) for i in range(506)]
        groups = events.partition(names)
        self.assertEqual([len(g) for g in groups], [80, 80, 80, 80, 80, 80, 26])
        self.assertEqual([n for g in groups for n in g], sorted(names))
        with self.assertRaises(ValueError):
            events.partition(names + [names[0]])

    def test_source_declarations_include_one_line_tests_and_runnable_examples(self):
        source = FIXTURE['source']
        self.assertEqual(events.source_declarations(source), ['TestA', 'FuzzA', 'TestOneLine', 'Example_demo'])
        with self.assertRaises(ValueError):
            events.source_declarations(source + '\nfunc TestA(t *testing.T) {}\n')

    def test_invalid_json_and_build_diagnostics(self):
        case = FIXTURE['execution']
        with self.assertRaises(ValueError):
            events.execution('not JSON', case['expected'], {})
        rows = [{'ImportPath': 'dependency', 'Action': 'build-output', 'Output': 'compiler note'}] + case['events']
        self.assertEqual(events.execution(encode(rows), case['expected'], {('p', 'TestNative'): 'owned fixture required'})['parents'], 4)


class OwnedCleanup(unittest.TestCase):
    def runner(self):
        spec = importlib.util.spec_from_file_location('full_go_cleanup_review', Path(__file__).with_name('component.py'))
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        return runner

    def test_first_signal_records_without_raising_and_keeps_original(self):
        runner = self.runner()
        runner.interrupt(signal.SIGINT, None)
        runner.interrupt(signal.SIGTERM, None)
        self.assertEqual(runner.interrupt_signal, signal.SIGINT)
        with self.assertRaises(InterruptedError):
            runner.check_interrupt()

    def test_join_checks_group_after_joined_parent(self):
        runner = self.runner()
        operations, alive = [], [True]
        class Child:
            pid = 991
            def poll(self): return 0
            def wait(self, timeout): operations.append(('wait', timeout))
        def killpg(pid, sig):
            self.assertEqual(pid, 991)
            operations.append(('signal', sig))
            if not alive[0]: raise ProcessLookupError()
            if sig == signal.SIGKILL: alive[0] = False
        with patch.object(runner.os, 'killpg', killpg):
            self.assertTrue(runner.join_owned(Child()))
        self.assertEqual(operations[0], ('wait', 1))
        self.assertIn(('signal', signal.SIGKILL), operations)
        self.assertFalse(alive[0])

    def test_join_live_child_keeps_group_owned_until_exit(self):
        runner = self.runner()
        operations, alive = [], [True]
        class Child:
            pid = 992
            terminal = False
            def poll(self): return 0 if self.terminal else None
            def wait(self, timeout):
                operations.append(('wait', timeout))
                self.terminal = True
                alive[0] = False
        def killpg(pid, sig):
            self.assertEqual(pid, 992)
            operations.append(('signal', sig))
            if not alive[0]: raise ProcessLookupError()
        with patch.object(runner.os, 'killpg', killpg):
            self.assertTrue(runner.join_owned(Child()))
        self.assertEqual(operations[:2], [('signal', signal.SIGTERM), ('wait', 10)])


if __name__ == '__main__':
    unittest.main()
