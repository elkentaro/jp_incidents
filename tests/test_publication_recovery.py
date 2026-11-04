"""Exercise durable publication failure/recovery without external services."""
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

import jp_incidents as app
import operations as ops
import publication


class PublicationRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.database = str(self.root/'private.db')
        self.at = datetime(2030, 1, 1, tzinfo=timezone.utc)
        for item in (patch.object(app, 'DB_PATH', self.database),
                     patch.dict(os.environ, {'JPI_GIT_REMOTE': 'origin', 'JPI_GIT_BRANCH': 'main',
                                             'JPI_LINKAGE_MAP': '0'}),
                     contextlib.redirect_stdout(io.StringIO())):
            item.__enter__()
            self.addCleanup(item.__exit__, None, None, None)
        self.calls = []
        self.failure = 'remote: Internal Server Error'

    def git(self, args, cwd, check=True):
        self.calls.append(args)
        if args[0] == 'push':
            return subprocess.CompletedProcess(args, bool(self.failure), self.failure or '')
        output = str(self.root) if args[0] == 'rev-parse' else '1' if args[0] == 'rev-list' else ''
        return subprocess.CompletedProcess(args, 0, output)

    def push(self, at=None):
        return publication.push_pending(self.database, str(self.root), 'origin', 'main',
                                        git=self.git, now=at or self.at)

    def state(self):
        return ops.get_state(self.database, 'publication')

    def alerts(self):
        with contextlib.closing(ops.connect(self.database)) as c:
            return {row[0]: json.loads(row[1]) for row in c.execute('SELECT key,payload FROM alert_outbox')}

    def test_backoff_survives_repeated_invocations_and_caps_at_thirty_minutes(self):
        moment = self.at
        for attempt, delay in enumerate((300, 600, 1200, 1800, 1800), 1):
            self.assertFalse(self.push(moment))
            state = self.state()
            self.assertEqual(state['attempts'], attempt)
            due = datetime.fromisoformat(state['next_attempt_at'])
            self.assertEqual((due - moment).total_seconds(), delay)
            calls = len(self.calls)
            self.push(due - timedelta(seconds=1))
            self.assertEqual(len(self.calls), calls)
            moment = due
        self.assertEqual(list(self.alerts()), ['publication-delayed'])

    def test_recovery_clears_pending_and_replaces_stale_warning(self):
        self.push()
        self.failure = None
        self.assertTrue(self.push(self.at + timedelta(minutes=5)))
        self.assertFalse(self.state()['pending'])
        self.assertEqual(self.state()['attempts'], 0)
        self.assertEqual(list(self.alerts()), ['publication-recovered'])

    def test_repeated_failure_does_not_requeue_delivered_warning(self):
        self.push()
        with contextlib.closing(ops.connect(self.database)) as c, c:
            c.execute('DELETE FROM alert_outbox')
        self.push(self.at + timedelta(minutes=5))
        self.assertEqual(self.alerts(), {})

    def test_ssh_rejection_and_non_fast_forward_retain_commits_without_force(self):
        for message in ('Permission denied (publickey).', '! [rejected] HEAD -> main (non-fast-forward)'):
            with self.subTest(message=message):
                ops.set_state(self.database, 'publication', {})
                self.failure = message
                self.assertFalse(self.push())
                self.assertTrue(self.state()['pending'])
                self.assertEqual(self.state()['last_error'], message)
                self.assertEqual(self.calls[-1], ['push', '--set-upstream', 'origin', 'HEAD:main'])

    def test_push_timeout_is_deferred(self):
        def git(args, cwd, check=True):
            if args[0] == 'push':
                raise subprocess.TimeoutExpired('git push', 120)
            return self.git(args, cwd, check)
        self.assertFalse(publication.push_pending(self.database, str(self.root), 'origin', 'main',
                                                  git=git, now=self.at))
        self.assertIn('timed out', self.state()['last_error'])

    def test_timeout_kills_git_and_ssh_process_group(self):
        with patch.object(publication.subprocess, 'Popen') as popen, \
             patch.object(publication.os, 'killpg') as kill:
            process = popen.return_value.__enter__.return_value
            process.pid = 12345
            process.communicate.side_effect = [subprocess.TimeoutExpired('git', 120), ('', None)]
            with self.assertRaises(subprocess.TimeoutExpired):
                publication.run_git(['push', 'origin', 'HEAD:main'], str(self.root))
            self.assertTrue(popen.call_args.kwargs['start_new_session'])
            kill.assert_called_once_with(12345, signal.SIGKILL)

    def test_interrupted_push_keeps_durable_pending_state(self):
        def git(args, cwd, check=True):
            if args[0] == 'push':
                self.assertTrue(self.state()['pending'])
                raise KeyboardInterrupt()
            return self.git(args, cwd, check)
        with self.assertRaises(KeyboardInterrupt):
            publication.push_pending(self.database, str(self.root), 'origin', 'main', git=git, now=self.at)
        self.failure = None
        self.assertTrue(self.push(self.at + timedelta(minutes=5)))
        self.assertFalse(self.state()['pending'])

    def test_pending_state_is_verified_even_if_tracking_ref_already_matches(self):
        self.push()
        def git(args, cwd, check=True):
            self.calls.append(args)
            return subprocess.CompletedProcess(args, 0, '0' if args[0] == 'rev-list' else '')
        self.assertTrue(publication.push_pending(self.database, str(self.root), 'origin', 'main',
                                                 git=git, now=self.at + timedelta(minutes=5)))
        self.assertEqual(self.calls[-1][0], 'push')
        self.assertFalse(self.state()['pending'])

    def test_collector_finishes_review_and_alerts_while_publication_is_deferred(self):
        args = SimpleNamespace(notify=False, publish=True, json_path=str(self.root/'incidents.json'),
                               rss_path=str(self.root/'feed.xml'), sources_path=str(self.root/'sources.json'))
        with patch.object(app, 'wait_for_network'), patch.object(app, 'check_ai_budget'), \
             patch.object(app, 'poll'), patch.object(app, 'send_local_alert'), \
             patch.object(app, 'write_public_json'), patch.object(app, 'write_public_rss'), \
             patch.object(app, 'write_public_sources'), patch.object(app, '_run_git', side_effect=self.git), \
             patch.object(app, 'review_pending') as review, patch.object(app, 'deliver_alerts') as alerts:
            app.run_cycle(args)
        self.assertEqual(ops.get_state(self.database, 'cycle')['status'], 'success')
        self.assertTrue(ops.get_state(self.database, 'cycle')['publication_pending'])
        self.assertIsNotNone(ops.get_state(self.database, 'collection_success'))
        review.assert_called_once()
        alerts.assert_called_once()

    def test_retry_does_not_collect_export_review_or_commit(self):
        self.failure = None
        with patch.object(app, '_run_git', side_effect=self.git), \
             patch.object(app, 'poll') as poll, patch.object(app, 'review_pending') as review, \
             patch.object(app, 'write_public_json') as export:
            app.retry_publication()
        poll.assert_not_called(); review.assert_not_called(); export.assert_not_called()
        self.assertEqual([call[0] for call in self.calls], ['rev-parse', 'rev-list', 'push'])

    def test_retry_skips_active_collection(self):
        with ops.lock(self.database, 'collector'), patch.object(app, '_run_git') as git:
            app.retry_publication()
        git.assert_not_called()

    def test_real_rejected_push_preserves_commit_then_recovers_without_new_commit(self):
        repo = self.root/'repo'
        remote = self.root/'remote.git'
        repo.mkdir()
        def git(*args, cwd=repo):
            return publication.run_git(list(args), str(cwd)).stdout.strip()
        git('init', '--bare', str(remote))
        git('init', '-b', 'main')
        git('config', 'user.email', 'test@example.invalid')
        git('config', 'user.name', 'Publication test')
        git('remote', 'add', 'origin', str(remote))
        (repo/'data.json').write_text('{"incidents":[]}\n')
        git('add', 'data.json'); git('commit', '-m', 'Saved incident data')
        commit = git('rev-parse', 'HEAD')
        hook = remote/'hooks/pre-receive'
        hook.write_text('#!/bin/sh\necho "Internal Server Error" >&2\nexit 1\n')
        hook.chmod(0o700)
        self.assertFalse(publication.push_pending(self.database, str(repo), 'origin', 'main', now=self.at))
        self.assertEqual(git('rev-parse', 'HEAD'), commit)
        self.assertEqual(git('status', '--porcelain'), '')
        hook.unlink()
        self.assertTrue(publication.push_pending(self.database, str(repo), 'origin', 'main',
                                                 now=self.at + timedelta(minutes=5)))
        self.assertEqual(git('rev-parse', 'main', cwd=remote), commit)
        self.assertEqual(git('rev-list', '--count', 'HEAD'), '1')
        self.assertFalse(self.state()['pending'])


if __name__ == '__main__':
    unittest.main()
