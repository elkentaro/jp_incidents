import io
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jp_incidents as app


class ManualReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='review space ')
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name) / 'private.db')
        for mock in (patch.object(app, 'DB_PATH', self.path),
                     patch.object(app, 'now_iso', return_value='2026-10-20T00:00:00+00:00')):
            mock.start()
            self.addCleanup(mock.stop)
        self.alert = patch.object(app, 'send_local_alert', return_value=True).start()
        self.addCleanup(patch.stopall)
        self.rec = {'title': 'Exampleへの不正アクセス', 'url': 'https://example.jp/download?id=123',
                    'summary': 'Potential incident', 'published': '2026-10-19T00:00:00+00:00'}
        self.iid = app.item_id(self.rec['url'])
        with app.db() as c:
            app.queue_for_review(c, 'Example', self.iid, self.rec)

    def hold(self):
        with patch.object(app, 'llm_extract_many') as ai:
            app.review_pending(fetch_body_fn=lambda _: app.ArticleText('', 'PDF text unavailable'))
            ai.assert_not_called()

    def facts(self, **overrides):
        return {**{'org': 'Example', 'incident_date': '2026-10-19', 'kind': 'data leak', 'records': 12}, **overrides}

    def test_pdf_download_without_suffix_is_held_and_alerted_once(self):
        self.hold()
        self.assertEqual(app.inspect_manual_review(self.iid)['status'], 'needs_review')
        with app.db() as c:
            self.assertEqual(app.promote_reviewed(c), [])
            self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0], 0)
        app.review_pending(fetch_body_fn=lambda _: self.fail('Held items must not be auto-reviewed'))
        self.assertEqual(self.alert.call_count, 1)
        detail = self.alert.call_args.args[2]
        for action in ['check', 'approve', 'reject']:
            self.assertIn('review ' + action + ' ' + self.iid, detail)
        self.assertLess(len(detail), 1200)  # all commands survive the operations-alert limit

    def test_failed_alert_retries_after_restart_without_duplicate_success(self):
        self.alert.return_value = False
        self.hold()
        self.assertIsNone(app.inspect_manual_review(self.iid)['notified_at'])
        self.alert.return_value = True
        app.review_pending()
        app.review_pending()
        self.assertEqual(self.alert.call_count, 2)
        self.assertIsNotNone(app.inspect_manual_review(self.iid)['notified_at'])

    def test_admin_digest_lists_items_and_retries_only_unacknowledged_batches(self):
        with app.db() as c:
            for index in range(6):
                iid = f'digest-{index}'
                app.queue_for_review(c, 'Example source', iid, {**self.rec, 'title':f'Article {index} @everyone'})
                app.hold_for_manual_review(c, {'id':iid}, 'Victim unclear')
            with patch.dict(os.environ, {'JPI_REVIEW_ADMIN_URL':'http://admin.example:1337'}):
                self.alert.return_value = False
                app.notify_manual_reviews(c)
                self.assertEqual(c.execute('SELECT COUNT(*) FROM manual_reviews WHERE notified_at IS NOT NULL').fetchone()[0],0)
                detail = self.alert.call_args.args[2]
                self.assertIn('6 awaiting review', detail)
                self.assertIn('http://admin.example:1337', detail)
                self.assertIn('Article 0', detail)
                self.assertIn('Article 3', detail)
                self.assertNotIn('Article 4', detail)
                self.assertNotIn('@everyone', detail)
                self.assertNotIn('review approve', detail)
                self.assertLess(len(detail),1600)
                self.alert.return_value = True
                app.notify_manual_reviews(c)
                self.assertEqual(c.execute('SELECT COUNT(*) FROM manual_reviews WHERE notified_at IS NOT NULL').fetchone()[0],4)
                app.notify_manual_reviews(c)
                self.assertEqual(c.execute('SELECT COUNT(*) FROM manual_reviews WHERE notified_at IS NOT NULL').fetchone()[0],6)
                app.notify_manual_reviews(c)
                self.assertEqual(self.alert.call_count,3)

    def test_invalid_admin_url_preserves_unsent_review(self):
        with app.db() as c:
            app.hold_for_manual_review(c, {'id':self.iid}, 'Victim unclear')
            with patch.dict(os.environ, {'JPI_REVIEW_ADMIN_URL':'https://user:password@admin.example'}):
                with self.assertRaises(ValueError):app.notify_manual_reviews(c)
            self.assertIsNone(app.inspect_manual_review(self.iid)['notified_at'])
            self.alert.assert_not_called()

    def test_unclear_victim_is_held_even_with_no_concrete_findings(self):
        with patch.object(app, 'llm_extract_many', return_value=app.ReviewFindings(reasons=['Victim unclear'])):
            app.review_pending(fetch_body_fn=lambda _: 'article evidence')
        self.assertEqual(app.inspect_manual_review(self.iid)['reason'], 'Victim unclear')
        self.assertEqual(app.inspect_manual_review(self.iid)['body'], 'article evidence')

    def test_clear_nonincident_rejects_without_manual_alert(self):
        with patch.object(app, 'llm_extract_many', return_value=app.ReviewFindings()):
            result = app.review_pending(fetch_body_fn=lambda _: 'irrelevant article')
        self.assertEqual(result['rejected'], 1)
        self.assertEqual(app.inspect_manual_review(), [])
        self.alert.assert_not_called()

    def test_approval_requires_verified_facts_and_only_publishes_next_cycle(self):
        self.hold()
        for bad in [self.facts(org='VICTIM_NAME'), self.facts(incident_date='invalid'),
                    self.facts(incident_date='2026-01-01'), self.facts(records=-1)]:
            with self.assertRaises(ValueError):
                app.decide_manual_review(self.iid, 'approve', 'Checked source', [bad])
        self.assertEqual(app.inspect_manual_review(self.iid)['status'], 'needs_review')
        app.decide_manual_review(self.iid, 'approve', 'Victim and date verified in original PDF', [self.facts()])
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0], 0)
            self.assertEqual(len(app.promote_reviewed(c)), 1)
        self.assertEqual(app.inspect_manual_review(self.iid)['resolution'], 'approve')
        with self.assertRaises(ValueError):
            app.decide_manual_review(self.iid, 'reject', 'Cannot overwrite completed approval')
        public = json.dumps(app.all_public_incidents())
        self.assertNotIn('Victim and date verified', public)
        self.assertNotIn('PDF text unavailable', public)

    def test_rejection_is_audited_final_and_stays_unpublished(self):
        self.hold()
        app.decide_manual_review(self.iid, 'reject', 'Advisory, not an actual victim')
        with app.db() as c:
            self.assertEqual(app.promote_reviewed(c), [])
        self.assertEqual(app.inspect_manual_review(self.iid)['note'], 'Advisory, not an actual victim')
        with self.assertRaises(ValueError):
            app.decide_manual_review(self.iid, 'approve', 'Stale command', [self.facts()])

    def test_manual_late_disclosure_preserves_original_incident_date(self):
        self.hold()
        app.decide_manual_review(self.iid, 'approve', 'Original PDF first announced this on October 19',
                                 [self.facts(incident_date='2026-06-01', disclosed_at='2026-10-19')])
        with app.db() as c:
            app.promote_reviewed(c)
            row = c.execute('SELECT published,disclosed_at FROM incidents').fetchone()
            self.assertEqual(app._incident_day(row['published']), '2026-06-01')
            self.assertEqual(app._incident_day(row['disclosed_at']), '2026-10-19')

    def test_commands_target_correct_db_from_different_working_directory(self):
        self.hold()
        commands = app.manual_review_commands(self.iid)
        env = {**os.environ, 'JPI_DB': self.path}
        result = subprocess.run(shlex.split(commands['check']), env=env, cwd='/tmp',
                                check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)['id'], self.iid)
        facts = Path(self.temp.name) / 'findings.json'
        facts.write_text(json.dumps([self.facts(), self.facts(org='Another Victim')]))
        argv = shlex.split(commands['check'])
        argv[3] = 'approve'
        result = subprocess.run(argv + ['--findings', str(facts), '--note', 'Both victims verified'],
                                env=env, cwd='/tmp', capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        with app.db() as c:
            self.assertEqual(len(app.promote_reviewed(c)), 2)

    def test_ai_parser_preserves_ambiguous_entries_for_human_review(self):
        for document in [{'incidents': [], 'needs_review': True, 'review_reason': 'Victim unnamed'},
                         {'incidents': [{'org': None, 'kind': 'data leak', 'incident_date': '2026-10-19'}]}]:
            payload = {'content': [{'type': 'text', 'text': json.dumps(document)}]}
            with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'test-key'}), \
                 patch.object(app.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(payload).encode())):
                result = app.llm_extract_many(self.rec, 'uncertain evidence')
            self.assertEqual(result, [])
            self.assertTrue(result.reasons)

    def test_sonnet_55_uses_supported_thinking_mode_in_both_extractors(self):
        response = {'content':[{'type':'text','text':json.dumps(
            {'incidents':[], 'needs_review':False, 'is_incident':False})}]}
        for extract in (app.llm_extract, app.llm_extract_many):
            with self.subTest(extract=extract.__name__), \
                 patch.dict(os.environ, {'ANTHROPIC_API_KEY':'test-key', 'JPI_MODEL':'claude-sonnet-5-5'}), \
                 patch.object(app.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(response).encode())) as request:
                self.assertIsNotNone(extract(self.rec, 'article evidence'))
                payload=json.loads(request.call_args.args[0].data)
                self.assertEqual(payload['thinking'], {'type':'between_tools'})
                self.assertEqual(payload['model'], 'claude-sonnet-5-5')
                self.assertEqual(request.call_count, 1)

    def test_bad_pdf_cannot_take_immediate_official_publication_path(self):
        with patch.object(app, 'resolve_url', side_effect=lambda url: url):
            result = app.classify(self.rec, {'name': 'Example'}, use_ai=False,
                                  fetch_body_fn=lambda _: app.ArticleText('bad text', 'Garbled PDF'))
        self.assertIsNone(result)

    def test_wrong_pdf_content_and_truncation_have_review_diagnostics(self):
        with patch.object(app, 'fetch', return_value=b'<html>Access blocked</html>'):
            text = app.fetch_body('https://example.jp/notice.pdf')
        self.assertFalse(text)
        self.assertIn('Expected a PDF', text.problem)
        worker = subprocess.CompletedProcess([], 0, stdout=b'valid text ' * 20,
                                             stderr=b'JPI_PDF_TRUNCATED')
        with patch.object(app, 'fetch', return_value=b'%PDF-1.7'), \
             patch.object(app.subprocess, 'run', return_value=worker):
            text = app.fetch_body('https://example.jp/download')
        self.assertTrue(text)
        self.assertIn('incomplete', text.problem)

    def test_formatted_alert_keeps_copyable_commands_and_redacts_secrets(self):
        with patch.dict(os.environ, {'ANTHROPIC_API_KEY': 'private-test-key'}):
            detail = app._safe_alert_detail("Check:\n`python '/tmp/two  spaces/tool.py' review check abc`\nprivate-test-key",
                                            preserve_format=True)
        self.assertIn("'/tmp/two  spaces/tool.py'", detail)
        self.assertIn('\n', detail)
        self.assertNotIn('private-test-key', detail)


if __name__ == '__main__':
    unittest.main()
