import io
import json
import os
from pathlib import Path
import sqlite3
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from datetime import datetime, timezone

import jp_incidents as app
import operations as ops
from scripts.check_heartbeat import validate


class ResilienceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = str(self.root/'live.db')
        for p in [patch.object(app,'DB_PATH',self.path), patch.object(app,'ALERT_STATE_PATH',str(self.root/'alerts.json'))]:
            p.start(); self.addCleanup(p.stop)
        c = app.db(); c.close()
        self.rec = {'url':'https://example.jp/notice/20261019.html', 'title':'Exampleへの不正アクセス',
                    'summary':'Notice', 'published':'2026-10-19T00:00:00+00:00'}

    def queue(self, iid='candidate'):
        with app.db() as c:
            app.queue_for_review(c,'Example',iid,self.rec)

    def seed(self):
        with app.db() as c:
            app.store(c,'Example',self.rec,{'org':'Example','kind':'data leak','records':12,
                                          'incident_date':self.rec['published']})
        return app.item_id(self.rec['url'])

    def test_git_failure_does_not_block_review_or_alert_delivery(self):
        args = SimpleNamespace(notify=False,publish=True,json_path='unused',rss_path='unused',sources_path='unused')
        with patch.object(app,'wait_for_network'), patch.object(app,'check_ai_budget'), \
             patch.object(app,'poll'), patch.object(app,'send_local_alert'), \
             patch.object(app,'publish_public_json',side_effect=RuntimeError('push failed')), \
             patch.object(app,'review_pending') as review, patch.object(app,'deliver_alerts') as alerts:
            with self.assertRaisesRegex(RuntimeError,'publication'):
                app.run_cycle(args)
        review.assert_called_once(); alerts.assert_called_once()
        self.assertEqual(ops.get_state(self.path,'cycle')['status'],'failed')
        self.assertIsNotNone(ops.get_state(self.path,'collection_success'))

    def test_lock_prevents_overlapping_collectors(self):
        with ops.lock(self.path,'collector') as first:
            with ops.lock(self.path,'collector') as second:
                self.assertTrue(first); self.assertFalse(second)

    def test_failed_operational_alert_survives_and_is_delivered_later(self):
        with patch.dict(os.environ, {'JPI_ALERT_WEBHOOK_URL':'https://discord.example/hook', 'ANTHROPIC_API_KEY':'private-key'}):
            app.send_local_alert('failure','Failure','private-key failed',post_fn=lambda _:False)
        with ops.connect(self.path) as c:
            row=c.execute('SELECT payload FROM alert_outbox').fetchone()
            self.assertNotIn('private-key',row[0])
        with patch.object(app,'send_local_alert',return_value=True) as send:
            app.deliver_alerts(); app.deliver_alerts()
            self.assertEqual(send.call_count,1)
        with ops.connect(self.path) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM alert_outbox').fetchone()[0],0)

    def test_backup_restores_data_queue_decisions_and_config_without_touching_live_db(self):
        self.seed(); self.queue()
        with app.db() as c:
            app.hold_for_manual_review(c,{'id':'candidate'},'Victim uncertain','evidence')
        config=self.root/'config';config.write_text('PRIVATE_TEST_VALUE=example')
        result=ops.backup(self.path,self.root/'backups',{'config.env':config})
        restored=self.root/'recovered'
        manifest=ops.restore_backup(result['archive'],restored)
        self.assertEqual(manifest['rows']['incidents'],1)
        self.assertEqual(manifest['rows']['manual_reviews'],1)
        self.assertEqual((restored/'config.env').read_text(),config.read_text())
        self.assertEqual(Path(result['archive']).stat().st_mode & 0o777,0o600)
        with self.assertRaises(FileExistsError):ops.restore_backup(result['archive'],self.root)
        with sqlite3.connect(self.path) as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],1)

    def test_delivery_bounds_work_and_preserves_remaining_alerts(self):
        for i in range(10):
            ops.queue_alert(self.path, str(i), {'title':'Failure', 'detail':'Example'})
        with patch.object(app, 'send_local_alert', return_value=True) as send:
            app.deliver_alerts()
            self.assertEqual(send.call_count, 4)
        with ops.connect(self.path) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM alert_outbox').fetchone()[0], 6)

    def test_unchanged_vague_listing_rechecks_changed_body(self):
        rec = {**self.rec, 'title':'お知らせ'}
        source = {'name':'Example', 'url':'https://example.jp/news', 'type':'html'}
        with patch.object(app, 'load_sources', return_value=[source]), \
             patch.object(app, 'load_items', return_value=[rec]), \
             patch.object(app, 'needs_notice_body', return_value=True), \
             patch.object(app, 'gate', return_value=False), \
             patch.object(app, 'probable_article', return_value=True), \
             patch.dict(os.environ, {'JPI_RECHECK_HOURS':'0'}):
            app.poll(fetch_body_fn=lambda _: 'original notice body')
            app.poll(fetch_body_fn=lambda _: 'changed notice body')
        with app.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM review_queue WHERE status='needs_review'").fetchone()[0], 1)

    def test_restore_rejects_path_traversal(self):
        path=self.root/'evil.tar.gz'
        with tarfile.open(path,'w:gz') as tar:
            entry=tarfile.TarInfo('../escape');entry.size=4
            tar.addfile(entry,io.BytesIO(b'evil'))
        with self.assertRaises(ValueError):ops.restore_backup(path,self.root/'restore')
        self.assertFalse((self.root/'escape').exists())

    def test_daily_ai_reservations_enforce_limits_before_network(self):
        payload={'max_tokens':100,'messages':[]}
        with patch.dict(os.environ,{'JPI_AI_DAILY_REQUEST_LIMIT':'1'}):
            ops.reserve_request(self.path,payload)
            with self.assertRaises(ops.BudgetLimit):ops.reserve_request(self.path,payload)
        with patch.dict(os.environ,{'JPI_AI_DAILY_TOKEN_LIMIT':'1'}):
            with self.assertRaises(ops.BudgetLimit):ops.reserve_request(self.path,payload)

    def test_bounded_review_rotates_failed_candidate_and_preserves_backlog(self):
        self.queue('a');self.queue('b')
        with patch.object(app,'llm_extract_many',return_value=None), patch.object(app,'deliver_alerts'):
            result=app.review_pending(fetch_body_fn=lambda _: 'body')
        self.assertEqual(result['deferred'],2)
        with patch.dict(os.environ,{'JPI_REVIEW_BATCH_LIMIT':'1'}), \
             patch.object(app,'llm_extract_many',return_value=[]), patch.object(app,'deliver_alerts'):
            result=app.review_pending(fetch_body_fn=lambda _: 'body')
        with app.db() as c:
            self.assertEqual(c.execute("SELECT status FROM review_queue WHERE id='b'").fetchone()[0],'rejected')
            self.assertEqual(c.execute("SELECT status FROM review_queue WHERE id='a'").fetchone()[0],'pending')

    def test_exhausted_monthly_budget_keeps_review_pending(self):
        self.queue();ops.set_state(self.path,'ai_budget',{'remaining':0})
        with patch.object(app,'llm_extract_many') as ai, patch.object(app,'deliver_alerts'):
            result=app.review_pending()
        self.assertEqual(result['deferred'],1);ai.assert_not_called()

    def test_temporary_daily_budget_expires_at_exact_timezone_boundary(self):
        env = {'JPI_AI_DAILY_TOKEN_LIMIT':'2000000',
               'JPI_AI_TEMP_DAILY_TOKEN_LIMIT':'3000000',
               'JPI_AI_TEMP_TOKEN_LIMIT_UNTIL':'2030-01-03T09:00:00+09:00'}
        with patch.dict(os.environ,env,clear=True):
            self.assertEqual(ops.daily_token_limit(datetime(2030,1,2,23,59,59,tzinfo=timezone.utc)),3000000)
            self.assertEqual(ops.daily_token_limit(datetime(2030,1,3,tzinfo=timezone.utc)),2000000)

    def test_temporary_budget_preserves_usage_and_hard_limit(self):
        moment=datetime(2030,1,2,tzinfo=timezone.utc)
        with ops.connect(self.path) as c:
            c.execute('INSERT INTO ai_usage VALUES(?,?,?)',('2030-01-02',10,2500000))
        env={'JPI_AI_TEMP_DAILY_TOKEN_LIMIT':'3000000',
             'JPI_AI_TEMP_TOKEN_LIMIT_UNTIL':'2030-01-03T00:00:00Z'}
        with patch.dict(os.environ,env,clear=True), patch.object(ops,'datetime') as clock:
            clock.now.return_value=moment
            clock.fromisoformat.side_effect=datetime.fromisoformat
            ops.reserve_request(self.path,{'max_tokens':1000})
            with self.assertRaises(ops.BudgetLimit):
                ops.reserve_request(self.path,{'max_tokens':500000})
        with ops.connect(self.path) as c:
            requests,tokens=c.execute('SELECT requests,tokens FROM ai_usage').fetchone()
        self.assertEqual(requests,11)
        self.assertGreater(tokens,2500000)
        self.assertLess(tokens,3000000)

    def test_incomplete_or_invalid_temporary_budget_fails_closed(self):
        for env in [
            {'JPI_AI_TEMP_DAILY_TOKEN_LIMIT':'3000000'},
            {'JPI_AI_TEMP_TOKEN_LIMIT_UNTIL':'2030-01-03T00:00:00Z'},
            {'JPI_AI_TEMP_DAILY_TOKEN_LIMIT':'3000000','JPI_AI_TEMP_TOKEN_LIMIT_UNTIL':'2030-01-03'},
            {'JPI_AI_TEMP_DAILY_TOKEN_LIMIT':'0','JPI_AI_TEMP_TOKEN_LIMIT_UNTIL':'2030-01-03T00:00:00Z'},
        ]:
            with self.subTest(env=env), patch.dict(os.environ,env,clear=True):
                with self.assertRaises(ValueError):ops.daily_token_limit()

    def test_changed_body_at_same_url_creates_one_private_review(self):
        source={'name':'Example'}
        with app.db() as c, patch.dict(os.environ,{'JPI_RECHECK_HOURS':'0'}):
            app.recheck_article(c,self.rec,source,lambda _: 'original body')
            app.recheck_article(c,self.rec,source,lambda _: 'corrected victim count body')
            app.recheck_article(c,self.rec,source,lambda _: 'corrected victim count body')
            self.assertEqual(c.execute("SELECT COUNT(*) FROM review_queue WHERE status='needs_review'").fetchone()[0],1)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)

    def test_correction_withdraw_restore_are_audited_and_automation_cannot_undo_them(self):
        iid=self.seed()
        app.edit_incident(iid,'correct','Verified correction',{'records':4})
        self.assertEqual(app.all_public_incidents()[0]['potential_records'],4)
        app.edit_incident(iid,'withdraw','Report retracted')
        self.assertEqual(app.all_public_incidents(),[])
        self.assertEqual(app.recent(3650),[])
        with app.db() as c:
            app.store(c,'Example',self.rec,{'org':'Wrong victim','kind':'data leak','records':999,
                                          'incident_date':'2026-10-18'})
        self.assertEqual(app.all_public_incidents(),[])
        app.edit_incident(iid,'restore','Retraction reversed with evidence')
        self.assertEqual(app.all_public_incidents()[0]['potential_records'],4)
        self.assertEqual(len(app.edit_incident(iid,'check')['history']),3)
        self.assertNotIn('Verified correction',json.dumps(app.all_public_incidents()))

    def test_heartbeat_checks_age_not_incident_changes(self):
        from datetime import datetime,timezone
        now=datetime(2026,10,20,tzinfo=timezone.utc)
        self.assertEqual(validate({'collector_success_at':'2026-10-20T00:00:00+00:00'},now),0)
        with self.assertRaises(ValueError):validate({'collector_success_at':'2026-10-19T00:00:00+00:00'},now)


if __name__=='__main__':unittest.main()
