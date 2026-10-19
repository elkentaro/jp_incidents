import io
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jp_incidents as app


def text_pdf(text='Unauthorized access disclosed on October 19, 2026.'):
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
    writer = PdfWriter()
    page = writer.add_blank_page(width=600, height=800)
    font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                             NameObject('/Subtype'): NameObject('/Type1'),
                             NameObject('/BaseFont'): NameObject('/Helvetica')})
    page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({
        NameObject('/F1'): writer._add_object(font)})})
    stream = DecodedStreamObject()
    stream.set_data(f'BT /F1 12 Tf 50 700 Td ({text}) Tj ET'.encode())
    page[NameObject('/Contents')] = writer._add_object(stream)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


class PdfTests(unittest.TestCase):
    def test_shift_jis_feed_preserves_japanese_titles(self):
        raw = ('<?xml version="1.0" encoding="Shift_JIS"?><rss><channel><item>'
               '<title>不正アクセスに関するお知らせ</title><link>https://example.jp/news/1</link>'
               '</item></channel></rss>').encode('shift_jis')
        self.assertEqual(app.parse_feed(raw)[0]['title'], '不正アクセスに関するお知らせ')

    def test_jsonp_is_parsed_as_data_and_cannot_execute_code(self):
        source = {'name': 'Issuer', 'url': 'https://example.jp/news/', 'type': 'json_news',
                  'feed_url': 'https://example.jp/feed.js', 'jsonp': True,
                  'records_key': 'item', 'link_field': 'link'}
        payload = b'news.callback({"item":[{"title":"Notice","link":"/notice.pdf","date":"2026-10-19"}]});'
        items = app.load_items(source, lambda _: payload)
        self.assertEqual(items[0]['url'], 'https://example.jp/notice.pdf')
        self.assertEqual(app._incident_day(items[0]['published']), '2026-10-19')
        with self.assertRaises(ValueError):
            app.load_items(source, lambda _: payload + b'alert("unexpected");')

    def test_shared_document_host_trust_is_scoped_to_configured_issuer(self):
        with patch.object(app, 'ORGANIZATION_SOURCES', [{'article_prefixes': ['https://documents.example/doc/123/']}]):
            self.assertEqual(app.ref_tier('https://documents.example/doc/123/file.pdf'), 'official')
            self.assertNotEqual(app.ref_tier('https://documents.example/doc/1234/file.pdf'), 'official')
            self.assertNotEqual(app.ref_tier('https://documents.example.evil/doc/123/file.pdf'), 'official')

    def test_real_pdf_is_extracted_in_worker_even_without_pdf_suffix(self):
        with patch.object(app, 'fetch', return_value=text_pdf()), patch.object(app, 'send_local_alert') as alert:
            body = app.fetch_body('https://example.jp/download?id=123')
        self.assertIn('Unauthorized access', body)
        self.assertNotIn('%PDF', body)
        alert.assert_not_called()

    def test_bad_pdf_and_timeout_are_logged_without_discord_or_crashing_poll(self):
        for error in (None, subprocess.TimeoutExpired('pdf_extract', 20)):
            with self.subTest(error=error), patch.object(app, 'fetch', return_value=b'%PDF-1.7\nbroken'), \
                 patch.object(app, 'send_local_alert') as alert:
                if error:
                    with patch.object(app.subprocess, 'run', side_effect=error):
                        self.assertEqual(app.fetch_body('https://example.jp/a.pdf'), '')
                else:
                    self.assertEqual(app.fetch_body('https://example.jp/a.pdf'), '')
                alert.assert_not_called()

    def test_http_redirect_base_is_used_for_article_links(self):
        src = {'name': 'Example', 'type': 'official', 'url': 'https://old.example/news/'}
        raw = app.FetchedBytes(b'<a href="notice.html">Security incident disclosure</a>',
                               'https://new.example/announcements/')
        items = app.load_items(src, lambda _: raw)
        self.assertEqual(items[0]['url'], 'https://new.example/announcements/notice.html')


class CollectionCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_patch = patch.object(app, 'DB_PATH', os.path.join(self.temp.name, 'test.db'))
        self.db_patch.start()
        self.addCleanup(self.db_patch.stop)
        self.clock = patch.object(app, 'now_iso', return_value='2026-10-20T00:00:00+00:00')
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.source = {'name': 'Example official', 'type': 'official', 'url': 'https://example.jp/news/'}

    def candidate(self, title='Exampleへの不正アクセスについて', path='notice/20261019.html'):
        return {'title': title, 'url': 'https://example.jp/' + path, 'summary': '',
                'published': '2026-10-19T00:00:00+00:00'}

    def queue(self, rec):
        c = app.db()
        app.queue_for_review(c, self.source['name'], app.item_id(rec['url']), rec)
        c.commit()
        c.close()

    def test_api_failure_keeps_candidates_pending_and_stops_batch(self):
        self.queue(self.candidate())
        self.queue(self.candidate(path='notice/20261020.html'))
        with patch.object(app, 'llm_extract_many', return_value=None) as ai:
            result = app.review_pending(fetch_body_fn=lambda _: 'article')
        self.assertEqual(result, {'total': 2, 'confirmed': 0, 'rejected': 0, 'deferred': 2})
        self.assertEqual(ai.call_count, 1)
        with app.db() as c:
            self.assertEqual(c.execute("SELECT COUNT(*) FROM review_queue WHERE status='pending'").fetchone()[0], 2)

    def test_unreadable_pdf_waits_for_human_without_ai_call(self):
        self.queue(self.candidate(path='notice/20261019.pdf'))
        with patch.object(app, 'llm_extract_many') as ai:
            result = app.review_pending(fetch_body_fn=lambda _: '')
        self.assertEqual(result['deferred'], 1)
        ai.assert_not_called()

    def test_recent_first_disclosure_admits_old_incident_without_redating_it(self):
        rec = self.candidate()
        self.queue(rec)
        evidence = '当社は2026年10月19日に本件を初めて公表しました。'
        finding = {'org': 'Example', 'kind': 'unauthorized access', 'records': None,
                   'incident_date': app.calendar_date_iso(2026, 6, 1), 'is_followup': False,
                   'first_disclosure_date': '2026-10-19', 'disclosure_evidence': evidence}
        with patch.object(app, 'llm_extract_many', return_value=[finding]):
            result = app.review_pending(fetch_body_fn=lambda _: evidence, corroborate_fn=lambda *_: [])
        self.assertEqual(result['confirmed'], 1)
        with app.db() as c:
            app.promote_reviewed(c)
            row = c.execute('SELECT published,disclosed_at FROM incidents').fetchone()
            self.assertEqual(app._incident_day(row['published']), '2026-06-01')
            self.assertEqual(app._incident_day(row['disclosed_at']), '2026-10-19')
        public = app.all_public_incidents()[0]
        self.assertEqual(app._incident_day(public['disclosed_at']), '2026-10-19')

    def test_updated_page_or_invented_disclosure_evidence_cannot_reage_incident(self):
        rec = self.candidate()
        base = {'incident_date': '2026-06-01', 'first_disclosure_date': '2026-10-19'}
        cases = [('更新日2026年10月19日', '更新日2026年10月19日'),
                 ('2026年10月19日に初公表', '本文にはその記載がない'),
                 ('2026年10月18日に初公表', '2026年10月18日に初公表')]
        for evidence, body in cases:
            self.assertIsNone(app.verified_disclosure_date({**base, 'disclosure_evidence': evidence}, rec, body,
                                                          '2026-10-20T00:00:00+00:00'))
        quote = '2026年10月19日に調査結果を公表しました。'
        self.assertIsNone(app.verified_disclosure_date(
            {**base, 'is_followup': True, 'disclosure_evidence': quote}, rec, quote,
            '2026-10-20T00:00:00+00:00'))

    def test_future_first_disclosure_is_rejected(self):
        quote = '2026年10月21日に公表予定です。'
        finding = {'incident_date': '2026-06-01', 'first_disclosure_date': '2026-10-21',
                   'disclosure_evidence': quote}
        self.assertIsNone(app.verified_disclosure_date(finding, self.candidate(), quote,
                                                      '2026-10-20T00:00:00+00:00'))

    def test_empty_or_navigation_only_results_are_recorded_without_discord(self):
        navigation = [{'title': 'ニュース一覧', 'url': 'https://example.jp/news/', 'summary': ''}]
        with patch.object(app, 'load_sources', return_value=[self.source]), \
             patch.object(app, 'load_items', return_value=navigation), \
             patch.object(app, 'send_local_alert') as alert, patch.object(app, 'promote_reviewed', return_value=[]):
            for _ in range(4):
                app.poll()
            alert.assert_not_called()
        with app.db() as c:
            row = c.execute('SELECT * FROM source_health').fetchone()
            self.assertEqual(row['empty_streak'], 4)
            self.assertEqual(row['article_count'], 0)
            self.assertEqual(app.record_source_health(c, self.source, [self.candidate()]), 'ok')
            self.assertEqual(c.execute('SELECT empty_streak FROM source_health').fetchone()[0], 0)

    def test_fetch_error_does_not_count_as_navigation_only_success(self):
        c = app.db()
        for _ in range(4):
            self.assertEqual(app.record_source_health(c, self.source, [], 'HTTP 403'), 'error')
        row = c.execute('SELECT * FROM source_health').fetchone()
        self.assertEqual(row['empty_streak'], 0)
        self.assertIsNone(row['last_success'])
        c.close()

    def run_poll(self, records, body):
        with patch.object(app, 'load_sources', return_value=[self.source]), \
             patch.object(app, 'load_items', return_value=records), \
             patch.object(app, 'send_local_alert'), patch.object(app, 'promote_reviewed', return_value=[]):
            app.poll(fetch_body_fn=body)

    def test_vague_official_notice_is_read_and_queued_for_ai_even_if_previously_skipped(self):
        rec = self.candidate(title='お客様への重要なお知らせとお詫び')
        with app.db() as c:
            c.execute('INSERT INTO skipped VALUES(?)', (app.item_id(rec['url']),))
        self.run_poll([rec], lambda _: '2026年10月19日、Exampleへの不正アクセスが判明しました。')
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM review_queue').fetchone()[0], 1)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM incidents').fetchone()[0], 0)

    def test_notice_body_budget_defers_remaining_items_until_next_cycle(self):
        records = [self.candidate(title='お客様への重要なお知らせとお詫び', path=f'notice/20261019-{i}.html')
                   for i in range(12)]
        calls = []
        def body(url):
            calls.append(url)
            return '臨時営業時間についてのお知らせです。'
        self.run_poll(records, body)
        self.assertEqual(len(calls), 8)
        self.run_poll(records, body)
        self.assertEqual(len(calls), 12)
        self.assertEqual(len(set(calls)), 12)

    def test_failed_notice_body_is_retryable(self):
        rec = self.candidate(title='お客様への重要なお知らせとお詫び')
        self.run_poll([rec], lambda _: '')
        with app.db() as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM notice_checks').fetchone()[0], 0)
            self.assertEqual(c.execute('SELECT COUNT(*) FROM skipped').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
