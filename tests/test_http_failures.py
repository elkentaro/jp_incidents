"""Broken HTTP responses must not stop unrelated source collection."""
import http.client
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import jp_incidents as app


def response(url, body=None, error=None):
    result = MagicMock()
    result.__enter__.return_value = result
    result.url = url
    result.read.return_value = body
    result.read.side_effect = error
    return result


class HttpFailureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        for patcher in (
            patch.object(app, "DB_PATH", str(Path(temp.name) / "test.db")),
            patch.dict(os.environ, {"JPI_EXPECTED_403_SOURCES": "", "JPI_FETCH_BODY": "1"}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def assert_later_source_collected(self, error):
        sources = [
            {"name": "Broken source", "type": "rss", "url": "https://broken.example/feed"},
            {"name": "Healthy source", "type": "rss", "url": "https://healthy.example/feed"},
        ]
        article_url = "https://healthy.example/notice.html"
        feed = (f'<rss><channel><item><title>Example株式会社への不正アクセス</title>'
                f'<link>{article_url}</link><description>調査中</description>'
                '</item></channel></rss>').encode()
        responses = {
            sources[0]["url"]: response(sources[0]["url"], error=error),
            sources[1]["url"]: response(sources[1]["url"], feed),
            article_url: response(article_url, b"<p>Article evidence</p>"),
        }
        with patch.object(app, "load_sources", return_value=sources), \
                patch.object(app, "promote_reviewed", return_value=[]), \
                patch.object(app.urllib.request, "urlopen", side_effect=lambda req, **kw: responses[req.full_url]), \
                patch.object(app, "send_local_alert") as alert:
            self.assertEqual(app.poll(fetch_body_fn=app.fetch_body), [])
        with sqlite3.connect(app.DB_PATH) as connection:
            runs = connection.execute("SELECT source,fetched,error FROM runs ORDER BY rowid").fetchall()
            self.assertEqual(len(runs), 2)
            self.assertEqual(runs[0][:2], ("Broken source", 0))
            self.assertIn(type(error).__name__, runs[0][2])
            self.assertEqual(runs[1], ("Healthy source", 1, None))
            self.assertEqual(connection.execute("SELECT url,status FROM review_queue").fetchall(),
                             [(article_url, "pending")])
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
            health = connection.execute("SELECT error,last_success FROM source_health WHERE url=?",
                                        (sources[0]["url"],)).fetchone()
            self.assertIn(str(error), health[0])
            self.assertIsNone(health[1])
        alert.assert_called_once()
        self.assertEqual(alert.call_args.args[0], "source-errors")
        self.assertIn("Broken source", alert.call_args.args[2])
        self.assertNotIn("Healthy source", alert.call_args.args[2])
        self.assertEqual(alert.call_args.kwargs["severity"], "warning")

    def test_incomplete_listing_does_not_stop_later_sources(self):
        self.assert_later_source_collected(http.client.IncompleteRead(b"unfinished feed"))

    def test_invalid_http_status_does_not_stop_later_sources(self):
        self.assert_later_source_collected(http.client.BadStatusLine("invalid status"))

    def test_broken_advertised_feed_preserves_official_homepage_items(self):
        source = {"name": "Example", "type": "official", "url": "https://example.jp/"}
        homepage = ('<link rel="alternate" type="application/rss+xml" href="feed.xml">'
                    '<a href="notice.html">不正アクセスについて</a>').encode()

        def fetcher(url):
            if url == source["url"]:
                return homepage
            raise http.client.IncompleteRead(b"unfinished feed")

        items = app.load_items(source, fetcher)
        self.assertEqual([item["url"] for item in items], ["https://example.jp/notice.html"])

    def test_broken_tdnet_pages_do_not_discard_other_days(self):
        source = {"url": "https://example.jp/tdnet/"}
        index = b'I_list_001_20261104.html I_list_001_20261103.html'
        notice = ('<tr><td class="kjName">Example株式会社</td>'
                  '<td class="kjTitle"><a href="notice.pdf">不正アクセスについて</a></td></tr>').encode()
        for failed_page in ("I_list_001_20261104.html", "I_list_002_20261104.html"):
            with self.subTest(failed_page=failed_page):
                def fetcher(url):
                    if url.endswith(failed_page):
                        raise http.client.IncompleteRead(b"unfinished page")
                    if url.endswith("I_list_001_20261104.html"):
                        return b'I_list_002_20261104.html'
                    return notice

                with patch.dict(os.environ, {"JPI_TDNET_DAYS": "2"}):
                    items = app.load_tdnet_items(index, source, fetcher)
                self.assertEqual([item["url"] for item in items], ["https://example.jp/tdnet/notice.pdf"])

    def test_network_probe_tries_next_endpoint_after_invalid_status(self):
        with patch.object(app.urllib.request, "urlopen", side_effect=[
            http.client.BadStatusLine("invalid status"), response("https://healthy.example/")
        ]) as open_url:
            self.assertTrue(app.network_ready(["https://broken.example/", "https://healthy.example/"]))
        self.assertEqual(open_url.call_count, 2)

    def test_incomplete_corroboration_does_not_supply_evidence(self):
        def fetcher(url):
            raise http.client.IncompleteRead(b"unfinished evidence feed")

        self.assertEqual(app.corroborate_finding({"org": "Example株式会社"}, {}, fetcher), [])

    def test_partial_article_response_is_never_used_as_evidence(self):
        for url in ("https://example.jp/notice.html", "https://example.jp/notice.pdf"):
            with self.subTest(url=url), patch.object(app.urllib.request, "urlopen", return_value=response(
                url, error=http.client.IncompleteRead(b"partial article evidence")
            )):
                body = app.fetch_body(url)
            self.assertEqual(str(body), "")
            if url.endswith(".pdf"):
                self.assertTrue(body.problem)


if __name__ == "__main__":
    unittest.main()
