import json
import os
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET

import jp_incidents as app


class StaticPublishingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.DB_PATH
        app.DB_PATH = os.path.join(self.temp.name, "test.db")
        connection = app.db()
        connection.execute(
            "INSERT INTO incidents(id,source,title,url,summary,published,first_seen,org,kind,records,score,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "incident-1", "東京都 / Tokyo Metropolitan Government", "個人情報の漏えいについて",
                "https://www.metro.tokyo.lg.jp/example", "", "2026-10-19T00:00:00+00:00",
                "2026-10-19T00:01:00+00:00", "Example Organization", "data leak", 1200, 60, "high",
            ),
        )
        connection.execute(
            "INSERT INTO refs(incident_id,url,source,title) VALUES(?,?,?,?)",
            (
                "incident-1", "https://www.metro.tokyo.lg.jp/example",
                "東京都 / Tokyo Metropolitan Government", "個人情報の漏えいについて",
            ),
        )
        connection.commit()
        connection.close()

    def tearDown(self):
        app.DB_PATH = self.old_db
        self.temp.cleanup()

    def test_json_and_rss_are_complete_and_stable(self):
        json_path = os.path.join(self.temp.name, "data", "incidents.json")
        rss_path = os.path.join(self.temp.name, "feed.xml")

        self.assertTrue(app.write_public_json(json_path))
        self.assertTrue(app.write_public_rss(rss_path))
        self.assertFalse(app.write_public_json(json_path))
        self.assertFalse(app.write_public_rss(rss_path))

        with open(json_path, encoding="utf-8") as source:
            document = json.load(source)
        self.assertEqual(document["total"], 1)
        self.assertEqual(document["incidents"][0]["potential_records"], 1200)
        self.assertEqual(len(document["incidents"][0]["sources"]), 1)

        items = ET.parse(rss_path).findall("./channel/item")
        self.assertEqual(len(items), 1)
        self.assertIn("Example Organization", items[0].findtext("title"))


class MunicipalSourceTests(unittest.TestCase):
    def test_discovers_feed_and_same_site_homepage_items(self):
        homepage = (
            '<html><head><link rel="alternate" type="application/rss+xml" href="/news.xml"></head>'
            '<body><a href="/notice">情報漏えいのお知らせ</a>'
            '<a href="https://outside.example/ignored">不正アクセス</a></body></html>'
        ).encode()
        feed = (
            "<rss><channel><item><title>不正アクセスについて</title>"
            "<link>https://example.jp/feed-item</link></item></channel></rss>"
        ).encode()

        def fetcher(url):
            return homepage if url == "https://example.jp/" else feed

        items = app.load_items(
            {"name": "Example city", "type": "municipal", "url": "https://example.jp/"}, fetcher
        )
        self.assertEqual({item["url"] for item in items}, {
            "https://example.jp/feed-item", "https://example.jp/notice"
        })

    def test_health_and_environment_titles_are_noise(self):
        source = {"name": "Official", "type": "municipal", "url": "https://example.jp/"}
        for title in ("インフルエンザウイルス感染症", "ワクチン予防接種", "アスベストの漏えい"):
            record = {"title": title, "summary": "", "url": "https://example.jp/a"}
            self.assertFalse(app.gate(record, source), title)

    def test_verified_municipal_domains_are_government_tier(self):
        self.assertEqual(app.ref_tier("https://www.city.kumamoto.jp/example"), "gov")
        self.assertEqual(app.ref_tier("https://www.city.shibuya.tokyo.jp/example"), "gov")
        self.assertEqual(len(app.MUNICIPAL_SOURCES), 44)


if __name__ == "__main__":
    unittest.main()
