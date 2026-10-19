import json
import os
import sqlite3
import tempfile
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

import jp_incidents as app


class StaticPublishingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_db = app.DB_PATH
        app.DB_PATH = os.path.join(self.temp.name, "test.db")
        published = app.now_iso()
        self.published_day = datetime.fromisoformat(published).astimezone(app.JST).date().isoformat()
        connection = app.db()
        connection.execute(
            "INSERT INTO incidents(id,source,title,url,summary,published,first_seen,org,kind,records,score,confidence) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "incident-1", "東京都 / Tokyo Metropolitan Government", "個人情報の漏えいについて",
                "https://www.metro.tokyo.lg.jp/example", "", published,
                published, "Example Organization", "data leak", 1200, 60, "high",
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
        self.assertEqual(document["schema_version"], 2)
        self.assertEqual(document["total"], 1)
        self.assertEqual(document["incidents"][0]["potential_records"], 1200)
        self.assertEqual(len(document["incidents"][0]["sources"]), 1)
        self.assertEqual(len(document["daily_counts_90d"]), 90)
        self.assertEqual(sum(day["count"] for day in document["daily_counts_90d"]), 1)
        self.assertEqual(document["date_range"], {"start": self.published_day, "end": self.published_day})

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
        for title in (
            "インフルエンザウイルス感染症", "ワクチン予防接種", "アスベストの漏えい",
            "船舶からの重油流出", "スポンサー契約のお知らせ",
        ):
            record = {"title": title, "summary": "", "url": "https://example.jp/a"}
            self.assertFalse(app.gate(record, source), title)

    def test_verified_municipal_domains_are_government_tier(self):
        self.assertEqual(app.ref_tier("https://www.city.kumamoto.jp/example"), "gov")
        self.assertEqual(app.ref_tier("https://www.city.shibuya.tokyo.jp/example"), "gov")
        self.assertEqual(len(app.MUNICIPAL_SOURCES), 44)

    def test_transport_registry_is_official_and_covers_every_mode(self):
        sectors = {source["sector"] for source in app.TRANSPORT_SOURCES}
        self.assertTrue({"rail", "air", "airport", "bus", "ferry", "taxi", "parent"} <= sectors)
        self.assertGreaterEqual(len(app.TRANSPORT_SOURCES), 90)
        self.assertEqual(app.ref_tier("https://www.jreast.co.jp/example"), "official")

    def test_prefectural_national_and_disclosure_registries(self):
        self.assertEqual(len(app.PREFECTURAL_SOURCES), 46)
        self.assertEqual(len(app.NATIONAL_SOURCES), 10)
        self.assertEqual(len(app.DISCLOSURE_SOURCES), 1)
        self.assertEqual(app.ref_tier("https://www.pref.aichi.jp/example"), "gov")
        self.assertEqual(app.ref_tier("https://www.release.tdnet.info/example.pdf"), "official")

    def test_tdnet_reads_incident_disclosures_and_ignores_financial_filings(self):
        main = b'<option value="I_list_001_20261019.html">2026/10/19</option>'
        daily = (
            '<div id="kaiji-date-1">2026年10月19日</div><table>'
            '<tr><td class="kjTime">17:05</td><td class="kjName">Ｇ－Example</td>'
            '<td class="kjTitle"><a href="incident.pdf">不正アクセスに関するご報告</a></td></tr>'
            '<tr><td class="kjTime">16:00</td><td class="kjName">Finance</td>'
            '<td class="kjTitle"><a href="results.pdf">決算短信</a></td></tr></table>'
        ).encode()

        def fetcher(url):
            return main if url.endswith("I_main_00.html") else daily

        items = app.load_items(app.DISCLOSURE_SOURCES[0], fetcher)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "Example：不正アクセスに関するご報告")
        self.assertTrue(items[0]["url"].endswith("incident.pdf"))

    def test_public_source_directory_matches_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sources.json")
            self.assertTrue(app.write_public_sources(path))
            self.assertFalse(app.write_public_sources(path))
            with open(path, encoding="utf-8") as source:
                document = json.load(source)
        self.assertEqual(document["total"], len(app.SOURCES))
        self.assertEqual(document["groups"]["prefecture"], 46)
        self.assertEqual(document["groups"]["transport"], len(app.TRANSPORT_SOURCES))

    def test_readme_lists_every_public_source(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        sources = app.public_sources()
        self.assertIn(f"**{len(sources)} configured sources**", readme)
        for source in sources:
            self.assertIn(f"[{source['name']}]({source['url']})", readme)


if __name__ == "__main__":
    unittest.main()
