import contextlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

import incident_categories as categories
import jp_incidents as app


class CategoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "incidents.db"
        self.patch = patch.object(app, "DB_PATH", str(self.path))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def store(self, c, url, org="Example Ltd", types=None, date="2026-10-20"):
        types = types or ["ransomware"]
        rec = {"title": org + " security incident", "summary": "", "url": url, "published": date}
        finding = {"org": org, "kind": categories.primary(types), "categories": types,
                   "records": 42 if "data leak" in types else None, "incident_date": date}
        return app.store(c, "Official notice", rec, finding)

    def test_one_event_keeps_independent_types_across_sources_and_exports(self):
        with contextlib.closing(app.db()) as c, c:
            self.assertTrue(self.store(c, "https://example.org/first"))
            self.assertFalse(self.store(c, "https://example.org/update",
                                        types=["unauthorized access", "data leak"]))
        records = app.all_public_incidents()
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["incident_categories"],
                         ["data leak", "ransomware", "unauthorized access"])
        self.assertEqual(records[0]["potential_records"], 42)
        self.assertEqual(len(app.recent(days=36500, kind="ransomware")), 1)
        feed = Path(self.temp.name) / "feed.xml"
        app.write_public_rss(str(feed), records)
        items = ET.parse(feed).findall("./channel/item")
        self.assertEqual(len(items), 1)
        self.assertEqual(len(items[0].findall("category")), 3)

    def test_repeat_article_does_not_create_category_rows_as_incidents(self):
        with contextlib.closing(app.db()) as c, c:
            self.store(c, "https://example.org/first")
            self.assertFalse(self.store(c, "https://example.org/first",
                                        types=["unauthorized access", "ransomware"]))
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
            iid = app.item_id("https://example.org/first")
            self.assertEqual(categories.get(c, iid), ["ransomware", "unauthorized access"])

    def test_ransomware_is_not_inherited_by_linked_clients(self):
        with contextlib.closing(app.db()) as c, c:
            self.store(c, "https://example.org/provider", "Provider Ltd")
            self.store(c, "https://example.org/client", "Client City", ["other"])
            app.link_incidents(c, app.item_id("https://example.org/client"),
                               app.item_id("https://example.org/provider"), "affected_by",
                               "https://example.org/notice")
        records = {r["organization"]: r for r in app.all_public_incidents()}
        self.assertEqual(records["Provider Ltd"]["incident_categories"], ["ransomware"])
        self.assertEqual(records["Client City"]["incident_categories"], ["other"])

    def test_historical_schema_upgrade_preserves_evidence(self):
        with contextlib.closing(app.db()) as c, c:
            self.store(c, "https://example.org/notice", types=["data leak"])
            c.execute("ALTER TABLE incident_categories RENAME TO new_categories")
            c.execute(categories.TABLE.replace(",'ransomware'", ""))
            c.execute("INSERT INTO incident_categories SELECT * FROM new_categories")
            c.execute("DROP TABLE new_categories")
            before = [tuple(r) for r in c.execute("SELECT * FROM incident_categories")]
            categories.install(c)
            self.assertEqual([tuple(r) for r in c.execute("SELECT * FROM incident_categories")], before)
            categories.save(c, app.item_id("https://example.org/notice"), ["ransomware"],
                            "https://example.org/confirmed")
            categories.install(c)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incident_categories").fetchone()[0], 2)

    def test_explicit_type_correction_replaces_old_tags(self):
        with contextlib.closing(app.db()) as c, c:
            self.store(c, "https://example.org/notice")
        iid = app.item_id("https://example.org/notice")
        app.edit_incident(iid, "correct", "Source confirms a DDoS incident, not ransomware.",
                          {"kind": "other"})
        self.assertEqual(app.all_public_incidents()[0]["incident_categories"], ["other"])

    def test_search_and_heuristic_recognize_ransomware_variants(self):
        sources = app.public_sources()
        self.assertTrue(any(s["name"] == "Bing ランサムウェア" for s in sources))
        for word in ["ランサムウェア", "ランサムウエア", "身代金要求型ウイルス", "ransomware"]:
            with self.subTest(word=word):
                rec = {"title": f"株式会社テスト、{word}による被害を公表", "summary": "Cyber incident in Japan",
                       "url": "https://example.org/incident", "published": "2026-10-20"}
                self.assertIsNotNone(app.RANSOMWARE_RE.search(rec["title"]))
                self.assertTrue(app.gate(rec, {"name": "Example"}))
                with patch.object(app, "resolve_url", side_effect=lambda u: u):
                    result = app.classify(rec, {"name": "Example"},
                                          fetch_body_fn=lambda _: rec["title"],
                                          enforce_window=False, use_ai=False)
                self.assertIn("ransomware", result["categories"])

    def test_other_remains_valid_and_combined_type_is_rejected(self):
        self.assertEqual(categories.normalize(["other"]), ["other"])
        for invalid in [["unauthorized access and data leak"], ["ransomware and data leak"], []]:
            with self.assertRaises(ValueError):
                categories.normalize(invalid)

    def test_source_supported_other_is_preserved_with_named_categories(self):
        with contextlib.closing(app.db()) as c, c:
            self.store(c, "https://example.org/ddos", types=["other"])
            self.store(c, "https://example.org/update", types=["data leak"])
        self.assertEqual(app.all_public_incidents()[0]["incident_categories"],
                         ["data leak", "other"])

    def test_one_article_supports_multiple_victims_and_events(self):
        with contextlib.closing(app.db()) as c, c:
            shared = {"title": "Two incidents", "summary": "", "url": "https://example.org/report",
                      "published": "2026-10-20"}
            app.queue_for_review(c, "Official", "q", shared)
            findings = [
                {"org": "First City", "kind": "ransomware", "categories": ["ransomware", "data leak"],
                 "records": None, "incident_date": "2026-10-19"},
                {"org": "Second City", "kind": "other", "records": None, "incident_date": "2026-10-20"},
                {"org": "First City", "kind": "other", "records": None, "incident_date": "2026-10-20"},
            ]
            c.execute("UPDATE review_queue SET status='confirmed',decision_json=? WHERE id='q'",
                      (json.dumps({"record": shared, "classifications": findings}),))
            c.commit()
            app.promote_reviewed(c)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 3)
            self.assertEqual(c.execute("SELECT COUNT(*) FROM refs WHERE url=?", (shared["url"],)).fetchone()[0], 3)


if __name__ == "__main__":
    unittest.main()
