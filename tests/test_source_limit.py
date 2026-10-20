import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jp_incidents as core


class SourceLimitTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        setting = patch.object(core, "DB_PATH", str(Path(temp.name) / "test.db"))
        setting.start()
        self.addCleanup(setting.stop)
        self.c = core.db()
        self.addCleanup(self.c.close)
        self.date = core.now_iso()

    def store(self, org, url, kind="unauthorized access"):
        rec = dict(url=url, title=org + " disclosure", published=self.date, summary="")
        cl = dict(org=org, kind=kind, records=None, incident_date=self.date)
        return core.store(self.c, "Example", rec, cl)

    def test_six_sources_per_event_and_new_category_evidence_survives_cap(self):
        for index in range(8):
            self.store("Example Ltd", f"https://example.jp/{index}")
        iid = self.c.execute("SELECT id FROM incidents").fetchone()[0]
        self.assertEqual(core.confirmed_source_count(self.c, iid), 6)
        url = "https://example.jp/new-ransomware-fact"
        self.store("Example Ltd", url, "ransomware")
        self.assertIn("ransomware", core.categories.get(self.c, iid))
        self.assertIn(url, self.c.execute(
            "SELECT evidence_json FROM incident_categories WHERE category='ransomware'"
        ).fetchone()[0])
        self.assertEqual(core.confirmed_source_count(self.c, iid), 6)
        self.store("Affected Customer", "https://customer.jp/notice")
        customer = self.c.execute("SELECT id FROM incidents WHERE org='Affected Customer'").fetchone()[0]
        self.assertEqual(core.confirmed_source_count(self.c, customer), 1)

    def test_historical_references_survive_and_further_additions_stop(self):
        self.store("Example Ltd", "https://example.jp/first")
        iid = self.c.execute("SELECT id FROM incidents").fetchone()[0]
        for index in range(8):
            self.c.execute("INSERT INTO refs VALUES(?,?,?,?)",
                           (iid, f"https://legacy.jp/{index}", "Legacy", "Disclosure"))
        self.assertFalse(core.add_reference(self.c, iid, "https://new.jp", "New", "Disclosure"))
        self.assertEqual(core.confirmed_source_count(self.c, iid), 9)

    def test_duplicate_does_not_consume_slot_and_db_backfill_cannot_exceed_cap(self):
        self.store("Example Ltd", "https://example.jp/first")
        iid = self.c.execute("SELECT id FROM incidents").fetchone()[0]
        self.assertFalse(core.add_reference(self.c, iid, "https://example.jp/first", "Example", "First"))
        for index in range(5):
            self.assertTrue(core.add_reference(self.c, iid, f"https://example.jp/{index}", "Example", "Report"))
        self.c.execute("UPDATE incidents SET url='https://example.jp/missing-original'")
        self.c.commit()
        reopened = core.db()
        try:
            self.assertEqual(core.confirmed_source_count(reopened, iid), 6)
        finally:
            reopened.close()


if __name__ == "__main__":
    unittest.main()
