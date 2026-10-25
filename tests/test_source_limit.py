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

    def saturated(self):
        for i in range(6):self.store('Example Ltd', f'https://news.example/{i}')
        return self.c.execute('SELECT id FROM incidents').fetchone()[0]

    def test_verified_victim_release_bypasses_cap_and_sorts_first(self):
        iid=self.saturated()
        proof={'issuer':'Example Ltd','evidence_quote':'Example Ltd: Our company reports unauthorized access.'}
        url='https://prtimes.jp/main/html/rd/p/000000001.html'
        self.assertTrue(core.add_reference(self.c,iid,url,'PR TIMES','Official notice',official_release=proof))
        self.assertFalse(core.add_reference(self.c,iid,url,'PR TIMES','Official notice',official_release=proof))
        self.assertEqual(core.confirmed_source_count(self.c,iid),7)
        self.assertEqual(core.ordered_references(self.c,iid)[0]['url'],url)
        self.assertFalse(core.add_reference(self.c,iid,'https://news.example/extra','News','Follow-up'))
        self.c.commit()
        self.assertEqual(core.all_public_incidents()[0]['sources'][0]['url'],url)

    def test_unproven_release_and_other_issuer_cannot_bypass_cap(self):
        iid=self.saturated()
        for url in ('https://prtimes.jp/main/html/rd/p/1.html','https://news.example/press/notice',
                    'https://www.release.tdnet.info.evil.example/inbs/123.pdf'):
            self.assertFalse(core.add_reference(self.c,iid,url,'JPX TDnet','Example Ltd: disclosure',
                official_release={'issuer':'Different Ltd','evidence_quote':'Different Ltd issues this release.'}))
        self.assertEqual(core.confirmed_source_count(self.c,iid),6)

    def test_tdnet_requires_collector_issuer_to_match_victim(self):
        iid=self.saturated()
        source=core.DISCLOSURE_SOURCES[0]['name']
        url='https://www.release.tdnet.info/inbs/140120261026123456.pdf'
        self.assertFalse(core.add_reference(self.c,iid,url,source,'Supplier Ltd：Incident notice'))
        self.assertTrue(core.add_reference(self.c,iid,url,source,'Example Ltd：Incident notice'))
        self.assertEqual(core.ordered_references(self.c,iid)[0]['url'],url)

    def test_authority_is_per_victim_and_deleted_with_reference(self):
        iid=self.saturated()
        url='https://issuer.example/notice'
        proof={'issuer':'Example Ltd','evidence_quote':'Example Ltd issued this notice.'}
        core.add_reference(self.c,iid,url,'Issuer','Notice',official_release=proof)
        self.c.execute('DELETE FROM refs WHERE incident_id=? AND url=?',(iid,url))
        self.assertFalse(core.reference_is_official(self.c,iid,url))

    def test_configured_release_host_is_not_a_first_party_domain(self):
        import source_authority
        source={'name':'Example Ltd','type':'official','url':'https://prtimes.jp/company/1'}
        self.assertFalse(source_authority.collected_issuer('https://prtimes.jp/company/2/release',
            'PR TIMES','Another issuer notice','Example Ltd',[source]))


if __name__ == "__main__":
    unittest.main()
