import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jp_incidents as app
import operations


class IncidentLinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mock = patch.object(app, 'DB_PATH', str(self.root / 'test.db'))
        self.mock.start()
        self.addCleanup(self.mock.stop)
        self.c = app.db()
        self.addCleanup(self.c.close)
        for iid, org, date in [('city', 'Example City', '2026-10-11'),
                               ('provider', 'Example Provider', '2026-10-11'),
                               ('earlier', 'Example City', '2026-09-01'),
                               ('unrelated', 'Example City', '2026-08-01')]:
            self.c.execute("INSERT INTO incidents(id,org,kind,published,title,url,source) VALUES(?,?,?,?,?,?,?)",
                           (iid, org, 'unauthorized access', date, 'Public notice',
                            'https://example.org/' + iid, 'Example'))
        self.c.commit()

    def link(self, a='city', b='provider', kind='affected_by'):
        app.link_incidents(self.c, a, b, kind, 'https://example.org/notice')
        self.c.commit()

    def test_reciprocal_links_survive_rename_without_name_based_grouping(self):
        self.link()
        self.link('city', 'earlier', 'same_organization')
        self.link('earlier', 'city', 'same_organization')
        self.c.execute("UPDATE incidents SET org='Renamed City' WHERE id='city'")
        self.c.commit()
        records = {r['id']: r for r in app.all_public_incidents()}
        self.assertEqual(len(records), 4)
        self.assertEqual(records['unrelated']['related'], [])
        self.assertEqual(records['provider']['related'][0]['relationship'], 'affects')
        self.assertEqual(records['earlier']['related'][0]['incident_id'], 'city')
        self.assertEqual(len(records['city']['related']), 2)
        self.assertEqual(self.c.execute('SELECT COUNT(*) FROM incident_links').fetchone()[0], 2)

    def test_invalid_endpoints_direction_and_withdrawal(self):
        for a, b, kind, url in [('city','city','affected_by','https://example.org/'),
                               ('city','missing','affected_by','https://example.org/'),
                               ('city','provider','unsupported','https://example.org/'),
                               ('city','provider','affected_by','javascript:alert(1)')]:
            with self.assertRaises(ValueError):
                app.link_incidents(self.c, a, b, kind, url)
        self.link()
        with self.assertRaises(ValueError):
            self.link('provider', 'city')
        self.c.execute("UPDATE incidents SET withdrawn=1 WHERE id='provider'")
        self.c.commit()
        self.assertEqual(app.incident_relationships(self.c), {})
        with self.assertRaises(ValueError):
            self.link()
        self.c.execute("UPDATE incidents SET withdrawn=0 WHERE id='provider'")
        self.c.commit()
        self.assertEqual(len(app.incident_relationships(self.c)['city']), 1)
        app.edit_incident_link('city', 'provider', 'affected_by', remove=True)
        self.assertEqual(app.incident_relationships(self.c), {})

    def test_json_rss_and_backup_restore_include_relationships(self):
        self.link()
        output = self.root / 'incidents.json'
        self.assertTrue(app.write_public_json(str(output)))
        self.assertFalse(app.write_public_json(str(output)))
        records = json.loads(output.read_text())['incidents']
        self.assertEqual(next(r for r in records if r['id']=='city')['related'][0]['incident_id'], 'provider')
        feed = self.root / 'feed.xml'
        app.write_public_rss(str(feed))
        self.assertIn('#incident-provider', feed.read_text())
        self.assertIn('Related 1', feed.read_text())
        result = operations.backup(app.DB_PATH, self.root / 'backups')
        restored = operations.restore_backup(result['archive'], self.root / 'restore')
        self.assertEqual(restored['rows']['incident_links'], 1)

    def test_alias_change_updates_json_even_when_visible_records_are_unchanged(self):
        output = self.root / 'incidents.json'
        app.write_public_json(str(output))
        before = json.loads(output.read_text())['incidents']
        self.c.execute("INSERT INTO incident_aliases VALUES(?,?,?,?)",
                       ('retired-id', 'city', '[]', app.now_iso()))
        self.c.commit()
        self.assertTrue(app.write_public_json(str(output)))
        document = json.loads(output.read_text())
        self.assertEqual(document['incidents'], before)
        self.assertEqual(document['aliases'], {'retired-id': 'city'})
        self.assertFalse(app.write_public_json(str(output)))


if __name__ == '__main__':
    unittest.main()
