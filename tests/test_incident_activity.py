import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import incident_activity as activity
import jp_incidents as app


class IncidentActivityTests(unittest.TestCase):
    added = '2026-10-20T12:00:00+00:00'
    later = '2026-10-24T12:00:00+00:00'

    def row(self):
        return {'id': 'one', 'published_at': '2020-01-01', 'organization': 'Example',
                'sources': [{'url': 'https://example.org/notice', 'name': 'Example'}],
                'related': [], 'incident_categories': ['data leak', 'ransomware']}

    def stamp(self, rows, old=None, at=None):
        return activity.stamp_incidents(rows, old, at or self.later)

    def test_old_incident_newly_added_to_index_is_recent(self):
        result = self.stamp([self.row()])[0]
        self.assertEqual(result['added_at'], self.later)
        self.assertEqual(result['updated_at'], self.later)
        self.assertEqual(result['published_at'], '2020-01-01')

    def test_no_change_or_reordering_preserves_activity(self):
        old = {'incidents': self.stamp([self.row()], at=self.added)}
        row = self.row()
        row['incident_categories'].reverse()
        result = self.stamp([row], old)[0]
        self.assertEqual(result['added_at'], self.added)
        self.assertEqual(result['updated_at'], self.added)

    def test_public_changes_advance_only_updated_time(self):
        old = {'incidents': self.stamp([self.row()], at=self.added)}
        changes = [
            {'sources': []}, {'potential_records': 12}, {'organization': 'Corrected'},
            {'related': [{'incident_id': 'two', 'relationship': 'affects'}]},
            {'incident_categories': ['data leak']}, {'service_aliases': ['Former name']},
        ]
        for change in changes:
            with self.subTest(change=change):
                result = self.stamp([dict(self.row(), **change)], old)[0]
                self.assertEqual(result['added_at'], self.added)
                self.assertEqual(result['updated_at'], self.later)
        self.assertEqual(old['incidents'][0]['updated_at'], self.added)

    def test_legacy_unknown_dates_are_not_fabricated(self):
        old = {'incidents': [self.row()]}
        result = self.stamp([self.row()], old)[0]
        self.assertIsNone(result['added_at'])
        self.assertIsNone(result['updated_at'])
        changed = self.stamp([dict(self.row(), organization='Corrected')], old)[0]
        self.assertIsNone(changed['added_at'])
        self.assertEqual(changed['updated_at'], self.later)

    def test_restore_is_a_new_public_addition(self):
        old = {'incidents': self.stamp([self.row()], at=self.added)}
        removed = {'incidents': self.stamp([], old)}
        self.assertEqual(self.stamp([self.row()], removed)[0]['added_at'], self.later)

    def test_export_is_stable_and_tracks_source_changes(self):
        rows = [self.row()]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app, 'all_public_incidents', side_effect=lambda: copy.deepcopy(rows)), \
                patch.object(app, 'public_incident_aliases', return_value={}), \
                patch.object(app, 'now_iso', return_value=self.added) as clock:
            path = str(Path(directory) / 'incidents.json')
            self.assertTrue(app.write_public_json(path))
            clock.return_value = self.later
            before = Path(path).read_bytes()
            self.assertFalse(app.write_public_json(path))
            self.assertEqual(Path(path).read_bytes(), before)
            rows[0]['sources'].append({'url': 'https://example.org/update', 'name': 'Update'})
            self.assertTrue(app.write_public_json(path))
            result = json.loads(Path(path).read_text())['incidents'][0]
            self.assertEqual(result['added_at'], self.added)
            self.assertEqual(result['updated_at'], self.later)
            self.assertFalse(app.write_public_json(path))


if __name__ == '__main__':
    unittest.main()
