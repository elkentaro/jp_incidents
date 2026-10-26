import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PIL import Image

import linkage_map as module

BASE = Path(__file__).resolve().parents[1]


class LinkageMapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'linkage.template.html').write_text((BASE/'linkage.template.html').read_text())
        self.now = datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc)
        self.document = {'updated_at': self.now.isoformat(), 'incidents': [
            {'id':'SECRET_A', 'organization':'PRIVATE_ORGANIZATION', 'related':[
                {'incident_id':'SECRET_B','relationship':'affects','evidence_url':'https://private.example/evidence'},
                {'incident_id':'SECRET_B','relationship':'affects'},
                {'incident_id':'WITHDRAWN','relationship':'affects'}]},
            {'id':'SECRET_B','title':'PRIVATE_TITLE','sources':[{'url':'https://private.example/source'}],
             'related':[{'incident_id':'SECRET_A','relationship':'affected_by'},
                        {'incident_id':'SECRET_C','relationship':'same_organization'}]},
            {'id':'SECRET_C','related':[{'incident_id':'SECRET_B','relationship':'same_organization'}]},
            {'id':'SECRET_D','related':[]} ]}
        self.source = self.root/'input.json'
        self.source.write_text(json.dumps(self.document))

    def test_direction_deduplication_and_only_visible_endpoints(self):
        nodes, edges = module.topology(self.document)
        self.assertEqual(edges, [(0, 1, 'affects'), (1, 2, 'same_organization')])
        neighbors, roles, downstream, counts = module.describe(nodes, edges)
        self.assertEqual(counts, dict(incidents=4, linked=3, unlinked=1, links=2, networks=1))
        self.assertEqual(roles, {0:'upstream', 1:'downstream', 2:'related', 3:'unlinked'})

    def test_standalone_nodes_share_map_without_invented_connections(self):
        for document in [self.document, dict(self.document, incidents=[{'id':str(i)} for i in range(20)])]:
            nodes, edges = module.topology(document)
            original_edges = list(edges)
            neighbors, roles, downstream, counts = module.describe(nodes, edges)
            positions = module.layout(nodes, edges, neighbors, downstream)
            self.assertEqual(set(positions), set(nodes))
            self.assertEqual(len(set(positions.values())), len(nodes))
            self.assertEqual(edges, original_edges)
            for node in nodes:
                if roles[node] == 'unlinked':
                    self.assertFalse(neighbors[node])
                    self.assertFalse(any(node in (a, b) for a, b, kind in edges))

    def test_identity_fields_never_reach_rendering_or_outputs(self):
        nodes, edges = module.topology(self.document)
        encoded = json.dumps([nodes, edges])
        self.assertNotIn('SECRET', encoded)
        changed = copy.deepcopy(self.document)
        for row in changed['incidents']:
            row.update(organization='DIFFERENT_ORGANIZATION', title='DIFFERENT_TITLE', sources=[])
        self.assertEqual(module.topology(changed), (nodes, edges))
        self.assertTrue(module.refresh(self.source, self.root, self.now))
        image = Image.open(self.root/'data/linkage-map.png')
        self.assertEqual(image.info, {})
        self.assertEqual(dict(image.getexif()), {})
        self.assertEqual(image.size, (2400, 1440))
        metadata = json.loads((self.root/'data/linkage-map.json').read_text())
        self.assertEqual(set(metadata), {'version','generated_at','source_updated_at','counts','image_sha256','page_sha256'})
        for name in module.OUTPUTS:
            content = (self.root/name).read_bytes()
            for secret in [b'SECRET', b'PRIVATE', b'private.example', b'WITHDRAWN']:
                self.assertNotIn(secret, content)

    def test_refresh_24_hour_boundary_preserves_caption_between_updates(self):
        self.assertTrue(module.refresh(self.source, self.root, self.now))
        first = {name:(self.root/name).read_bytes() for name in module.OUTPUTS}
        with patch.object(module, 'render', side_effect=AssertionError('Unexpected regeneration')):
            self.assertFalse(module.refresh(self.source, self.root, self.now+timedelta(hours=24, microseconds=-1)))
        self.assertEqual(first, {name:(self.root/name).read_bytes() for name in module.OUTPUTS})
        self.assertTrue(module.refresh(self.source, self.root, self.now+timedelta(hours=24)))
        page = (self.root/'linkage.html').read_text()
        self.assertIn('2026-10-27 00:00 UTC', page)
        self.assertNotIn('2026-10-26 00:00 UTC', page)

    def test_missing_or_corrupt_image_repairs_before_next_deadline(self):
        module.refresh(self.source, self.root, self.now)
        (self.root/'data/linkage-map.png').write_bytes(b'broken')
        self.assertTrue(module.refresh(self.source, self.root, self.now+timedelta(minutes=10)))
        Image.open(self.root/'data/linkage-map.png').verify()

    def test_invalid_source_does_not_replace_previous_snapshot(self):
        module.refresh(self.source, self.root, self.now)
        before = {name:(self.root/name).read_bytes() for name in module.OUTPUTS}
        self.source.write_text('{invalid')
        with self.assertRaises(ValueError):
            module.refresh(self.source, self.root, self.now+timedelta(days=1))
        self.assertEqual(before, {name:(self.root/name).read_bytes() for name in module.OUTPUTS})

    def test_image_has_no_language_specific_text(self):
        from PIL import ImageDraw
        nodes, edges = module.topology(self.document)
        original = ImageDraw.ImageDraw.text
        def reference_only(draw, position, text, *args, **kwargs):
            self.assertEqual(text, module.SITE_URL)
            return original(draw, position, text, *args, **kwargs)
        with patch.object(ImageDraw.ImageDraw, 'text', autospec=True, side_effect=reference_only) as drawing:
            png, counts = module.render(nodes, edges, self.now)
        self.assertEqual(drawing.call_count, 1)
        Image.open(io.BytesIO(png)).verify()

    def test_cycles_and_empty_graph_render(self):
        for document in [dict(self.document, incidents=[]),
                         dict(self.document, incidents=[{'id':'a','related':[{'incident_id':'b','relationship':'affects'}]},
                                                       {'id':'b','related':[{'incident_id':'a','relationship':'affects'}]}])]:
            nodes, edges = module.topology(document)
            png, counts = module.render(nodes, edges, self.now)
            Image.open(io.BytesIO(png)).verify()
            self.assertEqual(counts['incidents'], len(nodes))

    def test_duplicate_ids_are_rejected(self):
        self.document['incidents'].append(self.document['incidents'][0])
        with self.assertRaises(ValueError):
            module.topology(self.document)


if __name__ == '__main__':
    unittest.main()
