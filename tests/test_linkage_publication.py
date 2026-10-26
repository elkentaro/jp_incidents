"""Test daily map integration with the real publisher and mocked Git commands."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import jp_incidents as core
import linkage_map

ROOT = Path(__file__).resolve().parents[1]


class LinkagePublicationTests(unittest.TestCase):
    def test_daily_artifacts_share_publication_commit_and_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'data').mkdir()
            (root/'linkage.template.html').write_text((ROOT/'linkage.template.html').read_text())
            source = root/'data/incidents.json'
            document = {'updated_at':'2026-10-26T00:00:00+00:00','incidents':[]}
            calls = []
            def write_json(path):
                Path(path).write_text(json.dumps(document))
                return True
            def git(args, cwd, check=True):
                calls.append(args)
                if args[:2] == ['rev-parse','--show-toplevel']:
                    return SimpleNamespace(stdout=str(root), returncode=0)
                if args[0] == 'status':
                    return SimpleNamespace(stdout=' M linkage.html', returncode=0)
                if args[0] == 'rev-list':
                    return SimpleNamespace(stdout='0', returncode=0)
                return SimpleNamespace(stdout='', returncode=0)
            with patch.object(core, 'write_public_json', side_effect=write_json), \
                 patch.object(core, 'write_public_rss', return_value=False), \
                 patch.object(core, 'write_public_sources', return_value=False), \
                 patch.object(core.ops, 'get_state', return_value=None), \
                 patch.object(core, '_run_git', side_effect=git), \
                 patch.dict(os.environ, {'JPI_LINKAGE_MAP':'1'}), \
                 contextlib.redirect_stdout(io.StringIO()):
                def publish():
                    return core.publish_public_json(str(source), str(root/'feed.xml'), str(root/'data/sources.json'))
                self.assertTrue(publish())
                expected = {'data/incidents.json','feed.xml','data/sources.json', *linkage_map.OUTPUTS}
                add = next(args for args in calls if args[0] == 'add')
                self.assertEqual(set(add[2:]), expected)
                commit = next(args for args in calls if args[0] == 'commit')
                self.assertEqual(set(commit[commit.index('--')+1:]), expected)
                before = (root/'data/linkage-map.png').read_bytes()
                calls.clear()
                with patch.object(linkage_map, 'render', side_effect=AssertionError('Do not redraw before 24 hours')):
                    publish()
                self.assertEqual((root/'data/linkage-map.png').read_bytes(), before)
                calls.clear()
                with patch.object(linkage_map, 'refresh', side_effect=ValueError('Invalid graph input')):
                    with self.assertRaises(ValueError):
                        publish()
                self.assertFalse(any(args[0] in {'add','commit','push'} for args in calls))

    def test_disabled_renderer_leaves_existing_publication_available(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(args, cwd, check=True):
                return SimpleNamespace(stdout=str(root) if args[0] == 'rev-parse' else '0' if args[0] == 'rev-list' else '', returncode=0)
            with patch.object(core, 'write_public_json', return_value=False), \
                 patch.object(core, 'write_public_rss', return_value=False), \
                 patch.object(core, 'write_public_sources', return_value=False), \
                 patch.object(core.ops, 'get_state', return_value=None), \
                 patch.object(core, '_run_git', side_effect=git), \
                 patch.dict(os.environ, {'JPI_LINKAGE_MAP':'0'}), \
                 patch.object(linkage_map, 'refresh', side_effect=AssertionError('Renderer disabled')), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(core.publish_public_json(str(root/'data/incidents.json'), str(root/'feed.xml'), str(root/'data/sources.json')))


if __name__ == '__main__':
    unittest.main()
