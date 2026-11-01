"""Runtime source transport changes reach default listing and polling calls."""
import unittest
from unittest.mock import Mock, patch
import jp_incidents as core


class FetchRoutingTests(unittest.TestCase):
    def test_default_listing_uses_current_fetch_and_explicit_override_wins(self):
        source={'url':'https://example.jp/news','type':'official','name':'Example'}
        response=core.FetchedBytes(b'<html><body></body></html>',source['url'])
        runtime=Mock(return_value=response)
        explicit=Mock(return_value=response)
        with patch.object(core,'fetch',runtime):
            core.load_items(source)
            runtime.assert_called_once_with(source['url'])
            core.load_items(source,fetcher=explicit)
            explicit.assert_called_once_with(source['url'])
            self.assertEqual(runtime.call_count,1)

    def test_poller_passes_current_fetch_to_listings(self):
        runtime=Mock()
        with patch.object(core,'fetch',runtime),patch.object(core,'db'), \
                patch.object(core,'promote_reviewed',return_value=[]), \
                patch.object(core,'load_sources',return_value=[{'name':'Fixture','url':'https://example.jp/'}]), \
                patch.object(core,'load_items',side_effect=KeyboardInterrupt) as load:
            with self.assertRaises(KeyboardInterrupt):core.poll()
            self.assertIs(load.call_args.args[1],runtime)
