"""Runtime source transport changes reach default listing and polling calls."""
import unittest
from unittest.mock import Mock, patch
import jp_incidents as core


class FetchRoutingTests(unittest.TestCase):
    def test_cybersecurity_news_listing_only_collects_article_urls(self):
        source=next(s for s in core.SOURCES if s['url']=='https://cybersecurity-jp.com/news')
        page='''<html><body>
            <a href="/news/123456"><img src="image.png" alt=""></a>
            <a href="/news/123456">Example company reports unauthorized access</a>
            <a href="/news/123456">Repeated article title</a>
            <a href="/news/123457">Another company discloses a data leak</a>
            <a href="/news/page/2">Next news page</a>
            <a href="/column/123456">Security advice</a>
            <a href="https://cybersecurity-jp.com.attacker.example/news/123456">Unrelated site</a>
            </body></html>'''
        items=core.load_items(source,lambda _:page.encode())
        self.assertEqual([r['url'] for r in items],['https://cybersecurity-jp.com/news/123456','https://cybersecurity-jp.com/news/123457'])
        self.assertEqual(items[0]['title'],'Example company reports unauthorized access')
        self.assertTrue(all(r['outlet']=='Cybersecurity.jp news' for r in items))
        # Feed and HTML discoveries retain the same URL identity for queue deduplication.
        feed=core.parse_feed(b'<rss><channel><item><title>Feed title</title><link>https://cybersecurity-jp.com/news/123456</link></item></channel></rss>')
        self.assertEqual(core.item_id(items[0]['url']),core.item_id(feed[0]['url']))

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
