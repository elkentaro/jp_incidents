import hashlib
import sqlite3
import unittest
import reference_copies as copies


class ReferenceCopiesTests(unittest.TestCase):
    def setUp(self):
        self.c = sqlite3.connect(':memory:')
        self.c.row_factory = sqlite3.Row
        self.c.execute('CREATE TABLE refs(incident_id,url,source,title,UNIQUE(incident_id,url))')
        self.addCleanup(self.c.close)

    def add(self, url, iid='event'):
        self.c.execute('INSERT INTO refs VALUES(?,?,?,?)', (iid, url, 'News', 'Same headline'))
        return url

    def result(self, iid='event', protected=()):
        rows=self.c.execute('SELECT * FROM refs WHERE incident_id=? ORDER BY rowid',(iid,)).fetchall()
        return [r['url'] for r in copies.public_references(self.c,iid,rows,protected=protected)]

    def proof(self, a, b, method='editorial_verified', iid='event'):
        return copies.record(self.c,iid,a,b,method,hashlib.sha256(b'checked sources').hexdigest(),'2026-11-02')

    def test_publisher_variants_choose_original_without_deleting_private_links(self):
        gallery=self.add('https://newsdig.tbs.co.jp/articles/gallery/123')
        network=self.add('https://newsdig.tbs.co.jp/articles/-/123?display=1')
        original=self.add('https://newsdig.tbs.co.jp/articles/cbc/123?display=1')
        self.assertEqual(self.result(),[original])
        self.assertEqual(self.c.execute('SELECT count(*) FROM refs').fetchone()[0],3)

    def test_same_headline_and_same_incident_do_not_prove_syndication(self):
        a=self.add('https://first.example/story');b=self.add('https://second.example/story')
        self.assertEqual(self.result(),[a,b])
        self.assertFalse(self.proof(a,b,'qwen_facts'))
        self.assertFalse(self.proof(a,b,'qwen_source_support'))
        self.assertEqual(self.result(),[a,b])

    def test_confirmed_distribution_copy_prefers_publisher_even_if_arrives_later(self):
        mirror=self.add('https://news.yahoo.co.jp/articles/abc')
        original=self.add('https://newsdig.tbs.co.jp/articles/cbc/123')
        self.assertTrue(self.proof(original,mirror,'syndicated_local'))
        self.assertEqual(self.result(),[original])

    def test_new_article_ids_and_lookalike_hosts_stay_separate(self):
        urls=[self.add(u) for u in ('https://newsdig.tbs.co.jp/articles/cbc/123',
            'https://newsdig.tbs.co.jp/articles/cbc/124',
            'https://newsdig.tbs.co.jp.evil.example/articles/cbc/123')]
        self.assertEqual(self.result(),urls)

    def test_proof_is_event_scoped_and_does_not_hide_other_official_releases(self):
        a=self.add('https://first.example/story');b=self.add('https://second.example/story')
        self.add(a,'other');self.add(b,'other');self.proof(a,b)
        self.assertEqual(self.result('other'),[a,b])
        self.assertEqual(self.result(protected=[a]),[a,b])

    def test_removed_representative_restores_remaining_source_and_drops_stale_proof(self):
        a=self.add('https://first.example/story');b=self.add('https://second.example/story');self.proof(a,b)
        self.c.execute('DELETE FROM refs WHERE url=?',(b,))
        self.assertEqual(self.result(),[a])
        self.assertEqual(self.c.execute('SELECT count(*) FROM reference_copies').fetchone()[0],0)
        self.add(b);self.assertEqual(self.result(),[a,b])

    def test_chains_cycles_are_bounded_and_stable(self):
        urls=[self.add('https://example.org/'+str(i)) for i in range(3)]
        self.proof(urls[0],urls[1]);self.proof(urls[1],urls[2]);self.proof(urls[2],urls[0])
        self.assertEqual(self.result(),[urls[0]])

    def test_unavailable_proof_table_does_not_modify_database(self):
        self.add('https://example.org/a');before=list(self.c.iterdump());self.result()
        self.assertEqual(list(self.c.iterdump()),before)

    def test_proof_requires_both_accepted_urls_and_valid_digest(self):
        a=self.add('https://example.org/a')
        self.assertFalse(self.proof(a,'https://missing.example/b'))
        self.assertFalse(copies.record(self.c,'event',a,a,'exact','bad','today'))


if __name__=='__main__':unittest.main()
