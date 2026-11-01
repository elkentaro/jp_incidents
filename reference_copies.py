"""Select one public link per proven report; retain every private reference.

Text similarity alone is not proof. Call record() only after a complete-source
comparison establishes a copy with no new facts, or an editorial confirmation.
No source text or copy metadata is included in the public result.
"""
import re
from urllib.parse import urlsplit


def publisher_key(url):
    """Known article identities, never a generic path/query heuristic."""
    parsed = urlsplit(url)
    if parsed.hostname == 'newsdig.tbs.co.jp':
        match = re.fullmatch(r'/articles/(?:-|gallery|[a-z][a-z0-9_-]*)/(\d+)/?', parsed.path)
        if match:
            return 'newsdig:' + match[1]
    return None


def install(c):
    # Individual statements preserve the caller's transaction.
    c.execute('''CREATE TABLE IF NOT EXISTS reference_copies(
        incident_id TEXT NOT NULL,url TEXT NOT NULL,original_url TEXT NOT NULL,
        method TEXT NOT NULL,proof_hash TEXT NOT NULL,created_at TEXT NOT NULL,
        PRIMARY KEY(incident_id,url,original_url))''')
    c.execute('''CREATE TRIGGER IF NOT EXISTS reference_copies_cleanup
        AFTER DELETE ON refs BEGIN DELETE FROM reference_copies
        WHERE incident_id=OLD.incident_id AND (url=OLD.url OR original_url=OLD.url); END''')


def record(c, incident_id, url, original_url, method, proof_hash, created_at):
    if method not in {'exact', 'syndicated', 'syndicated_local', 'editorial_verified'}:
        return False
    if url == original_url or not re.fullmatch(r'[0-9a-f]{64}', proof_hash):
        return False
    if c.execute('SELECT count(*) FROM refs WHERE incident_id=? AND url IN (?,?)',
                 (incident_id, url, original_url)).fetchone()[0] != 2:
        return False
    install(c)
    c.execute('INSERT OR REPLACE INTO reference_copies VALUES(?,?,?,?,?,?)',
              (incident_id, url, original_url, method, proof_hash, created_at))
    return True


def preference(ref, position):
    parsed = urlsplit(ref['url'])
    distributor = parsed.hostname in {'news.yahoo.co.jp', 'news.livedoor.com',
                                      'news.goo.ne.jp', 'news.infoseek.co.jp', 'www.excite.co.jp'}
    # Prefer the broadcaster's article page, then the network page, then gallery.
    variant = 0
    if parsed.hostname == 'newsdig.tbs.co.jp':
        variant = 2 if '/gallery/' in parsed.path else 1 if '/-/' in parsed.path else 0
    return (distributor, variant, position)


def public_references(c, incident_id, refs, *, protected=()):
    """Read only, event scoped, deterministic, and safe if the proof table is absent."""
    refs = [dict(r) for r in refs]
    protected = set(protected)
    roots = {r['url']: r['url'] for r in refs}

    def root(url):
        while roots[url] != url:
            roots[url] = roots[roots[url]]
            url = roots[url]
        return url

    def join(a, b):
        if a in roots and b in roots and a not in protected and b not in protected:
            roots[root(b)] = root(a)

    keys = {}
    for ref in refs:
        key = publisher_key(ref['url'])
        if key:
            if key in keys:
                join(keys[key], ref['url'])
            else:
                keys[key] = ref['url']
    preferred = set()
    if c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='reference_copies'").fetchone():
        for a, b in c.execute('SELECT url,original_url FROM reference_copies WHERE incident_id=?', (incident_id,)):
            join(a, b)
            if a in roots and b in roots:
                preferred.add(b)
    groups = {}
    for position, ref in enumerate(refs):
        groups.setdefault(root(ref['url']), []).append((position, ref))
    result = []
    for group in groups.values():
        # Publisher/original preference only chooses among already proven copies.
        position, chosen = min(group, key=lambda pair: (
            *preference(pair[1], pair[0])[:2],
            pair[1]['url'] not in preferred, pair[0]))
        result.append((min(p for p, _ in group), chosen))
    return [ref for _, ref in sorted(result, key=lambda pair: pair[0])]
