"""Per-incident issuer provenance, separate from heuristic confidence tiers.

The caller must verify a release against the full source and the event before
passing a proof. A hosting platform or a notice-like URL alone is not proof.
"""
import re
import unicodedata
from urllib.parse import urlsplit


SCHEMA = """
CREATE TABLE IF NOT EXISTS reference_authority(
 incident_id TEXT NOT NULL, url TEXT NOT NULL, issuer TEXT NOT NULL,
 evidence_quote TEXT NOT NULL, PRIMARY KEY(incident_id,url));
CREATE TRIGGER IF NOT EXISTS reference_authority_cleanup AFTER DELETE ON refs
BEGIN DELETE FROM reference_authority WHERE incident_id=OLD.incident_id AND url=OLD.url; END;
"""


def identity(value):
    value = unicodedata.normalize('NFKC', value or '').casefold()
    value = re.sub(r'株式会社|有限会社|合同会社|\b(?:incorporated|corporation|limited|inc|corp|ltd)\b', '', value)
    return re.sub(r'[^\w]', '', value)


def matches(issuer, org):
    # Exact full-name equality, allowing bilingual labels and corporate suffixes.
    return bool(identity(issuer)) and any(identity(issuer) == identity(part)
                                         for part in (org or '').split(' / '))


def valid_proof(proof, org):
    return (isinstance(proof, dict) and isinstance(proof.get('issuer'), str)
            and matches(proof['issuer'], org)
            and isinstance(proof.get('evidence_quote'), str)
            and 1 <= len(proof['evidence_quote'].strip()) <= 1200)


def needs_issuer_review(url, title, text):
    """Conservative routing hint, never an authorization to bypass the cap."""
    parsed = urlsplit(url)
    host = (parsed.hostname or '').removeprefix('www.')
    return (host in {'release.tdnet.info', 'prtimes.jp', 'atpress.ne.jp', 'dreamnews.jp'}
            or bool(re.search(r'/(?:press|release|notice|ir)(?:/|\.)', parsed.path, re.I))
            or bool(re.search(r'プレスリリース|ニュースリリース|お詫び|ご報告|お知らせ|press release|会社名\s|当社|弊社|当法人|当組合|当院|当学|本市|当市|当県|our (?:company|organization)|we (?:have |recently )?(?:detected|discovered|identified|confirmed)',
                              title+'\n'+text, re.I)))


def collected_issuer(url, source, title, org, sources):
    """Recognize issuer metadata from configured first-party/disclosure collectors."""
    parsed = urlsplit(url)
    if parsed.scheme not in {'https', 'http'} or parsed.username or parsed.password:
        return False
    host = (parsed.hostname or '').removeprefix('www.')
    for entry in sources:
        if entry.get('type') == 'tdnet':
            if (host == 'release.tdnet.info' and re.fullmatch(r'/inbs/\d+\.pdf', parsed.path)
                    and source == entry['name']):
                issuer = re.split(r'[:：]', title or '', maxsplit=1)[0]
                if matches(issuer, org):
                    return True
            continue
        if entry.get('type') not in {'official', 'municipal', 'json_news'}:
            continue
        if host in {'release.tdnet.info', 'prtimes.jp', 'atpress.ne.jp', 'dreamnews.jp'}:
            continue  # A shared release host is never a first-party domain.
        if host != (urlsplit(entry['url']).hostname or '').removeprefix('www.'):
            continue
        if any(matches(name, org) for name in entry['name'].split(' / ')):
            return True
    return False
