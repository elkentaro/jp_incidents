"""Evidence-backed affected-service scopes, separate from organization identity."""
import json,re,unicodedata
from urllib.parse import urlsplit

SCHEMA="""CREATE TABLE IF NOT EXISTS incident_service_scopes(
 incident_id TEXT PRIMARY KEY,service_name TEXT NOT NULL,service_key TEXT NOT NULL,
 aliases_json TEXT NOT NULL DEFAULT '[]',evidence_json TEXT NOT NULL DEFAULT '[]');
 CREATE INDEX IF NOT EXISTS incident_service_name ON incident_service_scopes(service_key);"""

def key(value):
    return re.sub(r'[\s\u3000・･.,，。()（）「」『』:：/＿_\-]+','',unicodedata.normalize('NFKC',str(value or '')).casefold())

def name(value):
    if value in (None,''):return None
    if not isinstance(value,str) or len(value)>120 or any(ord(c)<32 for c in value):raise ValueError('Enter an affected service name of up to 120 characters.')
    value=' '.join(unicodedata.normalize('NFKC',value).split())
    if not key(value) or key(value) in {'service','system','services','systems','サービス','システム','不明','unknown','none'}:raise ValueError('Name the specific affected service, not a generic system label.')
    return value

def install(c):
    # Execute individual statements; never commit the caller's transaction.
    for statement in SCHEMA.split(';'):
        if statement.strip():c.execute(statement)

def available(c):return bool(c.execute("SELECT 1 FROM sqlite_master WHERE name='incident_service_scopes'").fetchone())
def read_all(c):
    if not available(c):return {}
    return {r[0]:dict(affected_service=r[1],service_aliases=json.loads(r[2])) for r in c.execute('SELECT incident_id,service_name,aliases_json FROM incident_service_scopes')}
def get(c,iid):
    if not available(c):return {}
    row=c.execute('SELECT service_name,aliases_json FROM incident_service_scopes WHERE incident_id=?',(iid,)).fetchone()
    return dict(affected_service=row[0],service_aliases=json.loads(row[1])) if row else {}
def names(record):return [v for v in [record.get('affected_service'),*record.get('service_aliases',[])] if v]
def matches(record,value):return bool(key(value) and any(key(v)==key(value) for v in names(record)))

def save(c,iid,value,url,quote='',*,alias=False):
    value=name(value)
    if not value:return
    parsed=urlsplit(url)
    if parsed.scheme not in {'https','http'} or not parsed.hostname or parsed.username or parsed.password:raise ValueError('A service scope needs a public source URL.')
    if not c.execute('SELECT 1 FROM incidents WHERE id=? AND withdrawn=0',(iid,)).fetchone():raise ValueError('Affected service requires an active incident.')
    install(c)
    row=c.execute('SELECT service_name,aliases_json,evidence_json FROM incident_service_scopes WHERE incident_id=?',(iid,)).fetchone()
    primary=row[0] if row else value;aliases=json.loads(row[1]) if row else [];evidence=json.loads(row[2]) if row else []
    if row and key(value)!=key(primary) and not any(key(v)==key(value) for v in aliases):
        if not alias:raise ValueError('Different affected services need separate incident records.')
        aliases.append(value)
    proof=dict(service=value,url=url,quote=str(quote or '')[:1000])
    if proof not in evidence:evidence.append(proof)
    c.execute('INSERT INTO incident_service_scopes VALUES(?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET service_name=excluded.service_name,service_key=excluded.service_key,aliases_json=excluded.aliases_json,evidence_json=excluded.evidence_json',
              (iid,primary,key(primary),json.dumps(aliases,ensure_ascii=False),json.dumps(evidence,ensure_ascii=False)))

def label(org,service=None):return str(org)+((' : '+service) if service else '')
