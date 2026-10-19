"""Portable operational helpers. Runtime state and backups are private."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone


SCHEMA = """
CREATE TABLE IF NOT EXISTS ops_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alert_outbox(key TEXT PRIMARY KEY,payload TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ai_usage(day TEXT PRIMARY KEY,requests INTEGER NOT NULL,tokens INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS article_versions(url TEXT PRIMARY KEY,fingerprint TEXT,body_hash TEXT,checked_at TEXT);
CREATE TABLE IF NOT EXISTS incident_changes(
 id INTEGER PRIMARY KEY,incident_id TEXT NOT NULL,action TEXT NOT NULL,before_json TEXT NOT NULL,
 after_json TEXT NOT NULL,note TEXT NOT NULL,created_at TEXT NOT NULL);
"""


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def connect(path):
    c = sqlite3.connect(path, timeout=10)
    c.executescript(SCHEMA)
    return c


def set_state(path, key, value):
    with contextlib.closing(connect(path)) as c, c:
        c.execute('INSERT OR REPLACE INTO ops_state VALUES(?,?)', (key, json.dumps(value)))


def get_state(path, key, default=None):
    with contextlib.closing(connect(path)) as c:
        row = c.execute('SELECT value FROM ops_state WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default


@contextlib.contextmanager
def lock(path, scope):
    target = Path(str(path) + '.' + scope + '.lock')
    with target.open('a') as handle:
        os.chmod(target, 0o600)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class BudgetLimit(RuntimeError):
    pass


def reserve_request(path, payload):
    """Reserve a conservative UTF-8 byte bound plus maximum output tokens before I/O."""
    tokens = len(json.dumps(payload, ensure_ascii=False).encode()) + int(payload['max_tokens'])
    day = datetime.now(timezone.utc).date().isoformat()
    with contextlib.closing(connect(path)) as c, c:
        c.execute('BEGIN IMMEDIATE')
        row = c.execute('SELECT requests,tokens FROM ai_usage WHERE day=?', (day,)).fetchone() or (0, 0)
        if row[0] >= int(os.environ.get('JPI_AI_DAILY_REQUEST_LIMIT', '200')):
            raise BudgetLimit('Daily AI request limit reached; candidates remain pending')
        if row[1] + tokens > int(os.environ.get('JPI_AI_DAILY_TOKEN_LIMIT', '2000000')):
            raise BudgetLimit('Daily AI token reservation limit reached; candidates remain pending')
        c.execute('INSERT OR REPLACE INTO ai_usage VALUES(?,?,?)', (day, row[0]+1, row[1]+tokens))


def queue_alert(path, key, payload):
    with contextlib.closing(connect(path)) as c, c:
        c.execute('INSERT INTO alert_outbox VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET payload=excluded.payload',
                  (key, json.dumps(payload), now()))


def restore_backup(archive, destination):
    """Restore into a NEW private directory, never over the live database."""
    destination = Path(destination)
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    allowed = {'database.sqlite', 'manifest.json', 'config.env', 'alert-state.json',
               'collector.service', 'collector.timer', 'alerts.service', 'alerts.timer',
               'backup.service', 'backup.timer', 'watchdog.service', 'watchdog.timer'}
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)) or any(not m.isfile() or m.name not in allowed for m in members):
            raise ValueError('Invalid backup members')
        for member in members:
            if member.size > 1_000_000_000:
                raise ValueError('Oversized backup member')
            with tar.extractfile(member) as source, (destination/member.name).open('wb') as target:
                shutil.copyfileobj(source, target)
            os.chmod(destination/member.name, 0o600)
    manifest = json.loads((destination/'manifest.json').read_text())
    if set(manifest['sha256']) != set(names) - {'manifest.json'}:
        raise ValueError('Backup manifest membership mismatch')
    for name, checksum in manifest['sha256'].items():
        if hashlib.sha256((destination/name).read_bytes()).hexdigest() != checksum:
            raise ValueError('Backup checksum mismatch')
    with contextlib.closing(sqlite3.connect(destination/'database.sqlite')) as c:
        if c.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Restored database integrity check failed')
        for table, count in manifest['rows'].items():
            if table not in {'incidents', 'refs', 'review_queue', 'manual_reviews', 'incident_changes'}:
                raise ValueError('Invalid backup table')
            if c.execute('SELECT COUNT(*) FROM '+table).fetchone()[0] != count:
                raise ValueError('Restored row counts differ')
    return manifest


def backup(path, directory, files=None):
    directory = Path(directory)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    target = directory/('backup-'+stamp+'.tar.gz')
    with tempfile.TemporaryDirectory(dir=directory) as work:
        stage = Path(work)
        snapshot = stage/'database.sqlite'
        with contextlib.closing(sqlite3.connect(path, timeout=30)) as source, \
             contextlib.closing(sqlite3.connect(snapshot)) as dest:
            source.backup(dest)
            rows = {table: dest.execute('SELECT COUNT(*) FROM '+table).fetchone()[0]
                    for table in ('incidents','refs','review_queue','manual_reviews','incident_changes')}
        for name, source in (files or {}).items():
            if Path(source).is_file():
                shutil.copyfile(source, stage/name)
        manifest = {'created_at': now(), 'rows': rows, 'sha256': {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in stage.iterdir()}}
        (stage/'manifest.json').write_text(json.dumps(manifest))
        temporary = stage/'archive.tar.gz'
        with tarfile.open(temporary, 'w:gz') as tar:
            for name in [*manifest['sha256'], 'manifest.json']:
                tar.add(stage/name, arcname=name)
        restore_backup(temporary, stage/'restore-test')
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    # Only prune after a new snapshot has passed its restore test.
    keep = max(2, int(os.environ.get('JPI_BACKUP_KEEP', '30')))
    for old in sorted(directory.glob('backup-*.tar.gz'), reverse=True)[keep:]:
        old.unlink()
    result = {'completed_at': now(), 'archive': str(target), 'restore_test': 'passed', 'off_host': False}
    set_state(path, 'backup', result)
    repo = os.environ.get('JPI_BACKUP_RESTIC_REPOSITORY')
    if repo:
        env = dict(os.environ, RESTIC_REPOSITORY=repo)
        # restic encrypts before transfer; credentials remain in local environment files.
        done = subprocess.run(['restic', 'backup', str(target), '--tag', 'jp-incidents'],
                              env=env, capture_output=True, timeout=900)
        if done.returncode:
            raise RuntimeError('Encrypted backup upload failed; local verified snapshot retained')
        result['off_host'] = True
        set_state(path, 'backup', result)
    return result
