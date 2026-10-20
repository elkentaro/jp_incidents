"""Independent categories for a single incident, with source provenance."""
import json
from datetime import datetime, timezone

# Ordering chooses a legacy primary type, not an incident's severity.
RANK = {"other": 0, "unauthorized access": 1, "ransomware": 2, "data leak": 3}
TABLE = """CREATE TABLE incident_categories(
    incident_id TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('data leak','unauthorized access','ransomware','other')),
    evidence_json TEXT NOT NULL, created_at TEXT NOT NULL,
    PRIMARY KEY(incident_id,category))"""


def normalize(values=None, kind=None):
    if values is None:
        values = [kind]
    if not isinstance(values, list) or not values or any(v not in RANK for v in values):
        raise ValueError("Supply valid independent incident categories")
    return sorted(set(values))


def primary(values):
    return max(normalize(values), key=RANK.get)


def install(connection):
    """Upgrade the historical table without losing categories or provenance."""
    found = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='incident_categories'"
    ).fetchone()
    if found is None:
        connection.execute(TABLE)
    elif "'ransomware'" not in found[0]:
        connection.execute("ALTER TABLE incident_categories RENAME TO incident_categories_previous")
        connection.execute(TABLE)
        connection.execute("INSERT INTO incident_categories SELECT * FROM incident_categories_previous")
        connection.execute("DROP TABLE incident_categories_previous")
    connection.execute(
        "INSERT OR IGNORE INTO incident_categories "
        "SELECT id,kind,'[]',COALESCE(first_seen,'') FROM incidents i "
        "WHERE kind IN ('data leak','unauthorized access','ransomware','other') "
        "AND NOT EXISTS(SELECT 1 FROM incident_categories c WHERE c.incident_id=i.id)"
    )
    for statement in [
        "CREATE TABLE IF NOT EXISTS incident_aliases(old_id TEXT PRIMARY KEY,canonical_id TEXT NOT NULL,evidence_json TEXT NOT NULL,created_at TEXT NOT NULL,CHECK(old_id!=canonical_id))",
        "CREATE TABLE IF NOT EXISTS incident_annotations(incident_id TEXT PRIMARY KEY,affected_system TEXT,date_basis TEXT,impact_note TEXT,evidence_json TEXT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS incident_link_evidence(incident_id TEXT NOT NULL,related_id TEXT NOT NULL,relationship TEXT NOT NULL,evidence_url TEXT NOT NULL,PRIMARY KEY(incident_id,related_id,relationship,evidence_url))",
    ]:
        connection.execute(statement)


def get(connection, incident_id, fallback="other"):
    rows = connection.execute(
        "SELECT category FROM incident_categories WHERE incident_id=? ORDER BY category", (incident_id,)
    ).fetchall()
    return [row[0] for row in rows] or normalize(kind=fallback)


def save(connection, incident_id, values, evidence_url=None, replace=False):
    values = normalize(values)
    if replace:
        connection.execute("DELETE FROM incident_categories WHERE incident_id=?", (incident_id,))
    now = datetime.now(timezone.utc).isoformat()
    for category in values:
        old = connection.execute(
            "SELECT evidence_json FROM incident_categories WHERE incident_id=? AND category=?",
            (incident_id, category),
        ).fetchone()
        evidence = set(json.loads(old[0]) if old else [])
        if evidence_url:
            evidence.add(evidence_url)
        connection.execute(
            "INSERT INTO incident_categories VALUES(?,?,?,?) "
            "ON CONFLICT(incident_id,category) DO UPDATE SET evidence_json=excluded.evidence_json",
            (incident_id, category, json.dumps(sorted(evidence)), now),
        )
    categories = get(connection, incident_id)
    connection.execute("UPDATE incidents SET kind=? WHERE id=?", (primary(categories), incident_id))
    return categories
