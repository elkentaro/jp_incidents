"""Stable per-incident activity times for the public index."""
import json
from datetime import datetime, timezone

_ACTIVITY_FIELDS = {"added_at", "updated_at"}


def _timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _content(value):
    """Compare public content without counting list reordering as an update."""
    if isinstance(value, dict):
        return {key: _content(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((_content(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value


def stamp_incidents(incidents, previous, observed_at):
    """Stamp additions/public changes; retain unknown dates in legacy snapshots.

    Times describe when changes enter the public index, not the incident date or
    an internal review. Unchanged exports never advance an incident's timestamp.
    """
    stamp = _timestamp(observed_at)
    if stamp is None:
        raise ValueError("Activity timestamp must include a timezone")
    old_rows = previous.get("incidents", []) if isinstance(previous, dict) else []
    old_by_id = {row["id"]: row for row in old_rows if isinstance(row, dict) and "id" in row}
    result = []
    for incident in incidents:
        row = {key: value for key, value in incident.items() if key not in _ACTIVITY_FIELDS}
        old = old_by_id.get(row["id"])
        if old is None:
            added = updated = stamp
        else:
            added = _timestamp(old.get("added_at"))
            updated = _timestamp(old.get("updated_at")) or added
            old_content = {key: value for key, value in old.items() if key not in _ACTIVITY_FIELDS}
            if _content(row) != _content(old_content):
                updated = stamp
        result.append(dict(row, added_at=added, updated_at=updated))
    return result
