"""Render an anonymous, daily PNG snapshot from the public incident JSON only.

Requires Pillow >= 10.2. No database, network, browser, or private admin imports.
"""
import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import tempfile

VERSION = 6
SITE_URL = 'https://elkentaro.github.io/jp_incidents/'
OUTPUTS = ('data/linkage-map.png', 'linkage.html', 'data/linkage-map.json')
COLORS = {'upstream': '#d55e00', 'downstream': '#0072b2', 'both': '#008568',
          'related': '#525b63', 'unlinked': '#873fb0'}


def instant(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('Snapshot dates must include a timezone')
    return result.astimezone(timezone.utc)


def topology(document):
    """Discard identity-bearing fields before layout or rendering."""
    records = document['incidents']
    if not isinstance(records, list):
        raise ValueError('incidents must be a list')
    ids = [r['id'] for r in records]
    if any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids):
        raise ValueError('Incident IDs must be distinct nonempty strings')
    aliases = {value: index for index, value in enumerate(sorted(ids))}
    edges = set()
    for record in records:
        for link in record.get('related', []):
            if link['incident_id'] not in aliases:
                continue  # A withdrawn/missing endpoint is never drawn.
            a, b = aliases[record['id']], aliases[link['incident_id']]
            kind = link['relationship']
            if a == b:
                continue
            if kind == 'affected_by':
                a, b, kind = b, a, 'affects'
            if kind in {'same_organization', 'same_event'}:
                a, b = sorted((a, b))
            elif kind != 'affects':
                continue
            edges.add((a, b, kind))
    return list(range(len(ids))), sorted(edges)


def describe(nodes, edges):
    neighbors = {i: set() for i in nodes}
    upstream, downstream = Counter(), Counter()
    for a, b, kind in edges:
        neighbors[a].add(b)
        neighbors[b].add(a)
        if kind == 'affects':
            downstream[a] += 1
            upstream[b] += 1
    roles = {i: ('both' if upstream[i] and downstream[i] else
                 'upstream' if downstream[i] else 'downstream' if upstream[i] else
                 'related' if neighbors[i] else 'unlinked') for i in nodes}
    visited, networks = set(), 0
    for node in nodes:
        if not neighbors[node] or node in visited:
            continue
        networks += 1
        stack = [node]
        while stack:
            item = stack.pop()
            if item in visited:
                continue
            visited.add(item)
            stack.extend(neighbors[item] - visited)
    return neighbors, roles, downstream, dict(incidents=len(nodes), linked=len(visited),
        unlinked=len(nodes)-len(visited), links=len(edges), networks=networks)


def layout(nodes, edges, neighbors, downstream):
    """Pack radial networks and standalone incidents into the same map."""
    parents = defaultdict(set)
    for a, b, kind in edges:
        if kind == 'affects':
            parents[b].add(a)
    satellites = defaultdict(list)
    owned = set()
    for node in nodes:
        if parents[node] and not downstream[node]:
            parent = min(parents[node], key=lambda p: (-downstream[p], p))
            satellites[parent].append(node)
            owned.add(node)
    clusters = []
    for node in nodes:
        if node in owned:
            continue
        children = sorted(satellites[node])
        radius = max(48, len(children)*13/(2*math.pi)) if children else 0
        points = {node: (0, 0)}
        for index, child in enumerate(children):
            angle = -math.pi/2 + 2*math.pi*index/len(children)
            points[child] = (radius*math.cos(angle), radius*math.sin(angle))
        clusters.append((radius+15, node, points))
    placed, positions = [], {}
    for radius, node, points in sorted(clusters, key=lambda c: (-c[0], c[1])):
        for step in range(100000):
            distance = 6*math.sqrt(step)
            angle = step*math.pi*(3-math.sqrt(5))
            x, y = distance*math.cos(angle), distance*math.sin(angle)
            if all(math.hypot(x-px, y-py) >= radius+pr+14 for px, py, pr in placed):
                break
        else:
            x, y = max((px+pr for px, py, pr in placed), default=0)+radius+14, 0
        placed.append((x, y, radius))
        positions.update({i: (x+px, y+py) for i, (px, py) in points.items()})
    return positions


def render(nodes, edges, now):
    from PIL import Image, ImageDraw, ImageFont
    neighbors, roles, downstream, counts = describe(nodes, edges)
    positions = layout(nodes, edges, neighbors, downstream)
    width, height = 2400, 1440
    image = Image.new('RGB', (width, height), '#fafbf8')
    draw = ImageDraw.Draw(image)
    if positions:
        xs, ys = zip(*positions.values())
        scale = min(2110/max(max(xs)-min(xs), 1), 1220/max(max(ys)-min(ys), 1), 6)
        mx, my = (max(xs)+min(xs))/2, (max(ys)+min(ys))/2
        positions = {i: (1200+(x-mx)*scale, 720+(y-my)*scale) for i, (x, y) in positions.items()}
        radii = {i: min(20, max(12, 5*scale)) if downstream[i] else min(10, max(6, 3.5*scale)) for i in positions}
        for a, b, kind in edges:
            ax, ay = positions[a]; bx, by = positions[b]
            distance = math.hypot(bx-ax, by-ay)
            if distance == 0:
                continue
            ux, uy = (bx-ax)/distance, (by-ay)/distance
            start = (ax+ux*radii[a], ay+uy*radii[a])
            end = (bx-ux*(radii[b]+2), by-uy*(radii[b]+2))
            draw.line((*start, *end), fill='#a9b5bb', width=2)
        for i, (x, y) in positions.items():
            r = radii[i]
            draw.ellipse((x-r, y-r, x+r, y+r), fill=COLORS[roles[i]], outline='#fafbf8', width=2)
    draw.text((width-48, height-40), SITE_URL, anchor='rs',
              font=ImageFont.load_default(size=24), fill='#65736d')
    buffer = io.BytesIO()
    image.save(buffer, format='PNG', optimize=True)  # No identity or text metadata.
    return buffer.getvalue(), counts


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.'+path.name, suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def refresh(source, root, now=None, force=False):
    root, source = Path(root), Path(source)
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError('now must be timezone-aware')
    now = now.astimezone(timezone.utc)
    png_path, page_path, metadata_path = (root/p for p in OUTPUTS)
    try:
        previous = json.loads(metadata_path.read_text())
        age = now-instant(previous['generated_at'])
        intact = all(hashlib.sha256(p.read_bytes()).hexdigest() == previous[key]
                     for p, key in [(png_path, 'image_sha256'), (page_path, 'page_sha256')])
        if not force and previous['version'] == VERSION and timedelta(0) <= age < timedelta(hours=24) and intact:
            return False
    except (OSError, ValueError, TypeError, KeyError):
        pass
    document = json.loads(source.read_text())
    data_updated = instant(document['updated_at']).isoformat()
    nodes, edges = topology(document)
    png, counts = render(nodes, edges, now)
    stamp = now.isoformat()
    template = (root/'linkage.template.html').read_text()
    replacements = dict(generated_at=stamp, updated_display=now.strftime('%Y-%m-%d %H:%M UTC'),
                        data_updated=data_updated, **{k: str(v) for k, v in counts.items()})
    for key, value in replacements.items():
        template = template.replace('{{'+key+'}}', value)
    if '{{' in template:
        raise ValueError('Unresolved linkage page template token')
    page = template.encode()
    metadata = dict(version=VERSION, generated_at=stamp, source_updated_at=data_updated, counts=counts,
                    image_sha256=hashlib.sha256(png).hexdigest(), page_sha256=hashlib.sha256(page).hexdigest())
    atomic_write(png_path, png)
    atomic_write(page_path, page)
    atomic_write(metadata_path, (json.dumps(metadata, indent=2)+'\n').encode())
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--force', action='store_true')
    args = parser.parse_args()
    changed = refresh(args.source or args.root/'data/incidents.json', args.root, force=args.force)
    print('Linkage snapshot refreshed' if changed else 'Linkage snapshot is less than 24 hours old')
