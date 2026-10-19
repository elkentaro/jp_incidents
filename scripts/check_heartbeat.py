"""External runner check: public collection heartbeat, never private incident state."""
import json
import os
from pathlib import Path
import sys
import urllib.request
from datetime import datetime, timezone


def validate(document, now=None, max_age=10800):
    stamp = datetime.fromisoformat(document['collector_success_at'].replace('Z', '+00:00'))
    age = ((now or datetime.now(timezone.utc))-stamp).total_seconds()
    if age < -300 or age > max_age:
        raise ValueError('Collector heartbeat is stale or has an invalid future timestamp')
    return age


def main():
    try:
        validate(json.loads(Path('data/health.json').read_text()))
        repo = os.environ['GITHUB_REPOSITORY']
        owner, project = repo.split('/')
        url = os.environ.get('JPI_PUBLIC_HEALTH_URL') or f'https://{owner}.github.io/{project}/data/health.json'
        with urllib.request.urlopen(url, timeout=30) as response:
            validate(json.load(response))
    except Exception:
        # Never include exception details: an HTTP exception may contain a secret URL.
        message = ('⚠️ JP Incident Monitor: external heartbeat check failed. '
                   'Collection/publication has no fresh heartbeat or the public site is unreachable. '
                   'Check the collector host, timer, and GitHub Pages deployment.')
        hook = os.environ.get('JPI_ALERT_WEBHOOK_URL')
        if hook:
            try:
                request = urllib.request.Request(hook, data=json.dumps({
                    'content': message, 'allowed_mentions': {'parse': []}}).encode(),
                    headers={'Content-Type':'application/json','User-Agent':'JP-Incident-Monitor-Watchdog'})
                with urllib.request.urlopen(request, timeout=30):
                    pass
            except Exception:
                print('External alert delivery failed; inspect repository secret configuration', file=sys.stderr)
        else:
            print('External alert webhook secret is not configured', file=sys.stderr)
        print(message, file=sys.stderr)
        return 1
    print('Collector and public-site heartbeats are fresh')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
