"""Durable Git publication retries, independent of collection and AI work."""
import contextlib
import json
import os
import signal
import subprocess
from datetime import datetime, timedelta, timezone

import operations as ops


def run_git(args, cwd, check=True):
    # Kill SSH as well as Git on timeout so a stalled push cannot retain the lock.
    with subprocess.Popen(['git', *args], cwd=cwd, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, start_new_session=True) as process:
        try:
            output, _ = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
    result = subprocess.CompletedProcess(['git', *args], process.returncode, output)
    if check and result.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {output.strip()}")
    return result


def _save(path, state, *, alert=None, clear_alert=None):
    """Commit the retry state and notification transition together."""
    with contextlib.closing(ops.connect(path)) as c, c:
        c.execute('INSERT OR REPLACE INTO ops_state VALUES(?,?)',
                  ('publication', json.dumps(state)))
        if clear_alert:
            c.execute('DELETE FROM alert_outbox WHERE key=?', (clear_alert,))
        if alert:
            key, payload = alert
            c.execute('INSERT OR REPLACE INTO alert_outbox VALUES(?,?,?)',
                      (key, json.dumps(payload), ops.now()))


def push_pending(path, repo, remote, branch, *, committed=False, git=run_git, now=None):
    """Attempt one due push. Callers must hold the shared collector lock.

    Push failures retain commits and return False; local export/commit failures
    remain fatal in the caller. No force push or automatic history rewriting.
    """
    moment = now or datetime.now(timezone.utc)
    stamp = moment.isoformat(timespec='seconds')
    target = {'repo': os.path.realpath(repo), 'remote': remote, 'branch': branch}
    state = ops.get_state(path, 'publication', {}) or {}
    if any(state.get(key) != value for key, value in target.items()):
        state = {}
    if state.get('pending') and state.get('next_attempt_at'):
        if moment < datetime.fromisoformat(state['next_attempt_at']):
            print('Publication pending; next retry at ' + state['next_attempt_at'])
            return False
    ahead = git(['rev-list', '--count', f'refs/remotes/{remote}/{branch}..HEAD'], repo, check=False)
    pending = committed or state.get('pending') or ahead.returncode != 0 or int(ahead.stdout.strip() or '0') > 0
    if not pending:
        print('Git publish skipped: no pending commits')
        return False

    # Persist before network I/O; an interrupted process remains retryable.
    attempt = state.get('attempts', 0) + 1
    delay = min(1800, 300 * 2 ** min(attempt - 1, 3))
    state = {**state, **target, 'pending': True, 'attempts': attempt,
             'last_attempt_at': stamp,
             'next_attempt_at': (moment + timedelta(seconds=delay)).isoformat(timespec='seconds')}
    _save(path, state)
    try:
        result = git(['push', '--set-upstream', remote, f'HEAD:{branch}'], repo, check=False)
        error = result.stdout.strip() if result.returncode else None
        if result.returncode and not error:
            error = f'git push exited with status {result.returncode}'
    except subprocess.TimeoutExpired:
        error = 'git push timed out after 120 seconds'
    except OSError as exc:
        error = f'Unable to run git push: {exc}'
    if error:
        first_failure = not state.get('first_failed_at')
        state.update(first_failed_at=state.get('first_failed_at') or stamp, last_error=error)
        alert = ('publication-delayed', {
            'title': 'Publication delayed', 'severity': 'warning', 'cooldown_hours': 0,
            'detail': 'Git push failed. Saved commits remain local and collection can continue. '
                      'Publication retries automatically after 5, 10, 20, then every 30 minutes. '
                      'If this persists, inspect the publication service logs and repository access.'
        }) if first_failure else None
        _save(path, state, alert=alert, clear_alert='publication-recovered')
        print(f"[warn] Publication deferred until {state['next_attempt_at']}: {error}")
        return False

    recovered = bool(state.get('first_failed_at'))
    _save(path, {**target, 'pending': False, 'attempts': 0, 'last_success_at': stamp},
          clear_alert='publication-delayed', alert=('publication-recovered', {
              'title': 'Publication recovered', 'severity': 'info', 'cooldown_hours': 0,
              'detail': 'Git push succeeded. All saved commits have reached the publication remote.'
          }) if recovered else None)
    print(f'Pushed incident data to {remote}/{branch}')
    return True
