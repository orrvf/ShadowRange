"""Visible localhost-only ShadowRange Linux lab agent; no remote shell execution."""
import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

MAX_TELEMETRY = 1_000_000


def post(url, token, route, body):
    request = Request(url + route, json.dumps(body).encode('utf-8'), {
        'Authorization': 'Bearer ' + token,
        'Content-Type': 'application/json',
    }, method='POST')
    with urlopen(request, timeout=8) as response:
        return json.load(response)


def collect(monitor, pid):
    with tempfile.TemporaryDirectory(prefix='shadowrange-agent-') as work:
        result = subprocess.run([str(monitor), str(pid)], cwd=work, capture_output=True, text=True, timeout=15, check=False)
        if result.returncode != 0:
            raise RuntimeError('proc_monitor returned nonzero: ' + result.stderr[:120])
        telemetry = Path(work, 'shadowrange.telemetry')
        if not telemetry.is_file() or telemetry.stat().st_size > MAX_TELEMETRY:
            raise RuntimeError('missing or oversized telemetry')
        return telemetry.read_text(encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='ShadowRange visible Linux laboratory agent')
    parser.add_argument('--server', default='http://127.0.0.1:8000')
    parser.add_argument('--id', default='linux-lab')
    parser.add_argument('--allowed-pid', type=int, required=True, help='Only this preapproved PID can be collected')
    parser.add_argument('--monitor', type=Path, default=Path('proc_monitor/proc_monitor'))
    parser.add_argument('--interval', type=int, default=5)
    args = parser.parse_args()
    parsed = urlparse(args.server)
    if parsed.scheme != 'http' or parsed.hostname not in ('localhost', '127.0.0.1') or parsed.username or parsed.password or parsed.path.strip('/') or parsed.query or parsed.fragment:
        parser.error('MVP allows only a localhost HTTP controller')
    if args.allowed_pid <= 0 or args.interval < 2 or args.interval > 60:
        parser.error('Invalid PID or polling interval')
    if not args.id or len(args.id) > 48 or not all(c.isalnum() or c in '-_' for c in args.id):
        parser.error('Invalid agent ID')
    token = os.getenv('SHADOWRANGE_AGENT_TOKEN')
    if not token or len(token) < 16:
        parser.error('Set SHADOWRANGE_AGENT_TOKEN (>=16 characters)')
    monitor = args.monitor.resolve()
    if not monitor.is_file():
        parser.error(f'Monitor executable not found: {monitor}')
    print(f'ShadowRange lab agent active: id={args.id}, allowed_pid={args.allowed_pid}. Ctrl+C to stop.', flush=True)
    while True:
        try:
            task = post(args.server.rstrip('/'), token, '/agent/poll', {'agent_id': args.id}).get('task')
            if task:
                result = {'agent_id': args.id, 'task_id': task['id'], 'status': 'ok'}
                try:
                    if task['action'] == 'health':
                        pass
                    elif task['action'] == 'collect_process' and type(task.get('pid')) is int and task['pid'] == args.allowed_pid:
                        result['telemetry'] = collect(monitor, args.allowed_pid)
                    else:
                        raise ValueError('task not approved by agent')
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, UnicodeError) as error:
                    result = {'agent_id': args.id, 'task_id': task['id'], 'status': 'error', 'error': str(error)[:200]}
                post(args.server.rstrip('/'), token, '/agent/result', result)
                print(f"Task {task['id']} ({task['action']}): {result['status']}", flush=True)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError, KeyError) as error:
            print(f'Controller unavailable or response rejected: {error}', flush=True)
        time.sleep(args.interval)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nAgent stopped by operator.')
