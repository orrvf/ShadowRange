"""ShadowRange lab controller: localhost-only, authenticated, allowlisted telemetry tasks.

No command execution endpoint, persistence, background installation, or internet binding.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_REQUEST = 1_500_000
MAX_TELEMETRY = 1_000_000


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def valid_pid(value):
    return type(value) is int and 0 < value <= 2**31 - 1


class State:
    def __init__(self, agent_token, admin_token, data_dir):
        self.agent_token = agent_token
        self.admin_token = admin_token
        self.data_dir = data_dir
        self.lock = threading.Lock()
        self.agents = {}
        self.tasks = {}


def handler_factory(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # No authorization headers or telemetry body in HTTP access logs.
            print('[http] ' + format % args)

        def respond(self, status, data):
            raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)

        def authorized(self, role):
            expected = state.admin_token if role == 'admin' else state.agent_token
            actual = self.headers.get('Authorization', '')
            if not hmac.compare_digest(actual, 'Bearer ' + expected):
                self.respond(401, {'error': 'unauthorized'})
                return False
            return True

        def read_json(self):
            length = self.headers.get('Content-Length')
            if length is None or not length.isdigit():
                raise ValueError('Content-Length required')
            size = int(length)
            if not 0 < size <= MAX_REQUEST:
                raise ValueError('request size outside limit')
            obj = json.loads(self.rfile.read(size).decode('utf-8'))
            if type(obj) is not dict:
                raise ValueError('expected JSON object')
            return obj

        def do_GET(self):
            if self.path == '/health':
                self.respond(200, {'service': 'ShadowRange lab controller', 'status': 'ok'})
                return
            if self.path == '/admin/status':
                if not self.authorized('admin'):
                    return
                with state.lock:
                    agents = dict(state.agents)
                    tasks = [{k: v for k, v in item.items() if k != 'telemetry'} for item in state.tasks.values()]
                self.respond(200, {'agents': agents, 'tasks': tasks})
                return
            self.respond(404, {'error': 'not found'})

        def do_POST(self):
            if self.path.startswith('/admin/'):
                if not self.authorized('admin'):
                    return
            elif self.path.startswith('/agent/'):
                if not self.authorized('agent'):
                    return
            else:
                self.respond(404, {'error': 'not found'})
                return
            try:
                body = self.read_json()
                if self.path == '/agent/poll':
                    agent_id = body.get('agent_id')
                    if not isinstance(agent_id, str) or not (1 <= len(agent_id) <= 48) or not all(c.isalnum() or c in '-_' for c in agent_id):
                        raise ValueError('invalid agent_id')
                    with state.lock:
                        state.agents[agent_id] = {'last_seen_utc': utc_now(), 'online_recently': True}
                        available = next((x for x in state.tasks.values() if x['agent_id'] == agent_id and x['status'] == 'queued'), None)
                        if available:
                            available['status'] = 'dispatched'
                            available['dispatched_at_utc'] = utc_now()
                            task = {k: available[k] for k in ('id', 'action', 'pid') if k in available}
                        else:
                            task = None
                    self.respond(200, {'task': task})
                elif self.path == '/admin/task':
                    agent_id = body.get('agent_id')
                    action = body.get('action')
                    pid = body.get('pid')
                    if not isinstance(agent_id, str) or not (1 <= len(agent_id) <= 48) or not all(c.isalnum() or c in '-_' for c in agent_id):
                        raise ValueError('invalid agent_id')
                    if action not in ('health', 'collect_process'):
                        raise ValueError('action not allowlisted')
                    if action == 'collect_process' and not valid_pid(pid):
                        raise ValueError('valid pid required')
                    with state.lock:
                        if agent_id not in state.agents:
                            raise ValueError('agent not registered; start agent first')
                        task_id = secrets.token_hex(12)
                        task = {'id': task_id, 'agent_id': agent_id, 'action': action, 'status': 'queued', 'created_at_utc': utc_now()}
                        if action == 'collect_process':
                            task['pid'] = pid
                        state.tasks[task_id] = task
                    self.respond(201, {'task_id': task_id, 'status': 'queued'})
                elif self.path == '/agent/result':
                    agent_id, task_id = body.get('agent_id'), body.get('task_id')
                    status = body.get('status')
                    if status not in ('ok', 'error') or not isinstance(task_id, str):
                        raise ValueError('invalid result envelope')
                    with state.lock:
                        task = state.tasks.get(task_id)
                        if not task or task['status'] != 'dispatched' or task['agent_id'] != agent_id:
                            raise ValueError('unknown, completed or mismatched task')
                        if status == 'ok' and task['action'] == 'collect_process':
                            telemetry = body.get('telemetry')
                            if not isinstance(telemetry, str) or len(telemetry.encode('utf-8')) > MAX_TELEMETRY:
                                raise ValueError('telemetry missing or too large')
                            records = [json.loads(line) for line in telemetry.splitlines() if line.strip()]
                            processes = [r for r in records if isinstance(r, dict) and r.get('type') == 'process']
                            if len(processes) != 1 or processes[0].get('pid') != task['pid']:
                                raise ValueError('process PID does not match task')
                            # Linux snapshots contain memory regions; Windows snapshots contain modules.
                            # Never reinterpret Windows modules as Linux memory regions.
                            platform = processes[0].get('platform', 'linux')
                            if platform not in ('linux', 'windows'):
                                raise ValueError('unsupported telemetry platform')
                            expected_types = {'process', 'module'} if platform == 'windows' else {'process', 'memory_region'}
                            if len(records) > 5000 or any(
                                not isinstance(r, dict)
                                or r.get('type') not in expected_types
                                or type(r.get('pid')) is not int
                                or r['pid'] != task['pid']
                                or (platform == 'windows' and r.get('platform') != 'windows')
                                for r in records
                            ):
                                raise ValueError('invalid telemetry records or mismatched PID/platform')
                            case_dir = state.data_dir / task_id
                            case_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
                            output = case_dir / 'shadowrange.telemetry'
                            with output.open('x', encoding='utf-8') as file:
                                file.write(telemetry)
                            os.chmod(output, 0o600)
                            task['telemetry_sha256'] = hashlib.sha256(telemetry.encode('utf-8')).hexdigest()
                            task['telemetry_path'] = str(output)
                        task['status'] = 'completed' if status == 'ok' else 'failed'
                        task['finished_at_utc'] = utc_now()
                        if status == 'error':
                            error = body.get('error', 'Agent reported failure')
                            task['error'] = str(error)[:200]
                    self.respond(200, {'accepted': True})
                else:
                    self.respond(404, {'error': 'not found'})
            except (ValueError, UnicodeError, json.JSONDecodeError) as error:
                self.respond(400, {'error': str(error)[:180]})
            except OSError:
                self.respond(500, {'error': 'server file operation failed'})
    return Handler


def main():
    parser = argparse.ArgumentParser(description='ShadowRange local lab controller')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--data-dir', type=Path, default=Path('controller/data'))
    args = parser.parse_args()
    agent_token, admin_token = os.getenv('SHADOWRANGE_AGENT_TOKEN'), os.getenv('SHADOWRANGE_ADMIN_TOKEN')
    if not agent_token or not admin_token or len(agent_token) < 16 or len(admin_token) < 16 or agent_token == admin_token:
        parser.error('Set distinct SHADOWRANGE_AGENT_TOKEN and SHADOWRANGE_ADMIN_TOKEN (>=16 characters each)')
    args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    state = State(agent_token, admin_token, args.data_dir.resolve())
    address = ('127.0.0.1', args.port)
    with ThreadingHTTPServer(address, handler_factory(state)) as server:
        print(f'ShadowRange controller running at http://127.0.0.1:{args.port} (localhost only)', flush=True)
        server.serve_forever()


if __name__ == '__main__':
    main()
