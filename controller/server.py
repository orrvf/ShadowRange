"""ShadowRange LAN Controller: authenticated WS tasks and multicast discovery.
HMAC authenticates but DOES NOT encrypt task contents or telemetry.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from websockets.sync.server import serve
from websockets.exceptions import ConnectionClosed
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remote_protocol import Channel, nonce, signed, verify_signed, session_key, encode

GROUP = '239.255.77.77'
DISCOVERY_PORT = 47077
MAX_REQUEST = 4096
MAX_WS_MESSAGE = 1_500_000
MAX_TELEMETRY = 1_000_000
MAX_TASKS = 100
TASK_TIMEOUT_SECONDS = 45


def now():
    return datetime.now(timezone.utc).isoformat()


def valid_pid(value):
    return type(value) is int and 0 < value <= 2**31 - 1


def valid_agent_id(value):
    return isinstance(value, str) and 1 <= len(value) <= 48 and all(c.isalnum() or c in '_-' for c in value)


def load_agent_keys(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not data:
        raise ValueError('agent registry must be a nonempty JSON object')
    for name, info in data.items():
        if (not valid_agent_id(name) or type(info) is not dict or
            set(info) != {'platform', 'token'} or info['platform'] not in ('linux', 'windows') or
            not isinstance(info['token'], str) or len(info['token']) < 32):
            raise ValueError('invalid agent registry entry')
    tokens = [a['token'] for a in data.values()]
    if len(set(tokens)) != len(tokens):
        raise ValueError('agent tokens must be unique')
    return data


def expire_tasks(state):
    deadline = time.monotonic()
    for task in state.tasks.values():
        if task['status'] == 'dispatched' and deadline > task['deadline']:
            task.update(status='failed', error='task timeout', finished_at_utc=now())


class State:
    def __init__(self, agent_keys, admin_token, data_dir):
        self.agent_keys, self.admin_token = agent_keys, admin_token
        self.data_dir = data_dir
        self.lock = threading.RLock()
        self.agents = {}
        self.tasks = {}


def check_telemetry(telemetry, task, platform):
    if not isinstance(telemetry, str):
        raise ValueError('missing telemetry')
    data = telemetry.encode('utf-8')
    if not 0 < len(data) <= MAX_TELEMETRY:
        raise ValueError('telemetry empty or too large')
    records = [json.loads(line) for line in telemetry.splitlines() if line.strip()]
    if not 1 <= len(records) <= 5000 or any(type(x) is not dict for x in records):
        raise ValueError('invalid telemetry records')
    processes = [r for r in records if r.get('type') == 'process']
    if len(processes) != 1 or processes[0].get('pid') != task['pid']:
        raise ValueError('missing process or mismatched PID')
    if processes[0].get('platform', 'linux') != platform:
        raise ValueError('telemetry platform mismatch')
    allowed = {'process', 'module'} if platform == 'windows' else {'process', 'memory_region'}
    if any(r.get('type') not in allowed or not valid_pid(r.get('pid')) or r['pid'] != task['pid'] or
           (platform == 'windows' and r.get('platform') != 'windows') for r in records):
        raise ValueError('invalid record type, PID or platform')
    return data


def ws_handler(state, ws):
    agent_id = None
    try:
        if ws.request.path != '/agent/ws':
            raise ValueError('invalid websocket path')
        raw = ws.recv(timeout=8)
        if not isinstance(raw, str):
            raise ValueError('expected text hello')
        hello = json.loads(raw)
        if type(hello) is not dict or set(hello) != {'type', 'agent_id', 'platform', 'allowed_pid', 'client_nonce'} or hello['type'] != 'hello':
            raise ValueError('invalid hello')
        agent_id = hello['agent_id']
        platform = hello['platform']
        pid = hello['allowed_pid']
        client_nonce = hello['client_nonce']
        if (not valid_agent_id(agent_id) or not valid_pid(pid) or
            type(client_nonce) is not str or len(client_nonce) != 32 or
            any(c not in '0123456789abcdef' for c in client_nonce)):
            raise ValueError('invalid agent identity')
        configured = state.agent_keys.get(agent_id)
        if not configured or configured['platform'] != platform:
            raise ValueError('unauthorized agent')
        token = configured['token']
        server_nonce = nonce()
        ws.send(encode(signed(token, 'server-challenge', {'type': 'challenge',
                          'client_nonce': client_nonce, 'server_nonce': server_nonce})))
        proof_raw = ws.recv(timeout=8)
        proof = verify_signed(token, 'agent-proof', json.loads(proof_raw))
        if proof != {'type': 'proof', 'agent_id': agent_id, 'client_nonce': client_nonce,
                     'server_nonce': server_nonce}:
            raise ValueError('unauthorized agent proof')
        channel = Channel(session_key(token, client_nonce, server_nonce), 'controller-to-agent', 'agent-to-controller')
        with state.lock:
            if agent_id in state.agents:
                raise ValueError('duplicate agent connection')
            state.agents[agent_id] = {'ws': ws, 'channel': channel, 'approved_pid': pid,
                                      'platform': platform, 'connected_at_utc': now()}
        ws.send(channel.send({'type': 'ready', 'agent_id': agent_id}))
        print(f'[agent] {agent_id} connected; platform={platform}', flush=True)
        for raw in ws:
            if not isinstance(raw, str):
                raise ValueError('expected text result')
            msg = channel.recv(raw)
            if type(msg) is not dict or msg.get('type') != 'result' or msg.get('status') not in ('ok', 'error'):
                raise ValueError('invalid result')
            task_id = msg.get('task_id')
            with state.lock:
                task = state.tasks.get(task_id) if type(task_id) is str else None
                if not task or task['agent_id'] != agent_id or task['status'] != 'dispatched':
                    raise ValueError('unrecognized or stale result')
                if time.monotonic() > task['deadline']:
                    task['status'] = 'failed'
                    task['error'] = 'task timeout'
                    task['finished_at_utc'] = now()
                    raise ValueError('late result')
                if msg['status'] == 'ok' and task['action'] == 'collect_process':
                    if set(msg) != {'type', 'task_id', 'status', 'telemetry'}:
                        raise ValueError('invalid collection result fields')
                    data = check_telemetry(msg['telemetry'], task, platform)
                    case_dir = state.data_dir / task_id
                    case_dir.mkdir(mode=0o700)
                    path = case_dir / 'shadowrange.telemetry'
                    with path.open('xb') as f:
                        f.write(data)
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass  # Windows ACLs may differ; run as an unprivileged account.
                    task['telemetry_sha256'] = hashlib.sha256(data).hexdigest()
                    task['telemetry_path'] = str(path)
                elif msg['status'] == 'ok' and set(msg) != {'type', 'task_id', 'status'}:
                    raise ValueError('unexpected health result fields')
                elif msg['status'] == 'error':
                    if set(msg) != {'type', 'task_id', 'status', 'error'}:
                        raise ValueError('invalid error fields')
                    task['error'] = str(msg['error'])[:160]
                task['status'] = 'completed' if msg['status'] == 'ok' else 'failed'
                task['finished_at_utc'] = now()
            ws.send(channel.send({'type': 'accepted', 'task_id': task_id}))
    except (ConnectionClosed, TimeoutError):
        pass
    except (ValueError, KeyError, json.JSONDecodeError, OSError, UnicodeError) as exc:
        print(f'[agent] refused message: {str(exc)[:120]}', flush=True)
        try:
            ws.close(code=1008, reason='invalid or unauthorized message')
        except (ConnectionClosed, OSError):
            pass
    finally:
        if agent_id is not None:
            with state.lock:
                entry = state.agents.get(agent_id)
                if entry and entry['ws'] is ws:
                    del state.agents[agent_id]
                    for task in state.tasks.values():
                        if task['agent_id'] == agent_id and task['status'] == 'dispatched':
                            task.update(status='failed', error='agent disconnected', finished_at_utc=now())


def http_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print('[admin] ' + fmt % args, flush=True)

        def respond(self, code, body):
            raw = json.dumps(body).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Content-Length', str(len(raw)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(raw)

        def authorized(self):
            if not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + state.admin_token):
                self.respond(401, {'error': 'unauthorized'})
                return False
            return True

        def do_GET(self):
            if self.path == '/health':
                return self.respond(200, {'service': 'ShadowRange LAN controller', 'status': 'ok'})
            if self.path != '/admin/status':
                return self.respond(404, {'error': 'not found'})
            if not self.authorized():
                return
            with state.lock:
                expire_tasks(state)
                agents = {name: {'connected': True, 'platform': e['platform'], 'approved_pid': e['approved_pid']}
                          for name, e in state.agents.items()}
                tasks = [{k: v for k, v in t.items() if k != 'deadline'} for t in state.tasks.values()]
            return self.respond(200, {'agents': agents, 'tasks': tasks})

        def do_POST(self):
            if self.path != '/admin/task':
                return self.respond(404, {'error': 'not found'})
            if not self.authorized():
                return
            try:
                length = self.headers.get('Content-Length', '')
                if not length.isdigit() or not 0 < int(length) <= MAX_REQUEST:
                    raise ValueError('invalid request size')
                body = json.loads(self.rfile.read(int(length)).decode('utf-8'))
                if type(body) is not dict or set(body) - {'agent_id', 'action', 'pid'}:
                    raise ValueError('invalid task fields')
                agent_id, action, pid = body.get('agent_id'), body.get('action'), body.get('pid')
                if not valid_agent_id(agent_id) or action not in ('health', 'collect_process'):
                    raise ValueError('disallowed action or agent ID')
                with state.lock:
                    expire_tasks(state)
                    entry = state.agents.get(agent_id)
                    if entry is None:
                        raise ValueError('agent is not connected')
                    if action == 'collect_process' and (not valid_pid(pid) or pid != entry['approved_pid']):
                        raise ValueError('PID not approved by agent')
                    if action == 'health' and pid is not None:
                        raise ValueError('health must not specify PID')
                    if any(t['agent_id'] == agent_id and t['status'] in ('queued', 'dispatched') for t in state.tasks.values()):
                        raise ValueError('agent already has an active task')
                    if len(state.tasks) >= MAX_TASKS:
                        raise ValueError('lab task limit reached; restart controller')
                    task_id = secrets.token_hex(12)
                    task = {'id': task_id, 'agent_id': agent_id, 'action': action,
                            'created_at_utc': now(), 'status': 'dispatched',
                            'dispatched_at_utc': now(), 'deadline': time.monotonic() + TASK_TIMEOUT_SECONDS}
                    if action == 'collect_process':
                        task['pid'] = pid
                    state.tasks[task_id] = task
                    ws = entry['ws']
                    channel = entry['channel']
                try:
                    ws.send(channel.send({'type': 'task', 'id': task_id, 'action': action,
                                        **({'pid': pid} if action == 'collect_process' else {})}))
                except (ConnectionClosed, OSError):
                    with state.lock:
                        task.update(status='failed', error='agent disconnected during dispatch', finished_at_utc=now())
                    return self.respond(503, {'error': 'agent disconnected'})
                return self.respond(201, {'task_id': task_id, 'status': 'dispatched'})
            except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
                return self.respond(400, {'error': str(exc)[:180]})
    return Handler


def multicast_discovery_responder(host, ws_port, agent_keys, stop_event):
    """On-demand, nonce-bound signed replies; discovery never accepts task commands."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', DISCOVERY_PORT))
        membership = struct.pack('4s4s', socket.inet_aton(GROUP), socket.inet_aton('0.0.0.0'))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        sock.settimeout(1)
        while not stop_event.is_set():
            try:
                raw, source = sock.recvfrom(512)
                data = json.loads(raw)
                if type(data) is not dict or set(data) != {'type', 'service', 'version', 'agent_id', 'nonce'}:
                    continue
                agent_id = data['agent_id']
                request_nonce = data['nonce']
                if (data['type'] != 'discover' or data['service'] != 'shadowrange-lab' or
                    data['version'] != 1 or not valid_agent_id(agent_id) or
                    type(request_nonce) is not str or len(request_nonce) != 32 or
                    any(c not in '0123456789abcdef' for c in request_nonce)):
                    continue
                info = agent_keys.get(agent_id)
                if not info:
                    continue
                reply = signed(info['token'], 'discovery', {'service': 'shadowrange-lab',
                    'version': 1, 'host': host, 'port': ws_port, 'nonce': request_nonce})
                sock.sendto(encode(reply).encode('utf-8'), source)
            except socket.timeout:
                continue
            except (OSError, json.JSONDecodeError, ValueError, TypeError):
                continue

def main():
    parser = argparse.ArgumentParser(description='ShadowRange LAN controller')
    parser.add_argument('--bind', required=True, help='Controller reachable IPv4 LAN address; do not use 0.0.0.0')
    parser.add_argument('--ws-port', type=int, default=8001)
    parser.add_argument('--admin-port', type=int, default=8000)
    parser.add_argument('--agents-file', type=Path, default=Path('controller/agents.json'))
    parser.add_argument('--data-dir', type=Path, default=Path('controller/data'))
    parser.add_argument('--no-discovery', action='store_true')
    args = parser.parse_args()
    try:
        socket.inet_aton(args.bind)
        if args.bind == '0.0.0.0' or args.bind.startswith('127.'):
            parser.error('--bind must be a specific non-loopback IPv4 address')
        if not 0 < args.ws_port < 65536 or not 0 < args.admin_port < 65536:
            parser.error('invalid port')
        admin_token = os.getenv('SHADOWRANGE_ADMIN_TOKEN', '')
        if len(admin_token) < 32:
            parser.error('SHADOWRANGE_ADMIN_TOKEN must be 32+ characters')
        agent_keys = load_agent_keys(args.agents_file)
        if any(hmac.compare_digest(admin_token, value['token']) for value in agent_keys.values()):
            parser.error('admin and agent tokens must be different')
        args.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    state = State(agent_keys, admin_token, args.data_dir.resolve())
    stop = threading.Event()
    if not args.no_discovery:
        threading.Thread(target=multicast_discovery_responder, args=(args.bind, args.ws_port, agent_keys, stop), daemon=True).start()
    try:
        with serve(lambda ws: ws_handler(state, ws), args.bind, args.ws_port,
                   compression=None, max_size=MAX_WS_MESSAGE, open_timeout=8,
                   ping_interval=20, ping_timeout=20) as wss:
            threading.Thread(target=wss.serve_forever, daemon=True).start()
            with ThreadingHTTPServer(('127.0.0.1', args.admin_port), http_handler(state)) as admin:
                print(f'ShadowRange admin: http://127.0.0.1:{args.admin_port} (loopback only)')
                print(f'ShadowRange agents: ws://{args.bind}:{args.ws_port}/agent/ws (HMAC; no encryption)')
                print('Multicast discovery enabled' if not args.no_discovery else 'Multicast discovery disabled')
                admin.serve_forever()
    finally:
        stop.set()


if __name__ == '__main__':
    main()
