"""Visible ShadowRange LAN agent, only preapproved process collection.
Messages are HMAC authenticated, NOT encrypted.
"""
import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse

from websockets.sync.client import connect
from websockets.exceptions import ConnectionClosed
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remote_protocol import Channel, nonce, signed, verify_signed, session_key, encode

GROUP = '239.255.77.77'
DISCOVERY_PORT = 47077
MAX_TELEMETRY = 1_000_000
ROOT = Path(__file__).resolve().parent.parent


def linux_start(pid):
    stat = Path(f'/proc/{pid}/stat').read_text(encoding='ascii')
    return stat.rsplit(') ', 1)[1].split()[19]


def windows_start(pid):
    # Fixed PowerShell expression, with previously validated numeric PID only.
    ps = f'(Get-Process -Id {pid} -ErrorAction Stop).StartTime.ToUniversalTime().Ticks'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', ps],
                            capture_output=True, text=True, timeout=10, check=True)
    return result.stdout.strip()


def collect(platform, monitor, pid):
    with tempfile.TemporaryDirectory(prefix='shadowrange-agent-') as tmp:
        if platform == 'linux':
            command = [str(monitor), str(pid)]
        else:
            dest = str(Path(tmp) / 'shadowrange.telemetry')
            command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-File', str(monitor),
                       '-TargetPid', str(pid), '-Output', dest]
        result = subprocess.run(command, cwd=tmp, capture_output=True, text=True, timeout=25)
        if result.returncode:
            raise RuntimeError('collector failed: ' + result.stderr[:120])
        path = Path(tmp) / 'shadowrange.telemetry'
        if not path.is_file() or not 0 < path.stat().st_size <= MAX_TELEMETRY:
            raise RuntimeError('missing or oversized telemetry')
        return path.read_text(encoding='utf-8-sig')


def discover(agent_id, token, timeout=8):
    """On-demand multicast query; accept only authenticated matching-nonce reply."""
    request_nonce = nonce()
    query = encode({'type': 'discover', 'service': 'shadowrange-lab', 'version': 1,
                    'agent_id': agent_id, 'nonce': request_nonce}).encode('ascii')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('B', 1))
        sock.bind(('', 0))
        sock.sendto(query, (GROUP, DISCOVERY_PORT))
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                raw, _ = sock.recvfrom(1024)
                msg = verify_signed(token, 'discovery', json.loads(raw))
                if (msg.get('service') != 'shadowrange-lab' or msg.get('version') != 1 or
                    msg.get('nonce') != request_nonce):
                    continue
                host, port = msg.get('host'), msg.get('port')
                if type(host) is not str or type(port) is not int or not 1 <= port <= 65535:
                    continue
                socket.inet_aton(host)
                if host == '0.0.0.0':
                    continue
                return f'ws://{host}:{port}/agent/ws'
            except (ValueError, OSError, TypeError, json.JSONDecodeError):
                continue
        raise TimeoutError('No authenticated controller discovered')

def check_url(url):
    parsed = urlparse(url)
    if (parsed.scheme != 'ws' or parsed.port is None or parsed.path != '/agent/ws' or
        parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('A ws://HOST:PORT/agent/ws endpoint is required')
    return url


def main():
    parser = argparse.ArgumentParser(description='ShadowRange authorized LAN agent')
    parser.add_argument('--config', type=Path, required=True, help='Private JSON with agent_id, platform, token')
    parser.add_argument('--allowed-pid', type=int, required=True)
    parser.add_argument('--server', help='Explicit ws://host:port/agent/ws; otherwise multicast discovery')
    parser.add_argument('--monitor', type=Path, help='Collector path; defaults to platform collector')
    args = parser.parse_args()
    if type(args.allowed_pid) is not int or not 0 < args.allowed_pid < 2**31:
        parser.error('invalid PID')
    try:
        config = json.loads(args.config.read_text(encoding='utf-8'))
        if type(config) is not dict or set(config) != {'agent_id', 'platform', 'token'}:
            raise ValueError('invalid agent configuration')
        agent_id, platform, token = config['agent_id'], config['platform'], config['token']
        if (not isinstance(agent_id, str) or not agent_id or len(agent_id) > 48 or
            not all(c.isalnum() or c in '_-' for c in agent_id) or
            platform not in ('linux', 'windows') or not isinstance(token, str) or len(token) < 32):
            raise ValueError('invalid identity')
        if (platform == 'linux') != (os.name == 'posix'):
            raise ValueError('agent platform does not match this operating system')
        monitor = (args.monitor or (ROOT / ('proc_monitor/proc_monitor' if platform == 'linux' else 'windows/collect.ps1'))).resolve()
        if not monitor.is_file():
            raise ValueError(f'collector missing: {monitor}')
        start = (linux_start if platform == 'linux' else windows_start)(args.allowed_pid)
        if not start:
            raise ValueError('cannot determine process start time')
        if args.server:
            check_url(args.server)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print(f'ShadowRange {platform} agent {agent_id}: authorized PID={args.allowed_pid}; Ctrl+C to stop', flush=True)
    while True:
        try:
            endpoint = check_url(args.server or discover(agent_id, token))
            with connect(endpoint, max_size=8192, compression=None,
                         proxy=None, open_timeout=8, ping_interval=20) as ws:
                client_nonce = nonce()
                ws.send(encode({'type': 'hello', 'agent_id': agent_id, 'platform': platform,
                                'allowed_pid': args.allowed_pid, 'client_nonce': client_nonce}))
                challenge = verify_signed(token, 'server-challenge', json.loads(ws.recv(timeout=8)))
                server_nonce = challenge.get('server_nonce')
                if (challenge.get('type') != 'challenge' or challenge.get('client_nonce') != client_nonce or
                    type(server_nonce) is not str or len(server_nonce) != 32):
                    raise ValueError('invalid controller challenge')
                ws.send(encode(signed(token, 'agent-proof', {'type': 'proof', 'agent_id': agent_id,
                                 'client_nonce': client_nonce, 'server_nonce': server_nonce})))
                channel = Channel(session_key(token, client_nonce, server_nonce), 'agent-to-controller', 'controller-to-agent')
                ready = channel.recv(ws.recv(timeout=8))
                if ready != {'type': 'ready', 'agent_id': agent_id}:
                    raise ValueError('controller rejected agent')
                print('HMAC verified; connected; waiting for tasks (unencrypted LAN).', flush=True)
                for raw in ws:
                    task = channel.recv(raw)
                    if type(task) is not dict:
                        raise ValueError('unexpected server message')
                    if task.get('type') == 'accepted':
                        continue
                    if task.get('type') != 'task':
                        raise ValueError('unexpected server message')
                    task_id, action = task.get('id'), task.get('action')
                    if not isinstance(task_id, str) or len(task_id) != 24 or any(c not in '0123456789abcdef' for c in task_id):
                        raise ValueError('invalid task ID')
                    result = {'type': 'result', 'task_id': task_id, 'status': 'ok'}
                    try:
                        if action == 'health' and set(task) == {'type', 'id', 'action'}:
                            pass
                        elif (action == 'collect_process' and set(task) == {'type', 'id', 'action', 'pid'}
                              and type(task['pid']) is int and task['pid'] == args.allowed_pid):
                            start_fn = linux_start if platform == 'linux' else windows_start
                            if start_fn(args.allowed_pid) != start:
                                raise ValueError('PID reused; original process has exited')
                            result['telemetry'] = collect(platform, monitor, args.allowed_pid)
                            if start_fn(args.allowed_pid) != start:
                                raise ValueError('process changed during collection')
                        else:
                            raise ValueError('action or PID not permitted')
                    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError, UnicodeError) as exc:
                        result = {'type': 'result', 'task_id': task_id, 'status': 'error', 'error': str(exc)[:160]}
                    ws.send(channel.send(result))
                    print(f"Task {task_id} ({action}): {result['status']}", flush=True)
        except (ConnectionClosed, OSError, TimeoutError, ValueError, KeyError, json.JSONDecodeError,
                subprocess.SubprocessError) as exc:
            print(f'Connection/discovery failed: {str(exc)[:130]}; retrying...', flush=True)
            time.sleep(5)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nAgent stopped.')
