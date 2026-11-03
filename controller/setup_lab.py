"""Generate local per-agent HMAC secrets (no certificates required)."""
import argparse
import json
import os
import secrets
from pathlib import Path


def private_write(path, content):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(content)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--agents', nargs='+', default=['linux-lab:linux', 'windows-lab:windows'])
    args = p.parse_args()
    root = Path(__file__).resolve().parent
    creds = root / 'credentials'
    registry = root / 'agents.json'
    admin = root / 'admin.env'
    if registry.exists() or admin.exists() or creds.exists():
        p.error('Credentials already exist; no files changed')
    agents = {}
    for item in args.agents:
        try:
            agent_id, platform = item.split(':', 1)
        except ValueError:
            p.error('Agent format must be ID:linux or ID:windows')
        if not 1 <= len(agent_id) <= 48 or not all(c.isalnum() or c in '_-' for c in agent_id) or platform not in ('linux', 'windows') or agent_id in agents:
            p.error('Invalid/duplicate agent ID')
        agents[agent_id] = {'platform': platform, 'token': secrets.token_hex(32)}
    creds.mkdir(mode=0o700)
    private_write(registry, json.dumps(agents, indent=2) + '\n')
    private_write(admin, 'export SHADOWRANGE_ADMIN_TOKEN=' + secrets.token_hex(32) + '\n')
    for agent_id, info in agents.items():
        private_write(creds / (agent_id + '.json'), json.dumps({'agent_id': agent_id, **info}, indent=2) + '\n')
    print('Created private per-agent tokens and admin token; no TLS certificates.')
    print('Keep controller/agents.json and controller/admin.env only on Controller.')
    print('Give each agent only its own JSON credential file.')


if __name__ == '__main__':
    main()
