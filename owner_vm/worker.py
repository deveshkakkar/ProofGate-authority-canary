"""Fixed synthetic worker: no bearer, key, network, model or owner-context tools."""
import base64
import errno
import json
import os
from pathlib import Path
import socket
import sys


def rpc(value):
    print(json.dumps(value), flush=True)
    raw = sys.stdin.buffer.readline(131073)
    if len(raw) > 131072 or not raw.endswith(b'\n'):
        raise RuntimeError('protocol')
    response = json.loads(raw)
    if response.get('ok') is not True:
        raise RuntimeError('gateway_denied')
    return response['data']


def observations():
    blocked = False
    try:
        Path('/var/lib/proofgate-canary/issuer/owner-boundary-fixture').read_bytes()
    except OSError:
        blocked = True
    readonly = False
    try:
        fd = os.open('/app/worker.py', os.O_WRONLY)
        os.close(fd)
    except OSError as error:
        readonly = bool(os.statvfs('/app').f_flag & os.ST_RDONLY) and error.errno in (errno.EROFS, errno.EACCES)
    network = False
    try:
        with socket.socket() as connection:
            connection.settimeout(1)
            connection.connect(('1.1.1.1', 443))
    except OSError:
        network = True
    forbidden = ['GH_TOKEN', 'GITHUB_TOKEN', 'SSH_AUTH_SOCK', 'DOCKER_HOST', 'PROOFGATE_TOKEN_FD']
    return {'uid': os.getuid(), 'gid': os.getgid(), 'marker_blocked': blocked,
            'source_readonly': readonly, 'network_blocked': network,
            'owner_environment_absent': not any(name in os.environ for name in forbidden),
            'owner_paths_absent': all(not Path(name).exists() for name in
                                     ['/home', '/root', '/run/proofgate-canary', '/var/lib/proofgate-canary']),
            'namespace_inodes': {name: os.stat('/proc/self/ns/' + name).st_ino
                                 for name in ['pid', 'mnt', 'net', 'user']}}


def main():
    session = rpc({'op': 'hello', 'observations': observations()})
    if session['mode'] == 'probe':
        rpc({'op': 'done'})
        return
    repo = rpc({'op': 'api', 'method': 'GET', 'path': ''})
    if repo['id'] != 1452255523:
        raise RuntimeError('repository')
    head = rpc({'op': 'api', 'method': 'GET', 'path': '/git/ref/heads/main'})['sha']
    rpc({'op': 'api', 'method': 'POST', 'path': '/git/refs',
         'body': {'ref': 'refs/heads/' + session['branch'], 'sha': head}})
    payload = json.dumps({'probe_version': 1, 'run_id': session['run_id']}, sort_keys=True).encode()
    rpc({'op': 'api', 'method': 'PUT', 'path': '/contents/probes/' + session['run_id'] + '.json',
         'body': {'message': 'Add harmless authenticated canary fixture', 'branch': session['branch'],
                  'content': base64.b64encode(payload).decode()}})
    rpc({'op': 'api', 'method': 'POST', 'path': '/pulls',
         'body': {'title': 'Authenticated canary positive control', 'head': session['branch'], 'base': 'main',
                  'body': 'Synthetic App-authored trial. Requires genuine human approval and human-operated merge. Not independent admission.'}})
    rpc({'op': 'done'})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2)
