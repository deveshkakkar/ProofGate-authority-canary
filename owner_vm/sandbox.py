"""Trusted VM supervisor. Bearer stays here; candidate gets only scoped API RPC."""
import base64
import http.client
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import ssl
import subprocess
import time
import tempfile
import uuid

from .common import ROOT, REPO, REPO_ID, OWNER_ID, require, run, record, Stop


def github(method, path, token, body=None):
    # Only trusted supervisor/controller code constructs full upstream paths.
    connection = http.client.HTTPSConnection('api.github.com', timeout=10,
                                             context=ssl.create_default_context())
    def alarm(*_):
        raise Stop('github_deadline')
    old = signal.signal(signal.SIGALRM, alarm); signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        connection.request(method, path, body=None if body is None else json.dumps(body), headers={
            'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'proofgate-owner-vm',
            'Content-Type': 'application/json'})
        response = connection.getresponse(); raw = response.read(131073)
        require(len(raw) <= 131072 and not response.getheader('Link'), 'github_response_bound')
        data = json.loads(raw) if raw else {}
        return response.status, data
    finally:
        connection.close(); signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, old)


class Gateway:
    """Positive-control routes only. Wrapper denials are not GitHub permission tests."""
    def __init__(self, token, mode, api=github):
        self.token, self.mode, self.api = token, mode, api
        self.run_id = uuid.uuid4().hex
        self.branch = 'authority-positive-' + self.run_id
        self.base_sha = None
        self.steps = 0
        self.events = []
        self.pr = None

    def call(self, request):
        require(self.mode == 'pr' and isinstance(request, dict), 'gateway_scope_denied')
        require(request.get('op') == 'api', 'gateway_request_shape')
        method, path, body = request.get('method'), request.get('path'), request.get('body')
        require(set(request) == ({'op', 'method', 'path'} if method == 'GET' else {'op', 'method', 'path', 'body'}),
                'gateway_request_shape')
        expected = [('GET', ''), ('GET', '/git/ref/heads/main'), ('POST', '/git/refs'),
                    ('PUT', '/contents/probes/' + self.run_id + '.json'), ('POST', '/pulls')]
        require(self.steps < len(expected) and (method, path) == expected[self.steps], 'gateway_scope_denied')
        if self.steps == 2:
            require(body == {'ref': 'refs/heads/' + self.branch, 'sha': self.base_sha}, 'branch_scope')
        if self.steps == 3:
            require(isinstance(body, dict) and set(body) == {'message', 'branch', 'content'}
                    and body['branch'] == self.branch and body['message'] == 'Add harmless authenticated canary fixture',
                    'fixture_scope')
            require(json.loads(base64.b64decode(body['content'], validate=True)) ==
                    {'probe_version': 1, 'run_id': self.run_id}, 'synthetic_fixture_only')
        if self.steps == 4:
            require(body == {'title': 'Authenticated canary positive control', 'head': self.branch, 'base': 'main',
                             'body': 'Synthetic App-authored trial. Requires genuine human approval and human-operated merge. Not independent admission.'},
                    'pull_request_scope')
        status, data = self.api(method, '/repos/' + REPO + path, self.token, body)
        self.events.append({'step': self.steps, 'method': method, 'http_status': status})
        require(status in (200, 201), 'github_request_failed')
        if self.steps == 0:
            require(type(data.get('id')) is int and data['id'] == REPO_ID
                    and data.get('full_name') == REPO and data.get('owner', {}).get('id') == OWNER_ID,
                    'repository_identity')
            result = {'id': REPO_ID}
        elif self.steps == 1:
            self.base_sha = data['object']['sha']
            require(re.fullmatch('[a-f0-9]{40}', self.base_sha) is not None, 'base_revision')
            result = {'sha': self.base_sha}
        elif self.steps == 4:
            user = data.get('user', {})
            require(user.get('login') == 'proofgate-coder[bot]' and user.get('type') == 'Bot', 'unexpected_principal')
            require(type(data.get('number')) is int and data['number'] > 0
                    and data.get('head', {}).get('ref') == self.branch
                    and data.get('base', {}).get('ref') == 'main', 'pr_subject')
            require(type(user.get('id')) is int and re.fullmatch('[a-f0-9]{40}', data['head'].get('sha', '')),
                    'pr_identity_fields')
            self.pr = {'number': data['number'], 'author': user['login'], 'author_id': user['id'],
                       'head_sha': data['head']['sha'], 'base_sha_at_create': self.base_sha,
                       'url': 'https://github.com/' + REPO + '/pull/' + str(data['number'])}
            result = self.pr
        else:
            result = {'written': True}
        self.steps += 1
        return result


def command(cfg, unit):
    args = ['/usr/bin/systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--unit=' + unit,
            '--property=User=' + str(cfg['worker_uid']), '--property=Group=' + str(cfg['worker_gid']),
            '--property=KillMode=control-group', '--property=MemoryMax=256M', '--property=MemorySwapMax=0', '--property=TasksMax=16',
            '--property=CPUQuota=100%', '--property=RuntimeMaxSec=120', '--property=LimitCORE=0',
            '--property=LimitFSIZE=1048576', '--property=NoNewPrivileges=yes', '--property=ProtectHome=yes',
            '--property=ProtectControlGroups=yes', '--property=PrivateTmp=yes',
            '/usr/bin/bwrap', '--unshare-all', '--unshare-user', '--die-with-parent', '--new-session', '--cap-drop', 'ALL',
            '--uid', str(cfg['worker_uid']), '--gid', str(cfg['worker_gid']), '--disable-userns',
            '--clearenv', '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
            '--ro-bind', '/lib64', '/lib64', '--ro-bind', str(ROOT / 'worker-root'), '/app',
            '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/run',
            '--dir', '/work', '--chdir', '/work', '--setenv', 'PATH', '/usr/bin:/bin',
            '--setenv', 'LANG', 'C.UTF-8', '/usr/bin/python3', '-I', '-B', '/app/worker.py']
    return args


def observe(unit, cfg):
    cgroup = run(['systemctl', 'show', unit, '-p', 'ControlGroup', '--value']).decode().strip()
    require(cgroup == '/system.slice/' + unit, 'unexpected_cgroup')
    pids = (Path('/sys/fs/cgroup') / cgroup.lstrip('/') / 'cgroup.procs').read_text().splitlines()
    require(len(pids) <= 16, 'process_bound')
    cg = Path('/sys/fs/cgroup') / cgroup.lstrip('/')
    limits = {name: (cg / name).read_text().strip() for name in ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max']}
    require(limits['memory.max'] == '268435456' and limits['memory.swap.max'] == '0'
            and limits['pids.max'] == '16', 'cgroup_limits')
    quota, period = limits['cpu.max'].split()
    require(quota != 'max' and 0 < int(quota) <= int(period), 'cpu_limit')
    runtime = run(['systemctl', 'show', unit, '-p', 'RuntimeMaxUSec', '--value']).decode().strip()
    require(runtime in ('2min', '120s', '120000000'), 'runtime_limit')
    workers = []
    for pid in pids:
        args = Path('/proc', pid, 'cmdline').read_bytes().split(b'\0')
        if args and args[0].startswith(b'/usr/bin/python3') and b'/app/worker.py' in args:
            workers.append(pid)
    require(len(workers) == 1, 'worker_process_identity')
    pid = workers[0]
    status = dict(line.split(':', 1) for line in Path('/proc', pid, 'status').read_text().splitlines() if ':' in line)
    require({int(n) for n in status['Uid'].split()} == {cfg['worker_uid']}, 'host_worker_uid')
    require(int(status['CapEff'].strip(), 16) == 0 and status['NoNewPrivs'].strip() == '1', 'worker_privileges')
    namespaces = {name: os.stat('/proc/' + pid + '/ns/' + name).st_ino for name in ['pid', 'mnt', 'net', 'user']}
    require(all(value != os.stat('/proc/self/ns/' + name).st_ino for name, value in namespaces.items()),
            'namespace_separation')
    base = Path('/proc', pid, 'root')
    require(all(not (base / name).exists() for name in ['home', 'root', 'var/lib/proofgate-canary', 'run/proofgate-canary']),
            'owner_paths_exposed')
    mounts = Path('/proc', pid, 'mountinfo').read_text().splitlines()
    require(any(row.split()[4] == '/app' and 'ro' in row.split()[5].split(',') for row in mounts), 'source_not_readonly')
    return {'host_worker_uid': cfg['worker_uid'], 'effective_capabilities': 0, 'no_new_privileges': True,
            'namespace_inodes': namespaces, 'owner_paths_absent': True, 'source_readonly': True,
            'cgroup_limits': limits, 'runtime_max_observed': runtime}


def execute(cfg, mode='probe', token=None):
    require(os.getuid() == 0 and mode in ('probe', 'pr'), 'owner_only')
    require((mode == 'probe') == (token is None), 'credential_mode')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    gateway = Gateway(token, mode)
    unit = 'proofgate-worker-' + gateway.run_id + '.service'
    result = {'run_id': gateway.run_id, 'mode': mode, 'completed': False,
              'profile': 'fixed-synthetic-python-worker-v1', 'full_coding_agent_verified': False,
              'A13': 'UNVERIFIED', 'events': gateway.events}
    process = None
    # Only this fixed no-key profile may retain startup text. Never capture it after key import.
    diagnostic = tempfile.TemporaryFile() if mode == 'probe' and not Path(cfg['key_path']).exists() else None
    try:
        process = subprocess.Popen(command(cfg, unit), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=diagnostic if diagnostic is not None else subprocess.DEVNULL,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                                   close_fds=True, bufsize=0)
        selector = selectors.DefaultSelector(); selector.register(process.stdout, selectors.EVENT_READ)
        pending = bytearray(); end = time.monotonic() + 115; hello = False; done = False
        requests = 0
        while not done:
            require(time.monotonic() < end and requests < 8, 'worker_budget')
            require(selector.select(timeout=min(5, max(0, end - time.monotonic()))), 'worker_stalled')
            chunk = os.read(process.stdout.fileno(), 4096)
            require(bool(chunk), 'worker_exited_before_done')
            pending.extend(chunk); require(len(pending) <= 8192, 'worker_output_bound')
            if b'\n' not in pending:
                continue
            line, _, rest = pending.partition(b'\n'); pending = bytearray(rest)
            request = json.loads(line); requests += 1
            require(isinstance(request, dict), 'worker_protocol')
            if not hello:
                require(set(request) == {'op', 'observations'} and request['op'] == 'hello', 'hello_required')
                observed = observe(unit, cfg); local = request['observations']
                require(set(local) == {'uid', 'gid', 'marker_blocked', 'source_readonly', 'network_blocked',
                                      'owner_environment_absent', 'owner_paths_absent', 'namespace_inodes'}, 'observation_shape')
                require(local['uid'] == cfg['worker_uid'] and local['gid'] == cfg['worker_gid']
                        and local['namespace_inodes'] == observed['namespace_inodes'], 'observation_identity')
                require(all(local[name] is True for name in ['marker_blocked', 'source_readonly', 'network_blocked',
                                                            'owner_environment_absent', 'owner_paths_absent']), 'isolation_failed')
                result['independent_os_observations'] = observed
                result['worker_observations'] = local
                hello = True
                data = {'mode': mode, 'branch': gateway.branch, 'run_id': gateway.run_id}
            elif request == {'op': 'done'}:
                require(mode == 'probe' or gateway.pr is not None, 'missing_app_pr')
                done = True; data = {'finished': True}
            else:
                data = gateway.call(request)
            process.stdin.write(json.dumps({'ok': True, 'data': data}).encode() + b'\n')
            process.stdin.flush()
        require(process.wait(timeout=5) == 0, 'worker_failed')
        result.update(completed=True, pr=gateway.pr)
        return result
    except Exception as error:
        result['failure'] = str(error) if type(error) is Stop else type(error).__name__
        raise Stop('sandbox_failed') from None
    finally:
        if process is not None:
            # Unit name is generated here, never supplied by the candidate.
            subprocess.run(['systemctl', 'kill', '--kill-whom=all', '--signal=KILL', unit],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if process.poll() is None:
                process.kill(); process.wait(timeout=5)
        if diagnostic is not None:
            diagnostic.seek(0)
            text = diagnostic.read(4096).decode('utf-8', errors='replace')
            if text:
                result['no_key_startup_diagnostic'] = text
            diagnostic.close()
        record(gateway.run_id, result)
