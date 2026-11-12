"""Owner-only entrypoint: preflight, private import, trial, read-only A14 observation."""
import argparse
import json
import os
from pathlib import Path
import resource
import socket
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from owner_vm.common import ROOT, STATE, CONFIG, UNIT, REPO, REPO_ID, APP_ID, INSTALLATION_ID, OWNER_ID, require, config, protected, run, write, record
from owner_vm.sandbox import execute, github


def preflight():
    cfg = config(gate=False)
    fixture = protected(STATE / 'issuer/owner-boundary-fixture', cfg['issuer_uid'], private=True)
    require(fixture.read_bytes() == b'harmless owner-only canary fixture\n', 'owner_fixture_missing_or_changed')
    result = execute(cfg, mode='probe')
    require(result['completed'], 'preflight_failed')
    original = json.loads(CONFIG.read_text())
    original['owner_isolation_verified'] = True
    write(CONFIG, json.dumps(original, indent=2) + '\n', mode=0o644)
    return {'preflight_passed': True, 'run_id': result['run_id'], 'owner_fixture_exists_outside': True,
            'profile': result['profile'], 'full_coding_agent_verified': False,
            'external_photon_exclusion': 'owner acknowledged; not remotely proven'}


def import_key(source):
    cfg = config()
    target = Path(cfg['key_path'])
    require(not target.exists() and not target.is_symlink(), 'key_already_exists_no_rotation')
    owner_uid = int(os.environ.get('SUDO_UID', '0'))
    source = Path(source).absolute()
    for part in [*reversed(source.parents), source]:
        metadata = part.lstat()
        require(not stat.S_ISLNK(metadata.st_mode) and metadata.st_uid in (0, owner_uid)
                and not metadata.st_mode & 0o022, 'unsafe_key_ancestor')
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid in (0, owner_uid)
                and stat.S_IMODE(metadata.st_mode) in (0o400, 0o600)
                and 0 < metadata.st_size <= 16384, 'unsafe_key_source')
        value = os.read(fd, 16385)
    finally:
        os.close(fd)
    result = subprocess.run(['/usr/bin/openssl', 'pkey', '-check', '-noout'], input=value,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    require(result.returncode == 0, 'invalid_private_key')
    import pwd
    user = pwd.getpwuid(cfg['issuer_uid'])
    write(target, value, mode=0o400, uid=user.pw_uid, gid=user.pw_gid, exclusive=True)
    return {'key_imported': True, 'key_generated': False, 'issuer_started': False}


def with_lease(cfg, action):
    from issuer.runtime import config as issuer_config, exchange, peer_uid
    issuer_config(str(CONFIG))
    protected(cfg['key_path'], cfg['issuer_uid'], private=True)
    run(['systemctl', 'start', UNIT], timeout=20)
    def rpc(request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5); connection.connect(cfg['socket_path'])
            require(peer_uid(connection) == cfg['issuer_uid'], 'issuer_peer')
            return exchange(connection, request)
    # Type=simple may report started before socket creation; bounded metadata-only readiness wait.
    end = time.monotonic() + 10
    while not Path(cfg['socket_path']).exists():
        require(time.monotonic() < end, 'issuer_not_ready'); time.sleep(0.1)
    lease = rpc({'op': 'issue'})
    report = {'app_id': APP_ID, 'installation_id': INSTALLATION_ID, 'repository_id': REPO_ID,
              'provider_expires_at': lease['provider_expires_at'], 'A13': 'UNVERIFIED',
              'completed': False, 'revocation_verified': False}
    success = False
    try:
        status, inventory = github('GET', '/installation/repositories?per_page=100', lease['token'])
        require(status == 200 and type(inventory.get('total_count')) is int and inventory['total_count'] == 1
                and len(inventory['repositories']) == 1 and inventory['repositories'][0]['id'] == REPO_ID,
                'token_scope')
        report['token_scope_exact'] = True
        report['result'] = action(lease['token'])
        success = True
    finally:
        # Always ask immutable issuer to revoke, then independently test denied use.
        try:
            rpc({'op': 'release', 'lease_id': lease['lease_id'], 'outcome': 'success' if success else 'failure'})
            status, _ = github('GET', '/installation/repositories?per_page=100', lease['token'])
            report['revocation_http_status'] = status
            report['revocation_verified'] = status == 401
            require(status == 401, 'revocation_unverified_owner_containment_required')
            report['completed'] = success
        finally:
            record('trial' + lease['lease_id'], report)
    return report


def trial():
    cfg = config()
    preflight()  # Rerun real no-key/no-GitHub OS checks immediately before issuance.
    return with_lease(cfg, lambda token: execute(cfg, mode='pr', token=token))


def a14(number, human_ack):
    require(type(number) is int and number > 0 and human_ack, 'human_ui_ack_required')
    config()  # Installed pins/binding only. Observation never needs another App lease.
    from owner_vm.a14 import recover
    return recover(number, human_ack)



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('preflight'); sub.add_parser('trial')
    key = sub.add_parser('import-key'); key.add_argument('source')
    positive = sub.add_parser('observe-a14'); positive.add_argument('number', type=int)
    positive.add_argument('--human-ui-approval-and-merge', action='store_true')
    args = parser.parse_args()
    try:
        require(os.getuid() == 0, 'owner_only'); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if args.command == 'preflight': result = preflight()
        elif args.command == 'import-key': result = import_key(args.source)
        elif args.command == 'trial': result = trial()
        else: result = a14(args.number, args.human_ui_approval_and_merge)
        print(json.dumps(result, sort_keys=True))
    except Exception as error:
        from owner_vm.common import Stop
        code = str(error) if type(error) is Stop else type(error).__name__
        # Recovery must never replace the historical failed-observation receipt.
        if args.command != 'observe-a14':
            try:
                import traceback
                record('controlfailure', {'command': args.command, 'failure': code,
                                         'frames': [{'file': Path(row.filename).name, 'line': row.lineno}
                                                    for row in traceback.extract_tb(error.__traceback__)]})
            except Exception:
                pass
        print('owner_control_failed:' + code, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
