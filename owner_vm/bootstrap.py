#!/usr/bin/python3
"""Owner executes on a fresh isolated VM. No private-key generation, no remote login."""
import argparse
import grp
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import pwd
import stat
import signal
import subprocess
import sys
import tarfile
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from owner_vm.common import ROOT, ETC, STATE, SOCKET, CONFIG, UNIT, REVISION, PROFILE_SHA, require, run, write, digest, protected

HERE = Path(__file__).resolve().parent
NAMES = {'issuer': 'pg-issuer', 'worker': 'pg-worker', 'denied_fixture': 'pg-denied'}


def download(url, maximum):
    require(url.startswith(('https://codeload.github.com/', 'https://files.pythonhosted.org/')), 'download_host')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def expired(*_):
        raise TimeoutError
    previous = signal.signal(signal.SIGALRM, expired); signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        with opener.open(url, timeout=30) as response:
            value = response.read(maximum + 1)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, previous)
    require(len(value) <= maximum, 'download_bound')
    return value


def verify_bundle():
    manifest = json.loads((HERE / 'bundle-manifest.json').read_text())
    require(manifest['schema'] == 1, 'bundle_schema')
    for name, expected in manifest['files'].items():
        require(Path(name).name == name and name != 'bundle-manifest.json', 'bundle_path')
        source = HERE / name
        require(source.is_file() and not source.is_symlink() and digest(source) == expected, 'bundle_changed')
    return manifest


def unpack_issuer(archive, manifest):
    require(manifest['revision'] == REVISION, 'issuer_revision')
    expected = manifest['files']; result = {}
    with gzip.GzipFile(fileobj=io.BytesIO(archive)) as stream:
        plain = stream.read(4194305)
    require(len(plain) <= 4194304, 'archive_expansion_bound')
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as tar:
        require(len(tar.getmembers()) <= 200, 'archive_members')
        for member in tar.getmembers():
            parts = Path(member.name).parts
            require(not Path(member.name).is_absolute() and '..' not in parts
                    and (member.isfile() or member.isdir()), 'archive_path')
            name = '/'.join(parts[1:])
            if name in expected:
                require(member.isfile() and name not in result and member.size <= 262144, 'issuer_member')
                value = tar.extractfile(member).read()
                require(hashlib.sha256(value).hexdigest() == expected[name], 'issuer_content_changed')
                result[name] = value
    require(set(result) == set(expected), 'issuer_files_missing')
    return result


def account(name):
    try:
        row = pwd.getpwnam(name)
    except KeyError:
        run(['useradd', '--system', '--user-group', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', name])
        row = pwd.getpwnam(name)
    require(0 < row.pw_uid < 1000 and row.pw_dir == '/nonexistent'
            and row.pw_shell == '/usr/sbin/nologin'
            and grp.getgrgid(row.pw_gid).gr_name == name
            and set(os.getgrouplist(name, row.pw_gid)) == {row.pw_gid}, 'unsafe_existing_account')
    return row


def directory(path, mode, uid=0, gid=0):
    path = Path(path)
    if path.exists():
        require(path.is_dir() and not path.is_symlink() and path.stat().st_uid == uid,
                'unsafe_existing_directory')
    else:
        path.mkdir(mode=mode)
        os.chown(path, uid, gid)
        os.chmod(path, mode)
    require(stat.S_IMODE(path.stat().st_mode) == mode, 'directory_mode_drift')


def previous_setup(marker, bundle_sha):
    """Resume only this exact managed intent; never silently adopt a different deployment."""
    protected(marker)
    require(json.loads(marker.read_text()) == {'issuer_revision': REVISION, 'bundle_sha256': bundle_sha},
            'bootstrap_revision_drift')
    if CONFIG.exists() and (ETC / 'installation.json').exists():
        from owner_vm.common import verify_install
        verify_install()
        run([str(ROOT / 'bin/owner-control'), 'preflight'], timeout=180)
        return True
    active = subprocess.run(['systemctl', 'is-active', '--quiet', UNIT],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    require(active.returncode != 0, 'partial_installation_service_active')
    return False


def prepare(ack):
    require(os.getuid() == 0 and ack, 'fresh_owner_vm_ack_required')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    require(release.get('ID', '').strip('"') == 'ubuntu'
            and release.get('VERSION_ID', '').strip('"') == '24.04'
            and platform.machine() == 'x86_64', 'ubuntu_2404_amd64_required')
    run(['systemd-detect-virt', '--vm'])
    require(not any(Path('/proc', p, 'comm').read_text().strip().lower() in ('codex', 'photon')
                    for p in os.listdir('/proc') if p.isdigit() and Path('/proc', p, 'comm').exists()),
            'photon_process_present')
    bundle = verify_bundle()
    # Never adopt or replace unrelated working directories/services.
    marker = STATE / 'bootstrap-intent.json'
    if marker.exists():
        if previous_setup(marker, digest(HERE / 'bundle-manifest.json')):
            return {'prepared': True, 'existing_installation_verified': True, 'key_unchanged': True}
    else:
        require(all(not p.exists() and not p.is_symlink() for p in
                    [ROOT, ETC, STATE, SOCKET.parent, Path('/etc/systemd/system') / UNIT]), 'existing_deployment_requires_review')
        directory(STATE, 0o755)
        write(marker, json.dumps({'issuer_revision': REVISION,
                                'bundle_sha256': digest(HERE / 'bundle-manifest.json')}), mode=0o644, exclusive=True)
    run(['apt-get', 'update', '-qq'], timeout=300)
    run(['apt-get', 'install', '--yes', '--no-install-recommends', 'python3-venv', 'bubblewrap',
         'apparmor-profiles', 'ca-certificates', 'openssl'], timeout=600)
    profile = Path('/usr/share/apparmor/extra-profiles/bwrap-userns-restrict')
    require(digest(profile) == PROFILE_SHA, 'apparmor_profile_revision_changed')
    for name in ['bwrap-userns-restrict', 'unpriv_bwrap']:
        local = Path('/etc/apparmor.d/local') / name
        require(not local.exists() or all(not line.strip() or line.lstrip().startswith('#')
                                         for line in local.read_text().splitlines()), 'apparmor_override_present')
    run(['/usr/sbin/apparmor_parser', '-r', str(profile)])
    users = {role: account(name) for role, name in NAMES.items()}
    require(len({r.pw_uid for r in users.values()}) == 3, 'account_collision')
    for path in [ROOT, ETC]: directory(path, 0o755)
    for path in [ROOT / 'deployment', ROOT / 'cache', ROOT / 'worker-root', ROOT / 'bin']:
        directory(path, 0o755)
    directory(ROOT / 'deployment/owner_vm', 0o755)
    for name in bundle['files']:
        write(ROOT / 'deployment/owner_vm' / name, (HERE / name).read_bytes(), mode=0o644)
    write(ROOT / 'deployment/owner_vm/bundle-manifest.json', (HERE / 'bundle-manifest.json').read_bytes(), mode=0o644)
    run(['/usr/bin/python3', '-m', 'venv', str(ROOT / 'venv')], timeout=60)
    wheels = json.loads((HERE / 'wheels.lock.json').read_text())
    require(sum(row['size'] for row in wheels) < 30000000, 'dependency_budget')
    for row in wheels:
        value = download(row['url'], row['size'])
        require(hashlib.sha256(value).hexdigest() == row['sha256'], 'dependency_hash')
        write(ROOT / 'cache' / row['filename'], value, mode=0o644)
    run([str(ROOT / 'venv/bin/python'), '-I', '-m', 'pip', 'install', '--no-index', '--no-deps',
         '--only-binary=:all:', '--require-hashes', '--find-links', str(ROOT / 'cache'),
         '-r', str(ROOT / 'deployment/owner_vm/requirements.lock')], timeout=120)
    site = run([str(ROOT / 'venv/bin/python'), '-I', '-c',
                'import sysconfig; print(sysconfig.get_path("purelib"))']).decode().strip()
    issuer = unpack_issuer(download('https://codeload.github.com/' +
                                   'deveshkakkar/ProofGate-authority-canary/tar.gz/' + REVISION, 2097152),
                           json.loads((HERE / 'issuer-manifest.json').read_text()))
    directory(Path(site) / 'issuer', 0o755)
    for name, value in issuer.items():
        write(Path(site) / name, value, mode=0o644)
    write(ROOT / 'worker-root/worker.py', (HERE / 'worker.py').read_bytes(), mode=0o644)
    for command, mode in [('owner-control', 'control'), ('sandbox-launcher', 'entry')]:
        script = '#!/bin/sh\nexec ' + str(ROOT / 'venv/bin/python') + ' -I -B ' + str(ROOT / 'deployment/owner_vm') + '/' + mode + '.py "$@"\n'
        write(ROOT / 'bin' / command, script, mode=0o755)
    issuer_user = users['issuer']
    directory(STATE / 'issuer', 0o700, issuer_user.pw_uid, issuer_user.pw_gid)
    directory(STATE / 'results', 0o700)
    for name, value in [('audit.jsonl', ''), ('state.json', '{"state":"ready"}\n'),
                        ('owner-boundary-fixture', 'harmless owner-only canary fixture\n')]:
        target = STATE / 'issuer' / name
        if not target.exists(): write(target, value, uid=issuer_user.pw_uid, gid=issuer_user.pw_gid, exclusive=True)
    cfg = json.loads(issuer['issuer/owner-config.template.json'])
    cfg.update(issuer_uid=issuer_user.pw_uid, launcher_uid=0, worker_uid=users['worker'].pw_uid,
               photon_uid=users['denied_fixture'].pw_uid, socket_path=str(SOCKET),
               audit_path=str(STATE / 'issuer/audit.jsonl'), state_path=str(STATE / 'issuer/state.json'),
               key_path=str(STATE / 'issuer/app.pem'), worker_launcher_path=str(ROOT / 'bin/sandbox-launcher'),
               worker_launcher_sha256=digest(ROOT / 'bin/sandbox-launcher'), owner_isolation_verified=False)
    if CONFIG.exists():
        prior = json.loads(protected(CONFIG).read_text())
        require({**prior, 'owner_isolation_verified': False} == cfg, 'partial_configuration_drift')
    else:
        write(CONFIG, json.dumps(cfg, indent=2) + '\n', mode=0o644, exclusive=True)
    unit = issuer['issuer/issuer.service.in'].decode()
    values = {'OWNER_SUPPLIED_ISSUER_OS_USER': NAMES['issuer'], 'OWNER_SUPPLIED_PRIVATE_IPC_OS_GROUP': NAMES['issuer'],
              'OWNER_SUPPLIED_VENV_PYTHON': str(ROOT / 'venv/bin/python'), 'OWNER_SUPPLIED_CONFIG_PATH': str(CONFIG),
              'OWNER_SUPPLIED_SOCKET_DIRECTORY': str(SOCKET.parent), 'OWNER_SUPPLIED_AUDIT_FILE': cfg['audit_path'],
              'OWNER_SUPPLIED_STATE_FILE': cfg['state_path'], 'OWNER_SUPPLIED_KEY_PATH': cfg['key_path']}
    for key, value in values.items(): unit = unit.replace('@' + key + '@', value)
    require('@OWNER_' not in unit, 'unit_unbound')
    unit = unit.replace('UMask=0077', 'UMask=0077\nRuntimeDirectory=proofgate-canary\nRuntimeDirectoryMode=0750')
    unit_path = Path('/etc/systemd/system') / UNIT
    if unit_path.exists():
        require(protected(unit_path).read_text() == unit, 'existing_unit_drift')
    else:
        write(unit_path, unit, mode=0o644, exclusive=True)
    installed = [p for directory in [ROOT / 'deployment', ROOT / 'worker-root', ROOT / 'bin', Path(site) / 'issuer']
                 for p in directory.rglob('*') if p.is_file()]
    installed += [Path('/etc/systemd/system') / UNIT]
    manifest = {'issuer_revision': REVISION, 'deployment_bundle_sha256': digest(HERE / 'bundle-manifest.json'),
                'files': {str(p): digest(p) for p in installed},
                'accounts': {role: {'uid': row.pw_uid, 'gid': row.pw_gid} for role, row in users.items()},
                'external_vm_exclusion': 'owner acknowledged; not remotely proven',
                'photon_uid_field': 'Denied-caller fixture UID only; Photon is not present on this VM.'}
    write(ETC / 'installation.json', json.dumps(manifest, indent=2), mode=0o644)
    run(['systemctl', 'daemon-reload'])
    # No service/key/token yet. Invoke actual sandbox preflight in the installed runtime.
    run([str(ROOT / 'bin/owner-control'), 'preflight'], timeout=180)
    return {'prepared': True, 'issuer_started': False, 'key_imported': False,
            'next': 'Owner privately transfers key, then owner-control import-key PATH and owner-control trial.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare'])
    parser.add_argument('--fresh-isolated-vm', action='store_true', help='Owner attests Photon cannot access/administer this fresh VM.')
    args = parser.parse_args()
    try:
        print(json.dumps(prepare(args.fresh_isolated_vm)))
    except Exception as error:
        from owner_vm.common import Stop
        code = str(error) if type(error) is Stop else type(error).__name__
        print('owner_bootstrap_failed:' + code, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
