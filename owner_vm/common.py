"""Chosen VM defaults, not an assertion that these paths/accounts already exist."""
import hashlib
import json
import os
import pwd
import re
from pathlib import Path
import stat
import subprocess

ROOT = Path('/var/lib/proofgate-canary/runtime')
ETC = Path('/etc/proofgate-canary')
STATE = Path('/var/lib/proofgate-canary')
SOCKET = Path('/run/proofgate-canary/issuer.sock')
CONFIG = ETC / 'issuer.json'
UNIT = 'proofgate-canary-issuer.service'
REVISION = '5609432116921acad9f10ef05c17140c170d72fb'
REPO = 'deveshkakkar/ProofGate-authority-canary'
REPO_ID = 1452255523
APP_ID = 5690450
INSTALLATION_ID = 180587357
OWNER_ID = 41484281
PROFILE_SHA = '11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9'


class Stop(Exception):
    """Only internally authored, non-secret error codes cross the CLI boundary."""


def require(ok, code):
    if not ok:
        raise Stop(code)


def run(args, timeout=60, input=None):
    p = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       timeout=timeout, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                             'LANG': 'C.UTF-8', 'DEBIAN_FRONTEND': 'noninteractive'})
    if p.returncode != 0:
        # Only forward this trusted CLI's fixed error code, never arbitrary subprocess output.
        safe = re.fullmatch(rb'owner_control_failed:([A-Za-z0-9_]+)\n', p.stderr)
        if Path(args[0]).name == 'owner-control' and safe:
            raise Stop('preflight_' + safe[1].decode())
        raise Stop('trusted_command_failed_' + Path(args[0]).name)
    return p.stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def protected(path, uid=0, private=False):
    path = Path(path)
    require(path.is_absolute(), 'path_not_absolute')
    for part in [*reversed(path.parents), path]:
        s = part.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid in (0, uid)
                and not s.st_mode & 0o022, 'unsafe_path')
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == uid
            and (not private or not s.st_mode & 0o077), 'unsafe_file')
    return path


def write(path, data, mode=0o600, uid=0, gid=0, exclusive=False):
    path = Path(path)
    flags = os.O_WRONLY | os.O_NOFOLLOW | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, mode)
    try:
        raw = data.encode() if isinstance(data, str) else data
        require(os.write(fd, raw) == len(raw), 'short_write')
        os.fchmod(fd, mode); os.fchown(fd, uid, gid); os.fsync(fd)
    finally:
        os.close(fd)


def config(gate=True):
    data = json.loads(protected(CONFIG).read_text())
    require(data['app_id'] == APP_ID and data['installation_id'] == INSTALLATION_ID
            and data['owner_id'] == OWNER_ID and data['repository_id'] == REPO_ID
            and data['repository'] == REPO, 'configuration_binding')
    require(data['launcher_uid'] == 0 and data['worker_uid'] > 0
            and len({data[k] for k in ['issuer_uid', 'launcher_uid', 'worker_uid', 'photon_uid']}) == 4,
            'uid_separation')
    if gate:
        require(data['owner_isolation_verified'] is True, 'preflight_required')
    verify_install()
    data['worker_gid'] = pwd.getpwuid(data['worker_uid']).pw_gid
    return data


def verify_install():
    manifest = json.loads(protected(ETC / 'installation.json').read_text())
    require(manifest['issuer_revision'] == REVISION, 'issuer_revision_changed')
    for name, expected in manifest['files'].items():
        require(name.startswith(str(ROOT) + '/') or name == '/etc/systemd/system/' + UNIT,
                'manifest_path')
        require(digest(protected(name)) == expected, 'installed_code_changed')
    return manifest


def record(name, value):
    require(name.isalnum(), 'result_name')
    write(STATE / 'results' / (name + '.json'), json.dumps(value, sort_keys=True, indent=2) + '\n')
