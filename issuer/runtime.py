"""Owner-installed runtime gates. Unbound templates cannot start a service."""
import hashlib
import json
import os
from pathlib import Path
import stat

from .core import APP, INSTALLATION, OWNER, REPOSITORY, NAME, PERMISSIONS, require, deadline


def secure_path(path, owner, private=False):
    require(isinstance(path, str) and Path(path).is_absolute(), 'unbound_path')
    parts = list(reversed(Path(path).parents)) + [Path(path)]
    for index, part in enumerate(parts):
        metadata = part.lstat()
        require(not stat.S_ISLNK(metadata.st_mode), 'symlink_forbidden')
        require(metadata.st_uid in (0, owner) and not metadata.st_mode & 0o022, 'unsafe_path')
        if index == len(parts) - 1:
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == owner, 'unsafe_file')
            require(not private or not metadata.st_mode & 0o077, 'private_file_mode')
    return Path(path)


def config(path):
    source = secure_path(path, 0)
    require(source.stat().st_size <= 8192, 'config_bound')
    value = json.loads(source.read_text())
    expected = {'schema', 'app_id', 'installation_id', 'owner_id', 'repository_id', 'repository',
                'permissions', 'issuer_uid', 'launcher_uid', 'worker_uid', 'photon_uid',
                'socket_path', 'audit_path', 'state_path', 'key_path', 'worker_launcher_path',
                'worker_launcher_sha256', 'owner_isolation_verified'}
    require(isinstance(value, dict) and set(value) == expected and type(value['schema']) is int
            and value['schema'] == 1, 'config_schema')
    for name, number in [('app_id', APP), ('installation_id', INSTALLATION),
                         ('owner_id', OWNER), ('repository_id', REPOSITORY)]:
        require(type(value[name]) is int and value[name] == number, 'config_binding')
    require(value['repository'] == NAME and value['permissions'] == PERMISSIONS, 'config_scope')
    names = ['issuer_uid', 'launcher_uid', 'worker_uid', 'photon_uid']
    require(all(type(value[n]) is int and value[n] >= 0 for n in names), 'unbound_uid')
    require(len({value[n] for n in names}) == 4, 'identities_not_separate')
    require(value['issuer_uid'] != 0 and value['worker_uid'] != 0, 'unsafe_uid')
    require(value['owner_isolation_verified'] is True, 'owner_isolation_gate')
    for name in ['socket_path', 'audit_path', 'state_path', 'key_path', 'worker_launcher_path']:
        require(isinstance(value[name], str) and Path(value[name]).is_absolute(), 'unbound_path')
    digest = value['worker_launcher_sha256']
    require(isinstance(digest, str) and len(digest) == 64
            and all(c in '0123456789abcdef' for c in digest), 'unbound_launcher_digest')
    launcher = secure_path(value['worker_launcher_path'], 0)
    require(hashlib.sha256(launcher.read_bytes()).hexdigest() == digest, 'launcher_changed')
    return value


def peer_uid(connection):
    import socket
    import struct
    return struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]


class State:
    """Persistent secret-free restart interlock; only owner containment permits reset."""
    def __init__(self, path, uid):
        self.path = secure_path(path, uid, private=True)

    def begin(self):
        with self.path.open('rb') as stream:
            value = stream.read(257)
        require(len(value) <= 256 and json.loads(value) == {'state': 'ready'}, 'owner_recovery_required')
        self.write('running')

    def write(self, value):
        require(value in ('running', 'blocked', 'ready'), 'invalid_state')
        fd = os.open(self.path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
        try:
            data = (json.dumps({'state': value}) + '\n').encode()
            require(os.write(fd, data) == len(data), 'state_write_failed')
            os.fsync(fd)
        finally:
            os.close(fd)


def exchange(connection, request):
    with deadline(120):
        return _exchange(connection, request)


def _exchange(connection, request):
    # Eight provider requests each have an absolute10s budget; leave room for revocation.
    connection.settimeout(120)
    connection.sendall(json.dumps(request).encode() + b'\n')
    line = connection.makefile('rb').readline(16385)
    require(len(line) <= 16384 and line.endswith(b'\n'), 'ipc_response_bound')
    response = json.loads(line)
    require(isinstance(response, dict) and 'error' not in response, 'issuer_denied')
    return response
