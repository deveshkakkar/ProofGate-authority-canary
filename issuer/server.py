"""Run only as the owner-provisioned dedicated issuer UID, outside Photon."""
import json
import os
from pathlib import Path
import resource
import signal
import socket
import sys

from .core import APP, Denied, GitHub, Issuer, require, deadline
from .runtime import config, peer_uid, secure_path, State


def handle(connection, issuer, launcher_uid, stopping):
    connection.settimeout(2)
    uid = peer_uid(connection)
    issued_here = False
    try:
        require(uid == launcher_uid, 'peer_denied')
        with deadline(2):
            line = connection.makefile('rb').readline(4097)
        require(len(line) <= 4096 and line.endswith(b'\n'), 'ipc_request_bound')
        issuer.event('launcher_request', peer_uid=uid)
        result = issuer.request(json.loads(line), uid, launcher_uid)
        issued_here = 'token' in result
        if stopping():
            issuer.release()
            raise Denied('issuer_stopping')
        connection.sendall(json.dumps(result).encode() + b'\n')
    except Exception:
        if issued_here:
            issuer.release()  # A disconnected launcher must not leave a minted token active.
        issuer.event('request_denied', peer_uid=uid)
        try:
            connection.sendall(b'{"error":"request_denied"}\n')
        except OSError:
            pass


def serve(configuration):
    require(os.getuid() == configuration['issuer_uid'], 'wrong_issuer_uid')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    state = State(configuration['state_path'], configuration['issuer_uid'])
    state.begin()  # Durable before any key/signing/provider operation; crashes block restart.
    key = secure_path(configuration['key_path'], configuration['issuer_uid'], private=True)
    require(key.stat().st_size <= 16384, 'key_size')
    key_bytes = key.read_bytes()  # Only the dedicated owner-controlled issuer reads this file.
    import jwt
    def sign(now):
        return jwt.encode({'iat': now - 60, 'exp': now + 240, 'iss': str(APP)}, key_bytes, algorithm='RS256')
    audit_path = Path(configuration['audit_path'])
    # Owner pre-creates the audit file; never follow a caller-selected path or symlink.
    secure_path(str(audit_path), configuration['issuer_uid'], private=True)
    def audit(row):
        fd = os.open(audit_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            require(os.fstat(fd).st_size <= 1044480, 'audit_capacity')
            data = (json.dumps(row, sort_keys=True) + '\n').encode()
            require(os.write(fd, data) == len(data), 'audit_write_failed')
            os.fsync(fd)
        finally:
            os.close(fd)
    endpoint = Path(configuration['socket_path'])
    parent = endpoint.parent.lstat()
    require(parent.st_uid == configuration['issuer_uid'] and not parent.st_mode & 0o027
            and not endpoint.exists() and not endpoint.is_symlink(), 'unsafe_socket_directory')
    # Parent and every ancestor must be protected from worker/Photon path substitution.
    for ancestor in [endpoint.parent, *endpoint.parent.parents]:
        st = ancestor.lstat()
        require(not ancestor.is_symlink() and st.st_uid in (0, configuration['issuer_uid'])
                and not st.st_mode & 0o022, 'unsafe_socket_ancestor')
    issuer = Issuer(GitHub(audit), sign, audit, latch=lambda: state.write('blocked'))
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(endpoint))
    os.chmod(endpoint, 0o660)
    server.listen(1)
    server.settimeout(1)
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True  # Capture a potentially issued token before cleanup; do not interrupt POST.
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    issuer.event('issuer_started', issuer_uid=os.getuid(), launcher_uid=configuration['launcher_uid'])
    try:
        while not stopping:
            issuer.expire()
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            with connection:
                handle(connection, issuer, configuration['launcher_uid'], lambda: stopping)
    finally:
        try:
            issuer.release()
            if stopping and not issuer.poisoned and not issuer.latch_failed:
                state.write('ready')
        finally:
            server.close()
            endpoint.unlink(missing_ok=True)


def main():
    try:
        require(len(sys.argv) == 2, 'config_required')
        serve(config(sys.argv[1]))
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('issuer_start_or_runtime_failed', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
