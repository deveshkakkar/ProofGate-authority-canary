"""Trusted launcher adapter, NOT a sandbox. Owner supplies verified worker launcher."""
import json
import os
import resource
import socket
import subprocess
import sys
import time

from .core import require, deadline
from .runtime import config, exchange, peer_uid


def invoke(configuration):
    require(os.getuid() == configuration['launcher_uid'], 'wrong_launcher_uid')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def call(request):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(configuration['socket_path'])
            require(peer_uid(connection) == configuration['issuer_uid'], 'wrong_issuer_peer')
            return exchange(connection, request)
    lease = call({'op': 'issue'})
    read_fd = write_fd = None
    process = None
    outcome = 'launcher_failure'
    try:
        require(set(lease) == {'lease_id', 'token', 'lease_seconds', 'provider_expires_at', 'lease_deadline_monotonic'}
                and lease['lease_seconds'] == 300, 'invalid_lease')
        remaining = lease['lease_deadline_monotonic'] - time.monotonic()
        require(remaining >= 30, 'expired_local_lease')
        read_fd, write_fd = os.pipe()
        # Never forward issuer responses or worker output into coordinator logs.
        process = subprocess.Popen([configuration['worker_launcher_path']],
                                   env={'PATH': '/usr/bin:/bin', 'PROOFGATE_TOKEN_FD': str(read_fd)},
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, close_fds=True, pass_fds=(read_fd,))
        os.close(read_fd); read_fd = None
        payload = (json.dumps(lease) + '\n').encode()
        require(len(payload) <= 16384, 'lease_bound')
        with deadline(5):
            require(os.write(write_fd, payload) == len(payload), 'credential_delivery_failed')
        os.close(write_fd); write_fd = None
        # The worker runs within the issuer lease, with time left for revocation.
        try:
            result = process.wait(timeout=min(240, remaining - 15))
        except subprocess.TimeoutExpired:
            outcome = 'timeout'
            raise
        outcome = 'success' if result == 0 else 'failure'
        require(result == 0, 'worker_failed')
        return 0
    finally:
        try:
            for fd in [read_fd, write_fd]:
                if fd is not None:
                    os.close(fd)
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            # Fixed trusted worker launcher must additionally terminate its entire sandbox/cgroup.
        finally:
            call({'op': 'release', 'lease_id': lease['lease_id'], 'outcome': outcome})


def main():
    try:
        require(len(sys.argv) == 2, 'config_required')
        return invoke(config(sys.argv[1]))
    except Exception:
        print('launcher_failed_owner_review_required', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
