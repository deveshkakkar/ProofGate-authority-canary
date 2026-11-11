"""Unprivileged local checks only; no daemon API, VM, account or service changes."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from . import gate


class GateTests(unittest.TestCase):
    def test_local_socket_ability_is_reported_as_failure_without_api_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory, 'harmless.sock'))
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(path); listener.listen(1)
                self.assertEqual(gate.denied_socket(path), 'UNEXPECTED_ACCESS')
                client, _ = listener.accept()
                with client:
                    self.assertEqual(client.recv(1), b'')  # No Docker/LXD/libvirt operation was sent.

    def test_disk_open_test_never_reads_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'harmless-disk-fixture'); path.write_bytes(b'harmless test data')
            with patch.object(gate.os, 'read', side_effect=AssertionError('data must never be read')):
                self.assertEqual(gate.denied_open(str(path)), 'UNEXPECTED_ACCESS')

    def test_absence_is_not_a_permission_denial(self):
        self.assertEqual(gate.denied_socket('/nonexistent/proofgate-test.sock'), 'ABSENT_OR_MASKED')

    def test_inherited_connection_is_detected_without_messages(self):
        left, right = socket.socketpair()
        with left, right:
            self.assertGreaterEqual(gate.inherited_authority([]), 2)

    def test_unsafe_effective_groups_stop_before_socket_probe(self):
        status = {'NoNewPrivs': '0', 'CapEff': '0', 'CapPrm': '0', 'CapAmb': '0', 'CapBnd': '0'}
        baseline = Mock(); baseline.read_text.return_value = json.dumps({'uid': 812, 'gid': 812, 'vm_disks': []})
        with patch.object(gate, 'snapshot', return_value={'unsafe_groups': ['docker']}), \
             patch.object(gate.os, 'getuid', return_value=812), patch.object(gate.os, 'geteuid', return_value=812), \
             patch.object(gate.os, 'getgid', return_value=812), patch.object(gate.os, 'getgroups', return_value=[812]), \
             patch.object(gate, 'protected', return_value=baseline), patch.object(gate, 'status', return_value=status), \
             patch.object(gate, 'denied_socket') as connects:
            self.assertFalse(gate.probe()['passed']); connects.assert_not_called()

    def test_owner_guest_commands_stop_on_wrong_hostname_before_extract_or_sudo(self):
        text = Path(__file__).with_name('OWNER-COMMANDS.md').read_text()
        block = next(b.split('```', 1)[0] for b in text.split('```sh\n')[1:] if 'hostname -s' in b.split('```', 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'hostname').write_text('#!/bin/sh\nprintf wrong-host\n')
            (root / 'hostname').chmod(0o755)
            for name in ['sha256sum', 'tar', 'sudo']:
                target = root / name
                target.write_text('#!/bin/sh\nprintf reached >> "$SENTINEL"\nexit 0\n')
                target.chmod(0o755)
            result = subprocess.run(['/bin/sh', '-c', block], cwd=root,
                                    env={'PATH': str(root), 'SENTINEL': str(root / 'reached')}, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'reached').exists())

    def test_owner_host_commands_refuse_existing_helper_without_sudo(self):
        text = Path(__file__).with_name('OWNER-COMMANDS.md').read_text()
        block = next(b.split('```', 1)[0] for b in text.split('```sh\n')[1:] if 'test ! -e' in b.split('```', 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'existing'
            (root / 'sudo').write_text('#!/bin/sh\nprintf reached >> "$SENTINEL"\nexit 0\n')
            (root / 'sudo').chmod(0o755)
            for dangling in [False, True]:
                if dangling: target.symlink_to(root / 'missing')
                else: target.mkdir()
                result = subprocess.run(['/bin/sh', '-c', block.replace('/usr/local/libexec/proofgate-host-boundary', str(target))],
                                        cwd=root, env={'PATH': str(root), 'SENTINEL': str(root / 'reached')}, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'reached').exists())
                if dangling: target.unlink()
                else: target.rmdir()

    def test_root_launcher_does_not_inherit_owner_environment_or_change_owner_account(self):
        baseline = Mock(); baseline.read_text.return_value = json.dumps({'uid': 812, 'gid': 812, 'vm_disks': ['/safe/image.qcow2']})
        executable = Path('/usr/bin/true')
        def safe(path): return baseline if path == gate.BASELINE else executable
        with patch.object(gate.os, 'getuid', return_value=0), patch.object(gate, 'old_agents', return_value=[]), \
             patch.object(gate, 'protected', side_effect=safe), \
             patch.object(gate.pwd, 'getpwnam', return_value=Mock(pw_uid=812)), \
             patch.object(gate.os, 'getgrouplist', return_value=[812]), \
             patch.object(gate.subprocess, 'call', return_value=0) as launch:
            self.assertEqual(gate.launch(['/usr/bin/true']), 0)
            args = launch.call_args.args[0]
            self.assertIn('--property=User=pg-photon-host', args)
            self.assertIn('--property=CapabilityBoundingSet=', args)
            self.assertIn('--property=NoNewPrivileges=yes', args)
            self.assertIn('--property=MemoryMax=1G', args)
            self.assertIn('--property=MemorySwapMax=0', args)
            self.assertIn('--property=TasksMax=128', args)
            self.assertIn('--property=CPUQuota=100%', args)
            self.assertIn('--property=RuntimeMaxSec=30min', args)
            self.assertTrue(any('-/safe/image.qcow2' in value for value in args))
            self.assertEqual(launch.call_args.kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'TERM': 'xterm-256color'})
            self.assertIn('-i', args)


if __name__ == '__main__':
    unittest.main()
