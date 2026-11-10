"""No root operations, keys or live provider calls in these unit tests."""
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch, Mock

from . import bootstrap, sandbox, control
from .common import Stop, REPO, REPO_ID, OWNER_ID


def archive(files):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode='w:gz') as stream:
        for name, data in files.items():
            row = tarfile.TarInfo('prefix/' + name); row.size = len(data)
            stream.addfile(row, io.BytesIO(data))
    return target.getvalue()


class BootstrapTests(unittest.TestCase):
    def test_immutable_issuer_content_and_path_rejection(self):
        body = b'harmless fixture'
        manifest = {'revision': bootstrap.REVISION, 'files': {'issuer/core.py': hashlib.sha256(body).hexdigest()}}
        self.assertEqual(bootstrap.unpack_issuer(archive({'issuer/core.py': body}), manifest), {'issuer/core.py': body})
        for entries in [{'issuer/core.py': b'changed'}, {'../issuer/core.py': body}, {'other.py': body}]:
            with self.assertRaises(Stop): bootstrap.unpack_issuer(archive(entries), manifest)
        with self.assertRaises(Stop): bootstrap.unpack_issuer(gzip.compress(b'x' * 4194305), manifest)

    def test_unsupported_download_hosts_reject_before_network(self):
        for url in ['http://files.pythonhosted.org/a', 'https://example.invalid/a',
                    'https://files.pythonhosted.org.evil/a']:
            with self.assertRaises(Stop): bootstrap.download(url, 10)

    def test_prepare_requires_explicit_owner_ack_and_root(self):
        with patch.object(bootstrap.os, 'getuid', return_value=1000):
            with self.assertRaises(Stop): bootstrap.prepare(True)
        with patch.object(bootstrap.os, 'getuid', return_value=0):
            with self.assertRaises(Stop): bootstrap.prepare(False)

    def test_existing_privileged_or_interactive_account_is_not_adopted(self):
        row = Mock(pw_uid=0, pw_gid=0, pw_dir='/root', pw_shell='/bin/bash')
        with patch.object(bootstrap.pwd, 'getpwnam', return_value=row), patch.object(bootstrap, 'run') as calls:
            with self.assertRaises(Stop): bootstrap.account('pg-worker')
            calls.assert_not_called()

    def test_partial_prepare_can_resume_but_changed_unit_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); marker = root / 'intent.json'; config = root / 'config.json'
            marker.write_text(json.dumps({'issuer_revision': bootstrap.REVISION, 'bundle_sha256': 'synthetic'}))
            config.write_text('{}')
            with patch.object(bootstrap, 'protected', side_effect=lambda p: p), \
                 patch.object(bootstrap, 'CONFIG', config), patch.object(bootstrap, 'ETC', root), \
                 patch.object(bootstrap.subprocess, 'run', return_value=Mock(returncode=3)):
                self.assertFalse(bootstrap.previous_setup(marker, 'synthetic'))
                with self.assertRaises(Stop): bootstrap.previous_setup(marker, 'changed')
                (root / 'installation.json').write_text('{}')
                with patch('owner_vm.common.verify_install') as verify, patch.object(bootstrap, 'run') as calls:
                    self.assertTrue(bootstrap.previous_setup(marker, 'synthetic'))
                    verify.assert_called_once(); calls.assert_called_once()


class GatewayTests(unittest.TestCase):
    def api(self, method, path, token, body=None):
        self.calls.append((method, path, body))
        step = len(self.calls)
        if step == 1: return 200, {'id': REPO_ID, 'full_name': REPO, 'owner': {'id': OWNER_ID}}
        if step == 2: return 200, {'object': {'sha': 'a' * 40}}
        if step == 5: return 201, {'number': 7, 'user': {'login': 'proofgate-coder[bot]', 'type': 'Bot', 'id': 123},
                                 'head': {'ref': self.gateway.branch, 'sha': 'b' * 40}, 'base': {'ref': 'main'}}
        return 201, {}

    def setUp(self):
        self.calls = []; self.gateway = sandbox.Gateway('synthetic-not-a-credential', 'pr', self.api)

    def request(self, method, path, body=None):
        value = {'op': 'api', 'method': method, 'path': path}
        if method != 'GET': value['body'] = body
        return self.gateway.call(value)

    def test_only_canary_synthetic_sequence_produces_recorded_app_pr(self):
        self.request('GET', ''); self.request('GET', '/git/ref/heads/main')
        self.request('POST', '/git/refs', {'ref': 'refs/heads/' + self.gateway.branch, 'sha': 'a' * 40})
        fixture = base64.b64encode(json.dumps({'probe_version': 1, 'run_id': self.gateway.run_id}).encode()).decode()
        self.request('PUT', '/contents/probes/' + self.gateway.run_id + '.json',
                     {'message': 'Add harmless authenticated canary fixture', 'branch': self.gateway.branch, 'content': fixture})
        result = self.request('POST', '/pulls', {'title': 'Authenticated canary positive control',
                    'head': self.gateway.branch, 'base': 'main',
                    'body': 'Synthetic App-authored trial. Requires genuine human approval and human-operated merge. Not independent admission.'})
        self.assertEqual(result['author'], 'proofgate-coder[bot]')
        self.assertTrue(all(row[1].startswith('/repos/' + REPO) for row in self.calls))
        self.assertNotIn('synthetic-not-a-credential', json.dumps(self.gateway.events))

    def test_escape_merge_check_or_production_routes_never_reach_provider(self):
        for method, path in [('PUT', '/pulls/1/merge'), ('POST', '/check-runs'),
                             ('GET', '/../ProofGate'), ('GET', 'https://api.github.com/user'),
                             ('GET', '?access_token=anything')]:
            with self.assertRaises(Stop): self.request(method, path, {} if method != 'GET' else None)
        self.assertEqual(self.calls, [])

    def test_probe_mode_cannot_make_any_provider_call(self):
        self.gateway.mode = 'probe'
        with self.assertRaises(Stop): self.request('GET', '')
        self.assertEqual(self.calls, [])

    def test_command_has_real_uid_and_no_bearer_or_host_network(self):
        args = sandbox.command({'worker_uid': 812, 'worker_gid': 812}, 'proofgate-worker-fixture.service')
        for value in ['--unshare-all', '--disable-userns', '--clearenv', '--property=MemoryMax=256M',
                      '--property=MemorySwapMax=0', '--property=TasksMax=16', '--property=User=812',
                      '--property=KillMode=control-group', '--property=RuntimeMaxSec=120']:
            self.assertIn(value, args)
        self.assertNotIn('--share-net', args)
        self.assertFalse(any('token' in value.lower() for value in args))


class ControllerTests(unittest.TestCase):
    def test_import_rejects_fifo_and_parent_symlink_before_key_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); fifo = root / 'fifo'
            import os
            os.mkfifo(fifo, 0o600)
            cfg = {'key_path': str(root / 'destination')}
            with patch.object(control, 'config', return_value=cfg), patch.object(control, 'protected'), \
                 patch.object(control.subprocess, 'run') as openssl:
                # /tmp writable ancestor also rejects; never opens or parses this FIFO.
                with self.assertRaises(Stop): control.import_key(str(fifo))
                openssl.assert_not_called()

    def test_a14_needs_a_successful_local_trial_and_actual_human_ack(self):
        with self.assertRaises(Stop): control.a14(7, False)
        with tempfile.TemporaryDirectory() as directory, patch.object(control, 'STATE', Path(directory)), \
             patch.object(control, 'config', return_value={}), patch.object(control, 'with_lease') as lease:
            Path(directory, 'results').mkdir()
            with self.assertRaises(Stop): control.a14(7, True)
            lease.assert_not_called()


if __name__ == '__main__':
    unittest.main()
