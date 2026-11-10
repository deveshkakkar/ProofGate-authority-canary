"""Runtime/launcher lifecycle regressions with synthetic leases, no credentials."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from .core import Denied
from . import core, runtime, launcher, server
from . import test_core


class RuntimeTests(unittest.TestCase):
    def test_unbound_identity_boundary_and_production_config_fail(self):
        template = json.loads(Path(__file__).with_name('owner-config.template.json').read_text())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); executable = root / 'launcher'
            executable.write_text('synthetic fixture only')
            value = {**template, 'issuer_uid': 820, 'launcher_uid': 0, 'worker_uid': 821,
                     'photon_uid': 822, 'owner_isolation_verified': True,
                     'worker_launcher_path': str(executable),
                     'worker_launcher_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()}
            for name in ['socket_path', 'audit_path', 'state_path', 'key_path']:
                value[name] = str(root / name)
            target = root / 'config.json'
            # This test isolates config validation; it does not prove root ownership.
            with patch.object(runtime, 'secure_path', side_effect=lambda path, *a, **k: Path(path)):
                target.write_text(json.dumps(value))
                self.assertEqual(runtime.config(str(target))['repository_id'], 1452255523)
                for key, bad in [('worker_uid', 820), ('issuer_uid', 0), ('photon_uid', None),
                                 ('owner_isolation_verified', False), ('repository_id', 1437623154),
                                 ('socket_path', None), ('worker_launcher_sha256', '0' * 64)]:
                    target.write_text(json.dumps({**value, key: bad}))
                    with self.subTest(key=key), self.assertRaises(Denied): runtime.config(str(target))

    def test_real_writable_ancestor_and_symlink_reject(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, 'source'); source.write_text('harmless fixture')
            link = Path(directory, 'link'); link.symlink_to(source)
            with self.assertRaises(Denied): runtime.secure_path(str(link), os.getuid(), private=True)
            with self.assertRaises(Denied): runtime.secure_path(str(source), os.getuid(), private=True)

    def test_persistent_state_blocks_crash_or_poison_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, 'state'); path.write_text('{"state":"ready"}')
            with patch.object(runtime, 'secure_path', return_value=path):
                state = runtime.State(str(path), 820)
                state.begin()
                with self.assertRaises(Denied): runtime.State(str(path), 820).begin()
                state.write('blocked')
                with self.assertRaises(Denied): state.begin()
                state.write('ready'); state.begin()
                self.assertEqual(json.loads(path.read_text()), {'state': 'running'})

    def test_disconnected_issue_reply_revokes_immediately(self):
        provider, audit, _, issuer = test_core.IssuerTests().setup_issuer()
        connection = Mock()
        connection.makefile.return_value = io.BytesIO(b'{"op":"issue"}\n')
        connection.sendall.side_effect = BrokenPipeError
        with patch.object(server, 'peer_uid', return_value=82):
            server.handle(connection, issuer, 82, lambda: False)
        self.assertIsNone(issuer.lease)
        self.assertTrue(any(call[0] == 'DELETE' for call in provider.calls))
        self.assertEqual(audit[-1]['event'], 'request_denied')

    def test_stop_during_mint_captures_then_revokes_without_replying_token(self):
        provider, audit, _, issuer = test_core.IssuerTests().setup_issuer()
        stopping = [False]; original = issuer.api
        def stop_during_post(method, path, auth, body=None):
            result = original(method, path, auth, body)
            if method == 'POST': stopping[0] = True
            return result
        issuer.api = stop_during_post
        connection = Mock(); connection.makefile.return_value = io.BytesIO(b'{"op":"issue"}\n')
        with patch.object(server, 'peer_uid', return_value=82):
            server.handle(connection, issuer, 82, lambda: stopping[0])
        self.assertIsNone(issuer.lease)
        self.assertTrue(any(call[0] == 'DELETE' for call in provider.calls))
        self.assertNotIn(provider.grant['token'], str(connection.sendall.call_args_list))

    def test_ipc_budget_and_no_secret_in_requests(self):
        connection = Mock(); connection.makefile.return_value = io.BytesIO(b'{"released":true}\n')
        result = runtime.exchange(connection, {'op': 'release', 'lease_id': 'synthetic', 'outcome': 'success'})
        self.assertTrue(result['released'])
        connection.settimeout.assert_called_with(120)
        self.assertNotIn('token', str(connection.sendall.call_args))

    def test_cleanup_exception_still_releases_and_core_dumps_disabled(self):
        lease = {'lease_id': 'synthetic', 'token': 'synthetic-not-a-credential',
                 'lease_seconds': 300, 'provider_expires_at': 'synthetic',
                 'lease_deadline_monotonic': time.monotonic() + 300}
        configuration = {'launcher_uid': 82, 'issuer_uid': 81,
                         'socket_path': '/synthetic-owner-socket', 'worker_launcher_path': '/synthetic-owner-launcher'}
        process = Mock(); process.wait.side_effect = RuntimeError('synthetic cleanup failure')
        process.poll.return_value = None
        class Socket:
            def __enter__(self): return Mock()
            def __exit__(self, *args): return False
        with patch.object(launcher.os, 'getuid', return_value=82), \
             patch.object(launcher.socket, 'socket', return_value=Socket()), \
             patch.object(launcher, 'peer_uid', return_value=81), \
             patch.object(launcher, 'exchange', side_effect=[copy.deepcopy(lease), {'released': True}]) as calls, \
             patch.object(launcher.resource, 'setrlimit') as limit, \
             patch.object(launcher.subprocess, 'Popen', return_value=process):
            with self.assertRaises(RuntimeError): launcher.invoke(configuration)
            self.assertEqual(calls.call_args_list[-1].args[1]['op'], 'release')
            limit.assert_called_once_with(launcher.resource.RLIMIT_CORE, (0, 0))
            env = launcher.subprocess.Popen.call_args.kwargs['env']
            self.assertEqual(set(env), {'PATH', 'PROOFGATE_TOKEN_FD'})

    def test_provider_redirect_pagination_oversize_and_bad_json_fail_closed(self):
        for status, link, body in [(302, None, b'{}'), (200, 'next', b'{}'),
                                   (200, None, b'x' * 262145), (200, None, b'not-json')]:
            connection = Mock(); response = connection.getresponse.return_value
            response.status = status; response.getheader.return_value = link; response.read.return_value = body
            audit = []
            with patch.object(core.http.client, 'HTTPSConnection', return_value=connection) as http:
                with self.subTest(status=status, link=link), self.assertRaises(Denied):
                    core.GitHub(audit.append)('GET', '/app', 'synthetic-not-a-credential')
                self.assertEqual(http.call_args.args[0], 'api.github.com')
                connection.close.assert_called_once()
            self.assertNotIn('synthetic-not-a-credential', json.dumps(audit))

    def test_large_stateless_provider_token_fits_bounded_ipc(self):
        provider, _, _, issuer = test_core.IssuerTests().setup_issuer()
        provider.grant['token'] = 'synthetic-' + 'a' * 3000
        lease = issuer.issue()
        connection = Mock(); connection.makefile.return_value = io.BytesIO((json.dumps(lease) + '\n').encode())
        self.assertEqual(runtime.exchange(connection, {'op': 'issue'})['lease_id'], lease['lease_id'])
        issuer.release()

    def test_transient_request_audit_failure_blocks_mint_without_provider_calls(self):
        provider, audit, _, issuer = test_core.IssuerTests().setup_issuer()
        def bad_audit(row):
            if row['event'] == 'launcher_request': raise OSError('synthetic transient audit failure')
            audit.append(row)
        issuer.audit = bad_audit
        connection = Mock(); connection.makefile.return_value = io.BytesIO(b'{"op":"issue"}\n')
        with patch.object(server, 'peer_uid', return_value=82):
            server.handle(connection, issuer, 82, lambda: False)
        self.assertTrue(issuer.poisoned)
        issuer.audit = audit.append
        with self.assertRaises(Denied): issuer.issue()
        self.assertEqual(provider.calls, [])

    def test_completion_audit_failure_revokes_in_the_actual_release_handler(self):
        provider, audit, _, issuer = test_core.IssuerTests().setup_issuer(); lease = issuer.issue()
        def bad_audit(row):
            if row['event'] == 'worker_finished': raise OSError('synthetic full audit')
            audit.append(row)
        issuer.audit = bad_audit
        request = {'op': 'release', 'lease_id': lease['lease_id'], 'outcome': 'success'}
        connection = Mock(); connection.makefile.return_value = io.BytesIO((json.dumps(request) + '\n').encode())
        with patch.object(server, 'peer_uid', return_value=82):
            server.handle(connection, issuer, 82, lambda: False)
        self.assertIsNone(issuer.lease)
        self.assertTrue(issuer.poisoned)
        self.assertTrue(any(call[0] == 'DELETE' for call in provider.calls))
        self.assertEqual(audit[-1]['event'], 'request_denied')


if __name__ == '__main__':
    unittest.main()
