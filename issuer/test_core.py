"""Synthetic provider responses only: no signing, keys or network calls."""
import copy
from datetime import datetime, timezone
import json
import os
import socket
import time
import unittest

from .core import APP, INSTALLATION, OWNER, REPOSITORY, NAME, PERMISSIONS, Denied, Issuer, deadline
from .runtime import peer_uid

NOW = 1794301200


class Provider:
    def __init__(self):
        self.calls = []
        self.app = {'id': APP, 'slug': 'proofgate-coder', 'owner': {'id': OWNER, 'login': 'deveshkakkar'},
                    'permissions': dict(PERMISSIONS), 'events': []}
        self.installation = {'id': INSTALLATION, 'app_id': APP, 'app_slug': 'proofgate-coder',
                             'account': {'id': OWNER, 'login': 'deveshkakkar', 'type': 'User'},
                             'suspended_at': None, 'repository_selection': 'selected',
                             'permissions': dict(PERMISSIONS), 'events': []}
        self.rows = [{'id': REPOSITORY, 'full_name': NAME}]
        self.grant = {'token': 'synthetic-provider-value-not-a-credential',
                      'expires_at': datetime.fromtimestamp(NOW + 3600, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
                      'permissions': dict(PERMISSIONS), 'repositories': copy.deepcopy(self.rows),
                      'repository_selection': 'selected'}
        self.count = 1
        self.fail_revoke = self.fail_issue = False

    def __call__(self, method, path, authorization, body=None):
        self.calls.append((method, path, copy.deepcopy(body)))  # Deliberately omit authorization.
        if method == 'DELETE':
            if self.fail_revoke: raise RuntimeError('synthetic revoke failure')
            return {}
        if method == 'POST':
            if self.fail_issue: raise RuntimeError('unknown outcome')
            return copy.deepcopy(self.grant)
        if path == '/app': return copy.deepcopy(self.app)
        if path.startswith('/app/installations?'): return [{'id': INSTALLATION}]
        if path.startswith('/app/installations/'): return copy.deepcopy(self.installation)
        if path.startswith('/installation/repositories?'):
            return {'total_count': self.count, 'repositories': copy.deepcopy(self.rows)}
        raise AssertionError('unexpected API route')


class IssuerTests(unittest.TestCase):
    def setup_issuer(self):
        provider = Provider(); audit = []; ticks = [0]
        issuer = Issuer(provider, lambda now: 'synthetic-jwt-placeholder', audit.append,
                        clock=lambda: NOW, monotonic=lambda: ticks[0])
        return provider, audit, ticks, issuer

    def test_exact_provider_request_and_redacted_audit(self):
        provider, audit, _, issuer = self.setup_issuer()
        lease = issuer.request({'op': 'issue'}, 82, 82)
        posts = [call for call in provider.calls if call[0] == 'POST']
        self.assertEqual(posts, [('POST', '/app/installations/180587357/access_tokens',
                                 {'repository_ids': [1452255523], 'permissions': dict(PERMISSIONS)})])
        self.assertEqual(lease['lease_seconds'], 300)
        issuer.request({'op': 'release', 'lease_id': lease['lease_id'], 'outcome': 'success'}, 82, 82)
        self.assertEqual([row['event'] for row in audit], ['issued', 'worker_finished', 'revoked'])
        self.assertNotIn(lease['token'], json.dumps(audit))
        self.assertNotIn('synthetic-jwt-placeholder', json.dumps(audit))

    def test_no_scope_or_command_arguments_and_wrong_peer(self):
        for request in [{'op': 'issue', 'repository_ids': [1437623154]},
                        {'op': 'issue', 'permissions': {'administration': 'write'}},
                        {'op': 'run', 'command': 'anything'}, {'op': 'release', 'lease_id': 'unknown'}]:
            provider, _, _, issuer = self.setup_issuer()
            with self.assertRaises(Denied): issuer.request(request, 82, 82)
            self.assertEqual(provider.calls, [])
        provider, _, _, issuer = self.setup_issuer()
        with self.assertRaises(Denied): issuer.request({'op': 'issue'}, 83, 82)
        self.assertEqual(provider.calls, [])

    def test_identity_permissions_suspension_and_all_scope_fail_before_post(self):
        for field, bad in [('app_id', APP + 1), ('id', INSTALLATION + 1),
                           ('app_slug', 'other'), ('repository_selection', 'all'),
                           ('suspended_at', 'yes'), ('events', ['push']),
                           ('permissions', {**PERMISSIONS, 'checks': 'write'}),
                           ('account', {'id': OWNER + 1, 'login': 'other', 'type': 'User'})]:
            provider, _, _, issuer = self.setup_issuer(); provider.installation[field] = bad
            with self.subTest(field=field), self.assertRaises(Denied): issuer.issue()
            self.assertFalse(any(call[0] == 'POST' for call in provider.calls))

    def test_invalid_grants_are_revoked_and_never_released(self):
        for field, bad in [('repositories', []), ('repositories', [{'id': 1437623154, 'full_name': 'production'}]),
                           ('permissions', {**PERMISSIONS, 'workflows': 'write'}),
                           ('repository_selection', 'all'), ('expires_at', '2099-01-01T00:00:00Z')]:
            provider, audit, _, issuer = self.setup_issuer(); provider.grant[field] = bad
            with self.subTest(field=field), self.assertRaises(Denied): issuer.issue()
            self.assertTrue(any(call[0] == 'DELETE' for call in provider.calls))
            self.assertIsNone(issuer.lease)
            self.assertNotIn('issued', [row['event'] for row in audit])

    def test_scoped_token_inventory_extra_or_missing_repository_rejects(self):
        for count, rows in [(2, [{'id': REPOSITORY, 'full_name': NAME}]),
                            (1, [{'id': 1437623154, 'full_name': 'production'}]), (True, [])]:
            provider, _, _, issuer = self.setup_issuer(); provider.count, provider.rows = count, rows
            with self.assertRaises(Denied): issuer.issue()
            self.assertIsNone(issuer.lease)
            self.assertTrue(any(call[0] == 'DELETE' for call in provider.calls))

    def test_deadline_revokes_without_worker_release(self):
        provider, audit, ticks, issuer = self.setup_issuer()
        issuer.issue(); ticks[0] = 300; issuer.expire()
        self.assertIsNone(issuer.lease)
        self.assertEqual(audit[-1]['event'], 'revoked')

    def test_single_lease_unknown_issue_or_failed_revocation_blocks_minting(self):
        provider, _, _, issuer = self.setup_issuer(); lease = issuer.issue()
        with self.assertRaises(Denied): issuer.issue()
        with self.assertRaises(Denied): issuer.request({'op': 'release', 'lease_id': 'wrong'}, 82, 82)
        self.assertEqual(issuer.lease['id'], lease['lease_id'])
        provider.fail_revoke = True
        with self.assertRaises(Denied): issuer.release()
        with self.assertRaises(Denied): issuer.issue()
        provider, audit, _, issuer = self.setup_issuer(); provider.fail_issue = True
        with self.assertRaises(Denied): issuer.issue()
        self.assertTrue(issuer.poisoned)
        self.assertEqual(audit[-1]['event'], 'issuance_outcome_unknown')
        provider.fail_issue = False
        with self.assertRaises(Denied): issuer.issue()

    def test_real_local_kernel_peer_identity(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with left, right:
            self.assertEqual(peer_uid(left), os.getuid())
            self.assertEqual(peer_uid(right), os.getuid())

    def test_malformed_issue_response_latches_and_cannot_retry(self):
        for bad in [None, [], {}, {'token': 'bad\nvalue'}]:
            provider, audit, _, issuer = self.setup_issuer(); provider.grant = bad
            with self.subTest(bad=bad), self.assertRaises(Denied): issuer.issue()
            self.assertTrue(issuer.poisoned)
            provider.grant = Provider().grant
            with self.assertRaises(Denied): issuer.issue()
            self.assertEqual(len([c for c in provider.calls if c[0] == 'POST']), 1)

    def test_invalid_grant_or_post_mint_metadata_drift_latches_after_revoke(self):
        provider, _, _, issuer = self.setup_issuer()
        provider.grant['permissions']['checks'] = 'write'
        with self.assertRaises(Denied): issuer.issue()
        self.assertTrue(issuer.poisoned)
        self.assertTrue(any(c[0] == 'DELETE' for c in provider.calls))
        provider, _, _, issuer = self.setup_issuer()
        original = provider.__call__
        def drift(method, path, auth, body=None):
            result = original(method, path, auth, body)
            if method == 'POST': provider.installation['app_id'] = APP + 1
            return result
        issuer.api = drift
        with self.assertRaises(Denied): issuer.issue()
        self.assertTrue(issuer.poisoned)
        self.assertIsNone(issuer.lease)

    def test_audit_or_latch_failure_after_mint_still_attempts_revoke(self):
        provider, _, _, issuer = self.setup_issuer()
        def bad_audit(row):
            if row['event'] == 'issued': raise OSError('synthetic full audit')
        def bad_latch(): raise OSError('synthetic full state')
        issuer.audit, issuer.latch = bad_audit, bad_latch
        with self.assertRaises(Denied): issuer.issue()
        self.assertTrue(issuer.poisoned and issuer.latch_failed)
        self.assertTrue(any(c[0] == 'DELETE' for c in provider.calls))
        self.assertIsNone(issuer.lease)

    def test_real_absolute_alarm_bounds_a_stalled_operation(self):
        start = time.monotonic()
        with self.assertRaises(Denied), deadline(0.01):
            time.sleep(1)
        self.assertLess(time.monotonic() - start, 0.5)

    def test_transient_revoked_audit_failure_blocks_next_issue(self):
        provider, audit, _, issuer = self.setup_issuer(); issuer.issue()
        def bad_audit(row):
            if row['event'] == 'revoked': raise OSError('synthetic audit failure')
        issuer.audit = bad_audit
        with self.assertRaises(Denied): issuer.release()
        self.assertIsNone(issuer.lease)
        self.assertTrue(issuer.poisoned)
        issuer.audit = audit.append
        with self.assertRaises(Denied): issuer.issue()
        self.assertEqual(len([c for c in provider.calls if c[0] == 'POST']), 1)


if __name__ == '__main__':
    unittest.main()
