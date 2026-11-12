"""Synthetic provider/receipt tests: no credentials, VM, issuer or real GitHub writes."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from . import a14
from .common import Stop, APP_ID, INSTALLATION_ID, REPO_ID, REPO, OWNER_ID

HEAD = 'b' * 40
BASE = 'a' * 40
MERGE = 'c' * 40
RUN = 'd' * 32
TIME = '2026-11-12T00:23:49Z'


def receipt():
    return {'app_id': APP_ID, 'installation_id': INSTALLATION_ID, 'repository_id': REPO_ID,
            'completed': True, 'revocation_verified': True, 'revocation_http_status': 401,
            'result': {'mode': 'pr', 'completed': True, 'run_id': RUN,
                       'pr': {'number': 4, 'author': 'proofgate-coder[bot]', 'author_id': 123,
                              'head_sha': HEAD, 'base_sha_at_create': BASE}}}


def metadata():
    repo = {'id': REPO_ID, 'full_name': REPO}
    return {'pr': {'number': 4, 'state': 'closed', 'merged': True, 'merged_at': TIME,
                   'merged_by': {'id': OWNER_ID, 'login': 'deveshkakkar'},
                   'user': {'id': 123, 'login': 'proofgate-coder[bot]', 'type': 'Bot'},
                   'head': {'sha': HEAD, 'ref': 'authority-positive-' + RUN, 'repo': repo.copy()},
                   'base': {'sha': BASE, 'ref': 'main', 'repo': repo.copy()}},
            'timeline': [{'id': 10, 'event': 'merged', 'commit_id': MERGE, 'created_at': TIME,
                          'actor': {'id': OWNER_ID, 'login': 'deveshkakkar'}}],
            'commit': {'sha': MERGE, 'parents': [{'sha': BASE}, {'sha': HEAD}]},
            'compare': {'status': 'identical', 'base_commit': {'sha': BASE}, 'merge_base_commit': {'sha': BASE}},
            'reviews': [{'id': 20, 'user': {'id': OWNER_ID}, 'state': 'APPROVED', 'commit_id': HEAD,
                         'submitted_at': '2026-11-12T00:23:35Z'}],
            'checks': {'total_count': 1, 'check_runs': [{'id': 30, 'app': {'id': 15368}, 'name': 'offline',
                        'status': 'completed', 'conclusion': 'success', 'head_sha': HEAD,
                        'completed_at': '2026-11-12T00:22:00Z'}]}}


class Reader:
    def __init__(self, data): self.data = data; self.evidence = []
    def __call__(self, path):
        self.evidence.append({'path': path, 'http_status': 200})
        key = ('timeline' if '/timeline?' in path else 'reviews' if '/reviews?' in path else
               'checks' if '/check-runs?' in path else 'compare' if '/compare/' in path else
               'commit' if '/commits/' in path else 'pr')
        return copy.deepcopy(self.data[key])


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.data = metadata(); self.subject = a14.trial_subject(receipt(), 4)

    def verify(self): return a14.verify(self.subject, Reader(self.data))

    def test_missing_null_and_matching_merge_sha_require_independent_event_and_commit(self):
        for variant in ['absent', None, MERGE]:
            with self.subTest(variant=variant):
                if variant == 'absent': self.data['pr'].pop('merge_commit_sha', None)
                else: self.data['pr']['merge_commit_sha'] = variant
                result = self.verify()
                self.assertEqual(result['merge_commit_sha'], MERGE)
                self.assertFalse(result['independent_admission_verified'])
                self.assertEqual(result['A13'], 'UNVERIFIED')

    def test_missing_and_malformed_pr_fields_fail_closed_without_keyerror(self):
        for field in ['number', 'merged', 'merged_at', 'merged_by', 'user', 'head', 'base']:
            for variant in ['absent', None, []]:
                with self.subTest(field=field, variant=variant):
                    self.data = metadata()
                    if variant == 'absent': self.data['pr'].pop(field)
                    else: self.data['pr'][field] = variant
                    with self.assertRaises(Stop): self.verify()

    def test_no_missing_conflicting_or_ambiguous_merge_evidence_is_accepted(self):
        changes = [lambda d: d['timeline'].clear(),
                   lambda d: d['timeline'].append(copy.deepcopy(d['timeline'][0])),
                   lambda d: d['timeline'][0].pop('commit_id'),
                   lambda d: d['timeline'][0].update(commit_id=None),
                   lambda d: d['timeline'][0].update(created_at='2026-11-12T00:24:00Z'),
                   lambda d: d['timeline'][0]['actor'].update(id=99),
                   lambda d: d['pr'].update(merge_commit_sha='e' * 40),
                   lambda d: d['pr'].update(merge_commit_sha='not-a-sha'),
                   lambda d: d['commit'].pop('parents'),
                   lambda d: d['commit'].update(parents=[{'sha': BASE}]),
                   lambda d: d['commit']['parents'][1].update(sha='e' * 40),
                   lambda d: d['compare'].update(status='diverged'),
                   lambda d: d['compare']['merge_base_commit'].update(sha='e' * 40)]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.data = metadata(); change(self.data)
                with self.assertRaises(Stop): self.verify()

    def test_wrong_subject_approval_or_check_producer_never_passes(self):
        changes = [lambda d: d['pr']['head'].update(sha='e' * 40),
                   lambda d: d['pr']['head'].update(ref='other-branch'),
                   lambda d: d['pr']['base']['repo'].update(id=1437623154),
                   lambda d: d['pr']['user'].update(id=99),
                   lambda d: d['pr']['merged_by'].update(id=99),
                   lambda d: d['reviews'][0].update(state='DISMISSED'),
                   lambda d: d['reviews'][0].update(commit_id='e' * 40),
                   lambda d: d['reviews'][0].update(submitted_at='2026-11-12T00:24:00Z'),
                   lambda d: d['checks'].update(total_count=2),
                   lambda d: d['checks']['check_runs'][0]['app'].update(id=99),
                   lambda d: d['checks']['check_runs'][0].update(head_sha='e' * 40),
                   lambda d: d['checks']['check_runs'][0].update(conclusion='failure'),
                   lambda d: d['checks']['check_runs'][0].update(completed_at='2026-11-12T00:24:00Z')]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                self.data = metadata(); change(self.data)
                with self.assertRaises(Stop): self.verify()

    def test_later_changes_requested_blocks_but_comment_does_not_dismiss_approval(self):
        later = {'id': 21, 'user': {'id': OWNER_ID}, 'state': 'COMMENTED', 'submitted_at': TIME}
        self.data['reviews'].append(later)
        self.verify()
        later.update(state='CHANGES_REQUESTED')
        with self.assertRaises(Stop): self.verify()

    def test_newer_failed_ci_cannot_be_hidden_by_older_success(self):
        check = copy.deepcopy(self.data['checks']['check_runs'][0]); check.update(id=31, conclusion='failure')
        self.data['checks']['check_runs'].append(check); self.data['checks']['total_count'] = 2
        with self.assertRaises(Stop): self.verify()

    def test_duplicate_review_and_check_ids_are_not_arbitrarily_resolved(self):
        contradiction = copy.deepcopy(self.data['reviews'][0]); contradiction['state'] = 'DISMISSED'
        self.data['reviews'].append(contradiction)
        with self.assertRaises(Stop): self.verify()
        self.data = metadata()
        contradiction = copy.deepcopy(self.data['checks']['check_runs'][0]); contradiction['conclusion'] = 'failure'
        self.data['checks']['check_runs'].append(contradiction); self.data['checks']['total_count'] = 2
        with self.assertRaises(Stop): self.verify()

    def test_advanced_merge_base_requires_original_base_ancestry(self):
        self.data['commit']['parents'][0]['sha'] = 'f' * 40
        self.data['compare']['status'] = 'ahead'
        self.verify()
        self.data['compare']['merge_base_commit']['sha'] = 'f' * 40
        with self.assertRaises(Stop): self.verify()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = self.root / 'trialoriginal.json'
        self.original.write_text(json.dumps(receipt()))
        self.failed = self.root / 'trialfailedobservation.json'
        self.failed.write_text(json.dumps({'completed': False, 'revocation_verified': True, 'revocation_http_status': 401}))
        self.failure = self.root / 'controlfailure.json'; self.failure.write_text('{"failure":"KeyError"}')
        self.protection = patch.object(a14, 'protected', side_effect=lambda p, **k: p)
        self.protection.start(); self.addCleanup(self.protection.stop)
        # Root ownership change alone is simulated; real exclusive writes and bytes are exercised.
        self.chown = patch('owner_vm.common.os.fchown')
        self.chown.start(); self.addCleanup(self.chown.stop)
        self.before = {p.name:p.read_bytes() for p in self.root.iterdir()}

    def test_recovery_appends_separate_receipt_and_preserves_all_original_bytes(self):
        report = a14.recover(4, True, self.root, Reader(metadata()))
        self.assertTrue(report['original_evidence_unchanged'])
        self.assertFalse(report['new_tokens_issued']); self.assertFalse(report['trial_repeated'])
        for name, raw in self.before.items():
            self.assertEqual((self.root / name).read_bytes(), raw)
            self.assertEqual(report['original_evidence_sha256'][name], hashlib.sha256(raw).hexdigest())
        self.assertTrue((self.root / report['recovery_receipt']).is_file())
        self.assertEqual((self.root / report['recovery_receipt']).stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(list(self.root.iterdir())), 4)

    def test_unverified_recovery_preserves_failure_separately(self):
        data = metadata(); data['timeline'] = []
        with self.assertRaises(Stop): a14.recover(4, True, self.root, Reader(data))
        failure = json.loads(next(self.root.glob('a14recovery*.json')).read_text())
        self.assertEqual(failure['A14'], 'NOT_VERIFIED')
        self.assertEqual(failure['error'], 'unique_merge_event_required')
        for name, raw in self.before.items(): self.assertEqual((self.root / name).read_bytes(), raw)

    def test_missing_ack_or_valid_receipt_never_uses_github(self):
        reader = Mock()
        with self.assertRaises(Stop): a14.recover(4, False, self.root, reader)
        self.original.unlink()
        with self.assertRaises(Stop): a14.recover(4, True, self.root, reader)
        reader.assert_not_called()

    def test_duplicate_or_unrevoked_trial_is_rejected_before_network(self):
        reader = Mock()
        (self.root / 'trialduplicate.json').write_bytes(self.original.read_bytes())
        with self.assertRaises(Stop): a14.recover(4, True, self.root, reader)
        (self.root / 'trialduplicate.json').unlink()
        invalid = receipt(); invalid['revocation_http_status'] = 200
        self.original.write_text(json.dumps(invalid))
        with self.assertRaises(Stop): a14.recover(4, True, self.root, reader)
        reader.assert_not_called()

    def test_existing_output_is_never_overwritten(self):
        target = self.root / ('a14recovery' + 'e'*32 + '.json'); target.write_bytes(b'preserve existing report')
        with patch.object(a14.uuid, 'uuid4', return_value=Mock(hex='e'*32)):
            with self.assertRaises(FileExistsError): a14.recover(4, True, self.root, Reader(metadata()))
        self.assertEqual(target.read_bytes(), b'preserve existing report')

    def test_concurrent_change_of_original_evidence_invalidates_recovery(self):
        reader = Reader(metadata())
        def changing(path):
            if '/check-runs?' in path: self.failure.write_text('{"failure":"changed concurrently"}')
            return reader(path)
        with self.assertRaises(Stop): a14.recover(4, True, self.root, changing)
        failure = json.loads(next(self.root.glob('a14recovery*.json')).read_text())
        self.assertFalse(failure['original_evidence_unchanged']); self.assertEqual(failure['A14'], 'NOT_VERIFIED')


class PublicReaderTests(unittest.TestCase):
    def test_network_scope_is_canary_get_only_without_auth_or_proxies(self):
        response = Mock(status=200); response.read.return_value = b'{}'; response.getheader.return_value = None
        connection = Mock(); connection.getresponse.return_value = response
        with patch.object(a14.http.client, 'HTTPSConnection', return_value=connection):
            a14.PublicGitHub()(a14.PREFIX + '/pulls/4')
        self.assertEqual(connection.request.call_args.args[:2], ('GET', a14.PREFIX + '/pulls/4'))
        headers = connection.request.call_args.kwargs['headers']
        self.assertNotIn('Authorization', headers)
        self.assertTrue(connection.close.called)
        for path in ['/app/installations', '/repos/deveshkakkar/ProofGate/pulls/4',
                     a14.PREFIX + '/../ProofGate/pulls/4', 'https://example.invalid',
                     a14.PREFIX + '/pulls/4?access_token=anything']:
            with self.assertRaises(Stop): a14.PublicGitHub()(path)

    def test_ambiguous_json_duplicates_and_non_json_numbers_are_rejected(self):
        for raw in [b'{"merged":true,"merged":false}', b'{"nested":{"sha":"a","sha":"b"}}',
                    b'{"id":NaN}', b'{"id":Infinity}']:
            with self.subTest(raw=raw):
                with self.assertRaises(Stop): a14.decode(raw)

    def test_truncation_pagination_http_errors_and_wrong_json_shape_fail_closed(self):
        for status, link, body in [(403, None, b'{}'), (302, None, b'{}'),
                                   (200, '<next>', b'[]'), (200, None, b'x'*1048577)]:
            with self.subTest(status=status, link=link, length=len(body)):
                response = Mock(status=status); response.getheader.return_value = link; response.read.return_value = body
                connection = Mock(); connection.getresponse.return_value = response
                with patch.object(a14.http.client, 'HTTPSConnection', return_value=connection):
                    with self.assertRaises(Stop): a14.PublicGitHub()(a14.PREFIX + '/pulls/4')
        data = metadata(); data['pr'] = []
        with self.assertRaises(Stop): a14.verify(a14.trial_subject(receipt(), 4), Reader(data))


if __name__ == '__main__': unittest.main()
