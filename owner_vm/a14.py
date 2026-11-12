"""Owner-only, unauthenticated GET recovery. Never imports the issuer or worker."""
import argparse
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import resource
import signal
import ssl
import stat
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from owner_vm.common import STATE, REPO, REPO_ID, OWNER_ID, APP_ID, INSTALLATION_ID, REVISION, Stop, require, protected, config, write

PREFIX = '/repos/' + REPO
SHA = re.compile(r'[0-9a-f]{40}')
RUN_ID = re.compile(r'[0-9a-f]{32}')
PUBLIC_ROUTE = re.compile(re.escape(PREFIX) + r'/(?:pulls/[1-9][0-9]*(?:/reviews\?per_page=100)?|issues/[1-9][0-9]*/timeline\?per_page=100|commits/[0-9a-f]{40}(?:/check-runs\?per_page=100)?|compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40})')


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate_json_field')
            result[key] = value
        return result
    def constant(_):
        raise Stop('non_json_constant')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def unique_ids(rows, code):
    values = [r.get('id') for r in rows]
    require(all(type(i) is int and i > 0 for i in values) and len(values) == len(set(values)), code)


def obj(value, code='github_object_missing'):
    require(type(value) is dict, code)
    return value


def sha(value):
    require(type(value) is str and SHA.fullmatch(value), 'github_revision_missing_or_invalid')
    return value


def date(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value), 'github_timestamp_missing')
    try:
        return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        raise Stop('github_timestamp_invalid') from None


class PublicGitHub:
    """Fixed-origin HTTPS, GET-only, no Authorization, no ambient proxies/redirects."""
    def __init__(self):
        self.evidence = []

    def __call__(self, path):
        require(type(path) is str and PUBLIC_ROUTE.fullmatch(path)
                and len(self.evidence) < 12, 'public_read_scope')
        connection = http.client.HTTPSConnection('api.github.com', timeout=10, context=ssl.create_default_context())
        def expired(*_):
            raise Stop('github_read_deadline')
        prior = signal.signal(signal.SIGALRM, expired); signal.setitimer(signal.ITIMER_REAL, 10)
        try:
            connection.request('GET', path, headers={'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'proofgate-a14-public-recovery'})
            response = connection.getresponse(); raw = response.read(1048577)
            self.evidence.append({'path': path, 'http_status': response.status,
                                  'response_sha256': hashlib.sha256(raw).hexdigest()})
            require(response.status == 200 and len(raw) <= 1048576 and not response.getheader('Link'),
                    'github_read_failed_or_truncated')
            return decode(raw)
        finally:
            connection.close(); signal.setitimer(signal.ITIMER_REAL, 0); signal.signal(signal.SIGALRM, prior)


def trial_subject(row, number):
    """A historical observer result (pr integer) is never an authenticated trial."""
    row = obj(row, 'receipt_object_required')
    created = obj(row.get('result', {}), 'receipt_result_invalid').get('pr')
    if type(created) is not dict or type(created.get('number')) is not int or created.get('number') != number:
        return None
    require(row.get('completed') is True and row.get('revocation_verified') is True
            and type(row.get('revocation_http_status')) is int and row['revocation_http_status'] == 401
            and (row.get('app_id'), row.get('installation_id'), row.get('repository_id')) ==
                (APP_ID, INSTALLATION_ID, REPO_ID), 'successful_revoked_trial_required')
    result = row['result']; run_id = result.get('run_id')
    require(type(run_id) is str and RUN_ID.fullmatch(run_id)
            and result.get('completed') is True and result.get('mode') == 'pr'
            and created.get('author') == 'proofgate-coder[bot]'
            and type(created.get('author_id')) is int and created['author_id'] > 0,
            'authenticated_trial_identity_required')
    sha(created.get('head_sha')); sha(created.get('base_sha_at_create'))
    return {'number': number, 'run_id': run_id, **created}


def verify(subject, get):
    """No caller-supplied merge SHA. All merge candidates originate at GitHub."""
    number = subject['number']; head = subject['head_sha']; path = PREFIX + '/pulls/' + str(number)
    pr = obj(get(path)); user = obj(pr.get('user')); merger = obj(pr.get('merged_by'))
    require(type(pr.get('number')) is int and pr.get('number') == number and pr.get('state') == 'closed' and pr.get('merged') is True
            and user.get('login') == 'proofgate-coder[bot]' and user.get('type') == 'Bot'
            and user.get('id') == subject['author_id']
            and merger.get('id') == OWNER_ID and merger.get('login') == 'deveshkakkar', 'human_merge_not_observed')
    tip = obj(pr.get('head')); base = obj(pr.get('base'))
    for revision in [tip, base]:
        repo = obj(revision.get('repo'))
        require(repo.get('id') == REPO_ID and repo.get('full_name') == REPO, 'pr_repository_mismatch')
    require(sha(tip.get('sha')) == head and tip.get('ref') == 'authority-positive-' + subject['run_id']
            and base.get('ref') == 'main', 'trial_revision_mismatch')
    merged_at = date(pr.get('merged_at'))
    timeline = get(PREFIX + '/issues/' + str(number) + '/timeline?per_page=100')
    require(type(timeline) is list and all(type(e) is dict for e in timeline), 'timeline_shape')
    events = [e for e in timeline if e.get('event') == 'merged']
    require(len(events) == 1, 'unique_merge_event_required')
    event = events[0]; actor = obj(event.get('actor'))
    require(type(event.get('id')) is int and event['id'] > 0
            and actor.get('id') == OWNER_ID and actor.get('login') == 'deveshkakkar'
            and date(event.get('created_at')) == merged_at, 'merge_event_identity_mismatch')
    merge = sha(event.get('commit_id'))
    advertised = pr.get('merge_commit_sha')
    # Absence/null permit corroborated recovery; malformed or contradictory fields do not.
    if advertised is not None:
        require(sha(advertised) == merge, 'merge_metadata_conflict')
    commit = obj(get(PREFIX + '/commits/' + merge))
    parents = commit.get('parents')
    require(sha(commit.get('sha')) == merge and type(parents) is list and len(parents) == 2,
            'two_parent_merge_commit_required')
    parent_shas = [sha(obj(p).get('sha')) for p in parents]
    require(parent_shas[1] == head and parent_shas[0] != head, 'merge_parent_head_mismatch')
    # The base may have advanced before merge. Compare the original base to the actual first parent.
    comparison = obj(get(PREFIX + '/compare/' + subject['base_sha_at_create'] + '...' + parent_shas[0]))
    require(comparison.get('status') in ('identical', 'ahead')
            and sha(obj(comparison.get('base_commit')).get('sha')) == subject['base_sha_at_create']
            and sha(obj(comparison.get('merge_base_commit')).get('sha')) == subject['base_sha_at_create'],
            'original_base_not_in_merge_history')
    reviews = get(path + '/reviews?per_page=100')
    require(type(reviews) is list and all(type(r) is dict for r in reviews), 'reviews_shape')
    unique_ids(reviews, 'review_ids_missing_or_duplicated')
    owner = [r for r in reviews if obj(r.get('user')).get('id') == OWNER_ID]
    require(owner and all(type(r.get('id')) is int and r['id'] > 0 for r in owner), 'owner_approval_missing')
    # COMMENTED is not an approval change. A dismissal/changes request still blocks.
    decisions = [r for r in owner if r.get('state') != 'COMMENTED']
    require(decisions, 'owner_approval_missing')
    latest = max(decisions, key=lambda r: (date(r.get('submitted_at')), r['id']))
    require(latest.get('state') == 'APPROVED' and latest.get('commit_id') == head
            and date(latest.get('submitted_at')) <= merged_at, 'matching_owner_approval_missing')
    checks = obj(get(PREFIX + '/commits/' + head + '/check-runs?per_page=100'))
    rows = checks.get('check_runs')
    require(type(rows) is list and all(type(c) is dict for c in rows)
            and type(checks.get('total_count')) is int and checks['total_count'] == len(rows), 'checks_incomplete')
    unique_ids(rows, 'check_ids_missing_or_duplicated')
    trusted = [c for c in rows if c.get('name') == 'offline' and obj(c.get('app')).get('id') == 15368]
    require(trusted and all(type(c.get('id')) is int and c['id'] > 0 for c in trusted), 'trusted_offline_check_missing')
    check = max(trusted, key=lambda c: c['id'])
    require(check.get('head_sha') == head and check.get('status') == 'completed' and check.get('conclusion') == 'success'
            and date(check.get('completed_at')) <= merged_at,
            'trusted_offline_check_not_successful')
    return {'A14': 'OWNER_ATTESTED_HUMAN_UI_AND_GITHUB_MERGE_OBSERVED', 'pr': number,
            'head_sha': head, 'merge_commit_sha': merge, 'merge_event_id': event['id'],
            'merge_sha_source': 'GitHub merge event corroborated by commit parents and original-base ancestry',
            'pr_merge_field': 'present' if advertised is not None else 'missing_or_null',
            'owner_review_id': latest['id'], 'check_id': check['id'], 'check_producer_app_id': 15368,
            'author': 'proofgate-coder[bot]', 'author_id': subject['author_id'], 'merge_actor_id': OWNER_ID,
            'approval_source': 'GitHub metadata plus explicit owner human-UI acknowledgment',
            'independent_admission_verified': False, 'A13': 'UNVERIFIED'}


def receipt_snapshot(results):
    paths = sorted(results.glob('trial*.json'))
    failure = results / 'controlfailure.json'
    if failure.exists() or failure.is_symlink(): paths.append(failure)
    require(len(paths) <= 128, 'receipt_count_bound')
    values = {}
    for path in paths:
        protected(path, private=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_size <= 65536, 'receipt_size_or_type')
            raw = os.read(fd, 65537)
            require(len(raw) <= 65536, 'receipt_size_bound')
            values[path.name] = raw
        finally:
            os.close(fd)
    return values


def recover(number, human_ack, results=None, get=None):
    require(type(number) is int and number > 0 and human_ack is True, 'human_ui_ack_required')
    results = STATE / 'results' if results is None else results
    before = receipt_snapshot(results)
    subjects = [(name, trial_subject(decode(raw), number)) for name, raw in before.items()
                if name.startswith('trial')]
    subjects = [(name, s) for name, s in subjects if s is not None]
    require(len(subjects) == 1, 'unique_successful_local_trial_required')
    receipt, subject = subjects[0]; reader = PublicGitHub() if get is None else get
    report = {'schema': 1, 'operation': 'read_only_a14_recovery', 'A14': 'NOT_VERIFIED',
              'new_tokens_issued': False, 'trial_repeated': False, 'independent_admission_verified': False,
              'A13': 'UNVERIFIED', 'original_trial_receipt': receipt,
              'repository_id': REPO_ID, 'app_id': APP_ID, 'installation_id': INSTALLATION_ID,
              'issuer_revision': REVISION, 'observer_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'original_evidence_sha256': {n: hashlib.sha256(raw).hexdigest() for n, raw in before.items()}}
    try:
        report.update(verify(subject, reader))
    except Exception as error:
        report['error'] = str(error) if type(error) is Stop else type(error).__name__
        raise
    finally:
        report['github_reads'] = getattr(reader, 'evidence', [])
        report['original_evidence_unchanged'] = receipt_snapshot(results) == before
        if not report['original_evidence_unchanged']:
            report.update(A14='NOT_VERIFIED', error='original_evidence_changed')
        name = 'a14recovery' + uuid.uuid4().hex + '.json'
        write(results / name, json.dumps(report, sort_keys=True, indent=2) + '\n', exclusive=True)
        require(report['original_evidence_unchanged'], 'original_evidence_changed')
    return {**report, 'recovery_receipt': name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('number', type=int)
    parser.add_argument('--human-ui-approval-and-merge', action='store_true')
    args = parser.parse_args()
    try:
        require(os.getuid() == 0, 'owner_only'); resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        config()  # Verify existing installed pins and binding; never open key/start issuer.
        print(json.dumps(recover(args.number, args.human_ui_approval_and_merge), sort_keys=True))
        return 0
    except Exception as error:
        code = str(error) if type(error) is Stop else type(error).__name__
        print('a14_recovery_failed:' + code, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
