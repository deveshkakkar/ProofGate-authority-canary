"""Fixed-scope GitHub integration. Never log provider bodies or credentials."""
from datetime import datetime, timezone
from contextlib import contextmanager
import http.client
import json
import ssl
import signal
import time
import uuid

APP = 5690450
INSTALLATION = 180587357
OWNER = 41484281
REPOSITORY = 1452255523
NAME = 'deveshkakkar/ProofGate-authority-canary'
PERMISSIONS = {'metadata': 'read', 'contents': 'write', 'pull_requests': 'write',
               'actions': 'read', 'checks': 'read', 'issues': 'read', 'statuses': 'read'}


class Denied(Exception):
    """Only fixed error codes are allowed across the process boundary."""


def require(ok, code):
    if not ok:
        raise Denied(code)


def exact_id(value, expected):
    return type(value) is int and value == expected


@contextmanager
def deadline(seconds):
    """Absolute Linux/main-thread budget, not a per-read idle timeout."""
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'timer_conflict')
    def expired(*_):
        raise Denied('absolute_deadline')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def repositories(value):
    require(isinstance(value, list) and len(value) == 1, 'repository_scope')
    row = value[0]
    require(isinstance(row, dict) and exact_id(row.get('id'), REPOSITORY)
            and row.get('full_name') == NAME, 'repository_scope')


class GitHub:
    """TLS-only fixed GitHub API host; no proxies, redirects or credential helpers."""
    def __init__(self, audit=lambda row: None):
        self.audit = audit

    def __call__(self, method, path, authorization, body=None):
        with deadline(10):
            return self.request(method, path, authorization, body)

    def request(self, method, path, authorization, body=None):
        connection = http.client.HTTPSConnection('api.github.com', timeout=10,
                                                  context=ssl.create_default_context())
        try:
            connection.request(method, path, body=None if body is None else json.dumps(body),
                               headers={'Authorization': 'Bearer ' + authorization,
                                        'Accept': 'application/vnd.github+json',
                                        'X-GitHub-Api-Version': '2026-03-10',
                                        'User-Agent': 'proofgate-canary-issuer',
                                        'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.audit({'event': 'provider_http', 'method': method, 'endpoint': path.split('?')[0],
                        'status': response.status, 'app_id': APP, 'installation_id': INSTALLATION,
                        'repository_id': REPOSITORY,
                        'utc': datetime.now(timezone.utc).isoformat()})
            raw = response.read(262145)
            require(len(raw) <= 262144 and not response.getheader('Link'), 'provider_response_bound')
            require(response.status in (200, 201, 204), 'provider_request_failed')
            return {} if response.status == 204 else json.loads(raw)
        except Denied:
            raise
        except Exception:
            raise Denied('provider_unavailable') from None
        finally:
            connection.close()


class Issuer:
    def __init__(self, api, signer, audit, clock=time.time, monotonic=time.monotonic,
                 latch=lambda: None):
        self.api, self.signer, self.audit = api, signer, audit
        self.clock, self.monotonic = clock, monotonic
        self.lease = None
        self.poisoned = False
        self.latch = latch
        self.latch_failed = False

    def poison(self):
        self.poisoned = True
        try:
            self.latch()
        except Exception:
            # A failed latch write must not prevent best-effort token revocation.
            # The startup running-state already blocks restart after any unclean session.
            self.latch_failed = True

    def event(self, event, **fields):
        # Only call with internally constructed non-secret fields.
        try:
            self.audit({'event': event, 'utc': datetime.fromtimestamp(self.clock(), timezone.utc).isoformat(),
                        'app_id': APP, 'installation_id': INSTALLATION, 'repository_id': REPOSITORY,
                        **fields})
        except Exception:
            self.poison()
            raise Denied('audit_failed_owner_review_required') from None

    def installation(self, jwt):
        app = self.api('GET', '/app', jwt)
        require(exact_id(app.get('id'), APP) and app.get('slug') == 'proofgate-coder', 'app_identity')
        require(exact_id(app.get('owner', {}).get('id'), OWNER)
                and app.get('owner', {}).get('login') == 'deveshkakkar', 'app_owner')
        require(app.get('permissions') == PERMISSIONS and app.get('events') == [], 'app_permissions')
        installs = self.api('GET', '/app/installations?per_page=100', jwt)
        require(isinstance(installs, list) and len(installs) == 1
                and exact_id(installs[0].get('id'), INSTALLATION), 'installation_inventory')
        row = self.api('GET', '/app/installations/' + str(INSTALLATION), jwt)
        require(exact_id(row.get('id'), INSTALLATION) and exact_id(row.get('app_id'), APP)
                and row.get('app_slug') == 'proofgate-coder', 'installation_identity')
        account = row.get('account', {})
        require(exact_id(account.get('id'), OWNER) and account.get('login') == 'deveshkakkar'
                and account.get('type') == 'User', 'installation_account')
        require('suspended_at' in row and row['suspended_at'] is None, 'installation_suspended')
        require(row.get('repository_selection') == 'selected' and row.get('permissions') == PERMISSIONS
                and row.get('events') == [], 'installation_scope')

    def release(self):
        if self.lease is None:
            return
        lease, self.lease = self.lease, None
        try:
            self.api('DELETE', '/installation/token', lease['token'])
        except Exception:
            self.poison()
            self.event('revocation_failed', lease_id=lease['id'])
            raise Denied('revocation_failed_owner_containment_required') from None
        self.event('revoked', lease_id=lease['id'])

    def expire(self):
        if self.lease and self.monotonic() >= self.lease['deadline']:
            self.event('lease_expired', lease_id=self.lease['id'])
            self.release()

    def issue(self):
        self.expire()
        require(not self.poisoned and self.lease is None, 'issuance_unavailable')
        jwt = self.signer(int(self.clock()))
        try:
            self.installation(jwt)
        except Exception:
            self.poison()
            self.event('metadata_validation_failed')
            raise Denied('owner_review_required') from None
        # There is no caller-selectable repository or permission argument.
        try:
            grant = self.api('POST', '/app/installations/' + str(INSTALLATION) + '/access_tokens', jwt,
                             {'repository_ids': [REPOSITORY], 'permissions': dict(PERMISSIONS)})
        except Exception:
            self.poison()
            self.event('issuance_outcome_unknown')
            raise Denied('owner_containment_required') from None
        if not isinstance(grant, dict):
            self.poison()
            self.event('unusable_issuance_response')
            raise Denied('owner_containment_required')
        token = grant.get('token')
        if not (isinstance(token, str) and 0 < len(token) <= 8192
                and all(33 <= ord(c) <= 126 for c in token)):
            self.poison()
            self.event('unusable_issuance_response')
            raise Denied('owner_containment_required')
        lease_id = uuid.uuid4().hex
        self.lease = {'id': lease_id, 'token': token, 'deadline': self.monotonic() + 300}
        try:
            repositories(grant.get('repositories'))
            require(grant.get('permissions') == PERMISSIONS
                    and grant.get('repository_selection') == 'selected', 'grant_scope')
            expiry = datetime.strptime(grant['expires_at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
            require(0 < expiry.timestamp() - self.clock() <= 3600, 'grant_expiry')
            observed = self.api('GET', '/installation/repositories?per_page=100', token)
            require(type(observed.get('total_count')) is int and observed['total_count'] == 1,
                    'token_repository_inventory')
            repositories(observed.get('repositories'))
            # A scoped-token inventory proves token scope, not the App's complete installation grants.
            self.installation(self.signer(int(self.clock())))
            self.event('issued', lease_id=lease_id, provider_expires_at=grant['expires_at'],
                       lease_seconds=300, permissions=dict(PERMISSIONS))
            require(self.lease['deadline'] - self.monotonic() >= 30, 'lease_validation_too_slow')
            return {'lease_id': lease_id, 'token': token, 'lease_seconds': 300,
                    'lease_deadline_monotonic': self.lease['deadline'],
                    'provider_expires_at': grant['expires_at']}
        except Exception:
            self.poison()
            self.release()
            raise Denied('grant_validation_failed') from None

    def request(self, request, peer_uid, launcher_uid):
        require(type(peer_uid) is int and peer_uid == launcher_uid, 'peer_denied')
        require(isinstance(request, dict), 'invalid_request')
        if request == {'op': 'issue'}:
            return self.issue()
        if set(request) == {'op', 'lease_id', 'outcome'} and request['op'] == 'release':
            require(request['outcome'] in ('success', 'failure', 'timeout', 'launcher_failure'), 'invalid_outcome')
            require(self.lease is not None and request['lease_id'] == self.lease['id'], 'unknown_lease')
            try:
                self.event('worker_finished', lease_id=self.lease['id'], outcome=request['outcome'])
            finally:
                self.release()  # Completion auditing must never bypass revocation.
            return {'released': True}
        raise Denied('invalid_request')
