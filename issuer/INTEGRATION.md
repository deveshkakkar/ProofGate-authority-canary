# Owner-provisioned canary issuer contract

Executable preparation; **not installed or credential-enabled**. The owner supplies real deployment values. No key, token, actual deployment path or OS account has been supplied to Photon. Production access is forbidden. A13 remains UNVERIFIED; do not retry the omitted ruleset field. This kit is not independent admission verification.

## Fixed authority

App `5690450` (`proofgate-coder`), installation `180587357`, owner `deveshkakkar` / `41484281`. Only repository `1452255523`, `deveshkakkar/ProofGate-authority-canary`. No selector, scope, command, URL, key path or TTL may be supplied by a socket caller.

Repository permissions are exactly Metadata/Actions/Checks/Issues/Commit statuses **read**, Contents/Pull requests **write**. Every other repository, organization, account and enterprise permission is absent. No administration, workflows, check/status publication or production token. A permission or identity mismatch locks issuance until owner investigation.

## Owner inputs — all currently unbound

Fill `owner-config.template.json` outside Git; null values deliberately fail startup. The non-secret configuration may be shared after paths/identities are approved; **never share its referenced key or credential bytes**.

| Owner must supply | Required invariant |
| --- | --- |
| Issuer host/runtime boundary and operator | Photon cannot administer, SSH into, mount, inspect or execute owner commands in it. A different UID alone fails if Photon can reach host sudo/Docker or the credential store. |
| Python executable / venv / installed kit revision | Linux, Python >=3.12, pinned `PyJWT[crypto]` runtime. Owner installs a reviewed wheel into a root-owned, non-writable runtime, independently locks/transcribes transitive dependency versions and records its digest. No runtime package downloads or candidate imports. |
| Issuer OS user/UID; private IPC group | Dedicated non-root UID, different from launcher, worker and Photon; no shell exposed to them. Owner controls group membership. |
| Launcher OS user/UID | Trusted owner-controlled supervisor, distinct from issuer/worker/Photon. Root is permissible for a reviewed sandbox supervisor; never for candidate code. No owner GitHub token is needed. |
| Worker UID and Photon UID | Distinct from each other and both trusted roles; neither can read issuer files/processes or invoke its socket. Worker has no sudo, Docker/host socket, owner connector, SSH agent, host home or issuer mount. |
| Config path | Root-owned non-secret file, no group/other writes, protected ancestors, no symlinks. |
| Key path | Owner creates/downloads App key through the separate trusted process. Dedicated issuer UID owns it with mode0400/0600; parent0700 and protected ancestors. Outside Photon and worker; never a repo file, command-line value, environment secret or chat attachment. |
| Socket path/directory | AF_UNIX pathname only, no TCP listener. Dedicated issuer-owned directory0750/0710; group traversal only for trusted launcher; socket0660 in that private IPC group. Protected ancestors, no symlinks. Worker has no mount/route to it. |
| Audit path | Owner pre-creates issuer-owned0600 file; protected ancestors, no symlinks. Capacity bound1MiB, then fail closed; owner preserves/rotates it while service stopped. |
| State path | Owner pre-creates issuer-owned0600 secret-free file containing exactly `{"state":"ready"}` after confirming no outstanding credential. It is fsynced to running before key access. Blocked/unclean-running states refuse startup, including after reboot; only owner containment permits reset to ready. Protected ancestors, no symlinks. |
| Worker launcher path and SHA256 | Root-owned immutable executable and protected interpreter/dependencies. No caller-selected argv. It creates a fresh bounded sandbox/cgroup, drops to worker UID, closes all inherited FDs except the explicit credential pipe, exposes only the fixed canary workspace/tools and enforces the network/mount/process/tool boundary. |
| `owner_isolation_verified` | False until owner verifies the **actual** full worker/tool boundary. This is an owner deployment gate, not a self-attestation proving isolation. Supply sanitized PID/UID/namespace/mount/tool/denied-access evidence and revision separately. |

## Startup and local IPC

`issuer.service.in` is a disabled, unbound **system service template**. Owner substitutes every `@...@` value, installs the wheel/runtime/config on the trusted host and reviews the resulting unit. ProtectHome means key/runtime/config must be accessible outside protected home directories. Systemd starts the issuer as its dedicated user, with no restart, no capabilities/core dumps, private devices/tmp, read-only system, explicit socket/audit write paths,128MiB/16tasks/25%CPU and30min maximum runtime. No existing host service is changed by this repository.

Issuer command (placeholders, not actual paths):

```text
<owner-supplied-python> -I -B -m issuer.server <owner-supplied-config>
```

Owner-controlled launcher command, **outside Photon and outside the worker**:

```text
<owner-supplied-python> -I -B -m issuer.launcher <owner-supplied-config>
```

The launcher adapter is **not a sandbox**. Owner must provide and verify the root-owned sandbox launcher before setting the isolation gate. Its fixed executable receives only `PATH` and `PROOFGATE_TOKEN_FD`; that pipe contains one bounded JSON lease. It must start the real worker with its restricted tool catalog and canary credentials, not reuse Photon's owner-context tools. No credential in argv, shell history, remote URLs, Git config, persisted helper or default environment. The owner launcher must terminate the entire sandbox/cgroup on exit or timeout; killing its parent alone is insufficient. It retains bounded synthetic test observations separately without credential values; the adapter suppresses untrusted stdout/stderr.

IPC is one JSON line per connection: request <=4096bytes, response/credential pipe <=16384bytes. Tokens up to8192ASCII characters are accepted to accommodate GitHub's stateless token format; no fixed40character assumption. Kernel `SO_PEERCRED` must match the configured launcher UID; the launcher checks the issuer's kernel UID. The only messages are `{"op":"issue"}` and `{"op":"release","lease_id":"<issuer nonce>","outcome":"success|failure|timeout|launcher_failure"}`. Unknown fields and caller-selected scope fail. The issue response contains token/lease/expiry and travels only over privateIPC and an inherited pipe to the owner-verified launcher/worker. Credential-pipe writes have a five-second absolute deadline. Photon receives only sanitized outcome records. No API is provided for caller-selected commands or admin operations.

## Independent GitHub checks and lease

The issuer uses established PyJWT RS256 App JWTs (five-minute validity including60seconds clock skew) and TLS to fixed `api.github.com`; no proxy, redirect, alternate host or owner-auth fallback. Each provider call has an absolute10second Linux/main-thread signal deadline; IPC response budget120seconds accommodates the eight provider calls and cleanup. IPC request reads have a two-second absolute deadline. Launcher and issuer disable core dumps; the sandbox must also disable them. It independently reads `/app`, the App installation inventory and the specific installation. Require exact App/owner/installation/permission identities, zero webhook events, selected repository mode and non-suspended state. More than one App installation fails. Private visibility and OAuth-disablement remain owner-side registration evidence; the runtime does not pretend API fields prove them.

POST always specifies repository ID1452255523 and the full exact permission allowlist. The issuer validates the returned repositories/permissions/expiry, then calls `/installation/repositories` with the narrowed token and rechecks installation metadata before release. **The narrowed token inventory proves token scope, not the complete selected repository grant of the installation.** The complete canary-only grant still requires owner-side current installation readback. It is never inferred from a token with requested repository scope. No broader inventory token is issued as a workaround.

GitHub controls provider expiry (normally1hour); this implementation accepts <=3600seconds and permits one active five-minute lease. The response includes its monotonic deadline, shared by the two trusted local processes. Worker timeout is the lesser of240seconds and remaining lease minus15seconds; leases with <30seconds remaining are not released. The issuer initiates revocation on completion, lease deadline or graceful stop. Normal polling/request handling can add up to three seconds before a deadline revocation attempt; that provider call has a ten-second bound and can fail. This assumes healthy local storage. It does not represent the five-minute lease as provider-enforced expiry. A hard crash can leave the token valid until provider expiry; owner containment below is required. Unknown POST outcome, validation drift or failed revocation persistently block further issuance. Startup changes state ready->running before key access; only clean stop after successful revocation restores ready. Crash/poison cannot be cleared by reboot/restart. Owner containment is required before resetting the state file.

## Audit and recovery

Issuer records internally constructed UTC, event, App/installation/repository IDs, OS peer UID, lease UUID, provider expiry, lease duration, exact permissions, fixed API endpoint/method/HTTP status, worker outcome and revocation outcome. Owner records config/code/runtime/launcher digests, real OS/host/tool boundary evidence, actual App bot PR author, head/base SHAs, checks and review IDs separately. Logs contain no token/JWT/key, credential fingerprints, provider response bodies, arbitrary caller fields or untrusted worker text. Successful fake-provider tests are not live GitHub evidence.

Containment sequence: stop the launcher/worker cgroup and disable issuance; issuer calls DELETE `/installation/token` using its in-memory active token. Confirm its revoked/denied-use observation with the same isolated credential channel. If the issuer crashed, audit failed, POST outcome is unknown or revocation failed, **owner suspends the specific canary installation180587357** through owner settings, verifies containment and preserves evidence. Removing a private key alone does not revoke already-issued installation tokens. Do not restart issuance, broaden a grant, remove protections or fall back to an owner token. Owner recovery/re-enablement remains explicit; no unrelated installation or service is touched. SIGKILL/power-loss containment has not been tested.

## Executable acceptance sequence

1. Local: `python3 -m unittest discover -s issuer -t . -v`. Provider/signing tests use synthetic mocks, no keys/network; kernel socket peer-UID observation is real local OS evidence only.
2. Owner provisions actual runtime/identities/config/key/privateIPC and verifies denied owner credential/tool/mount access from the actual full coding worker. Return only sanitized configuration and isolation evidence. No token comes to Photon.
3. Owner starts issuer/launcher. Capture authenticated App/installation metadata and audited exact grant/revocation; use the isolated worker's GitHub channel to create one harmless App-authored canary PR. Record bot author, head/base, token-scope inventory and ordinary `offline` producer15368. This live test has not run.
4. Human `@deveshkakkar` reviews the exact App-authored PR in GitHub and approves; authorized human-operated merge establishes A14. Neither owner-context automation nor an owner-authored PR substitutes for that review. Until A14 succeeds, negative merge denials remain inconclusive for policy enforcement.
5. Execute the approved canary attacks with all confounders recorded. Test A13 using the authenticated App against a real human blocking review; keep UNVERIFIED until observed. Stop and revoke for unexpected privilege; do not retry the omitted configuration field. A04 remains NOT_RUN without a second authorized disposable target.

Issue28 remains open. This coder issuer cannot publish a trusted admission check and is not the future verifier identity. Protected policy registry, authenticated verification and source/base/policy freshness remain separate unproven requirements. No production credentials, protection changes or activation proposal is ready from this kit alone.

API/runtime references: [installation token scope and format](https://docs.github.com/en/rest/apps/apps#create-an-installation-access-token-for-an-app), [installation repository inventory](https://docs.github.com/en/rest/apps/installations#list-repositories-accessible-to-the-app-installation), [RS256/PyJWT](https://pyjwt.readthedocs.io/en/stable/usage.html#encoding-decoding-tokens-with-rs256-rsa).
