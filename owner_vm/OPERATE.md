# Owner bootstrap: fresh Ubuntu VM only

This selects defaults; none is an assertion about an existing VM. Supported target: a **fresh Ubuntu24.04LTS amd64 VM**, recommended2vCPU/2GiB/10GiB. Owner retains console/admin recovery access. Photon must have no SSH credentials, shared mounts, hypervisor/admin route or command execution into this VM. No public ports, firewall changes or new remote access are configured. The VM exclusion is an explicit owner provisioning assertion, not a claim a local script can remotely prove.

The immutable issuer input is `5609432116921acad9f10ef05c17140c170d72fb`. Its files are SHA256-verified from a public GitHub archive; original issuer code is not modified. Deployment files and launcher are content-pinned in `bundle-manifest.json`, reverified in the root-owned installed manifest. Dependencies use four exact wheel versions/hashes, with no source builds or package resolution. No PR1 bypass/merge is required or attempted: the owner reviews and executes this immutable preparation input outside Photon.

Owner decisions are only **the isolated VM** and **the privately transferred key file**. Accounts `pg-issuer`, `pg-worker`, `pg-denied`, private groups and UIDs are discovered/created and validated automatically. Launcher is the existing trusted VM root account; candidate code always runs as pg-worker. Runtime defaults to `/var/lib/proofgate-canary/runtime`, configuration to `/etc/proofgate-canary`, state to `/var/lib/proofgate-canary` and IPC to `/run/proofgate-canary`. These are VM-only defaults. Runtime does not trust a potentially writable `/opt`, and installation sets an explicit022umask. The legacy config `photon_uid` field binds pg-denied, an unprivileged denial fixture; it does not assert Photon has an identity on this VM.

From an owner-reviewed immutable checkout/archive of this bootstrap revision, in the owner VM console:

```sh
sudo python3 -I -B owner_vm/bootstrap.py prepare --fresh-isolated-vm
```

Prepare refuses other OS/architecture, unsafe existing accounts/directories, changed package profile, shared/unreviewed deployment revisions or a running partial service. It installs only the selected VM dependencies, verifies original issuer bytes and deployment digests, binds configuration, loads the pinned packaged bwrap AppArmor profile and runs an actual no-key preflight. It does not disable AppArmor/userns restrictions globally. No issuer service starts and no key/token is created. Identical managed retries verify and preflight; an incomplete same-revision preparation can resume without resetting existing state/key. Drift stops for owner review. No force/cleanup/rotation/reset mode exists.

The worker is a fixed synthetic Python program, not a full LLM coding agent. It runs via systemd/cgroup plus unprivileged bubblewrap: distinct real hostUID; new PID/mount/user/network namespaces; readonly source; private proc/dev/tmp; no owner home, issuer/key/socket mounts, host network or token environment; zero capabilities/no-new-privileges. Root independently inspects the actual cgroup/kernel PID, UID, namespaces, source mount, memory256MiB/swap0/pids16/CPU<=1core/runtime120seconds. Worker observations additionally check network failure and a harmless outside marker. Preflight sets the issuer gate only for this exact fixed-worker profile; full coding-agent/tool isolation is still unverified.

Generate the App key **yourself** through owner GitHub settings and transfer it privately to your VM admin home with0400/0600 permissions. Do not send it to Photon, chat, CI or Git. Key source must be a regular file under protected, non-symlink ancestors (not `/tmp`). Import never generates or rotates a key, never echoes its contents, and retains your original source for owner-managed custody:

```sh
sudo /var/lib/proofgate-canary/runtime/bin/owner-control import-key "$HOME/<owner-key-file>"
sudo /var/lib/proofgate-canary/runtime/bin/owner-control trial
```

The latter reruns OS preflight, starts the original issuer, independently checks live token scope, starts the real fixed worker and creates **one genuine App-authored synthetic canary PR**. The bearer stays inside trusted issuer/controller/gateway memory, outside both Photon and worker. Worker API requests cross a stdio gateway that allows only the canary positive-control sequence; wrapper denials are NOT GitHub permission-enforcement tests. Results must show proofgate-coder[bot] from actual GitHub response. Then issuer revokes and controller verifies denied token use(401). Five-minute lease does not change GitHub's provider expiry. Unknown privilege/revocation failure stops; owner contains the installation.

Only sanitized results under `/var/lib/proofgate-canary/results/`, the non-secret config and installed digests may be shared with Photon. Never share raw process memory, issuer sockets, key files, leases, owner credentials or tokens. Failed/inconclusive results are retained. No live token tests or owner VM behavior are implied by unit tests or credential-free hosted smoke.

Once the actual PR has green required CI, **you review and approve its exact head in GitHub and perform the merge yourself**. No command here submits approval or merges. Then observe that specific local trial's positive control:

```sh
sudo /var/lib/proofgate-canary/runtime/bin/owner-control observe-a14 <actual-pr-number> --human-ui-approval-and-merge
```

The acknowledgement records your genuine human UI action; GitHub metadata alone cannot distinguish human interaction from automation under the same account. Observation now uses public unauthenticated GETs and issues no App token. It binds the successful revoked locally recorded trial, actual App author/branch/head, owner approval, successful offline App15368 check and independently corroborated merge event/commit. New observation receipts are exclusive and never replace the original trial or failure. For an existing b68850a deployment and the PR4 missing-merge-field incident, follow [A14-RECOVERY.md](A14-RECOVERY.md) instead of invoking the old deployed observer; do not rerun trial or bootstrap. It does not establish full independent admission or policy freshness. A13 stays UNVERIFIED until its future actual authenticated negative test, without further configuration retries. No production activity is allowed.

Recovery: stop only the new worker unit(s) and issuer; preserve results/state/protections. The issuer normally revokes active tokens. If a token outcome/revocation is unknown, use your separate owner route to suspend installation180587357; deleting a key does not revoke existing tokens. Running/blocked durable state is never reset automatically. Owner must verify containment before any manual recovery/reset. Existing VM admin access remains unchanged. Complete-worker isolation and adversarial tests follow only after actual A14; issue28 stays open.
