# proofgate-issuer-canary-01: owner commands

No VM connection, SSH credential request or host change has been performed by the agent. The supplied Ubuntu24.04/Python3.12/KVM/2vCPU/3GiB/30GiB environment matches the reviewed bootstrap. The VM input remains b68850a; issuer input remains5609432. No PR merge or branch-protection bypass is required. All commands below are run by the owner, in the explicitly named environment.

## 1. KVM host: contain the inherited administrator identity before a key exists

Docker group membership grants root-level access; LXD local admin membership can expose the host filesystem. This observed Photon session also has libvirt, kvm, sudo and adm membership. Masking only a Docker socket, clearing an environment variable, or editing `/etc/group` while old processes remain alive does not establish separation. KVM access alone is not a claim of host-root authority; it is unnecessary to this Photon role and is excluded.

The observed process is an interactive SSH-owned agent, not a dedicated Photon service. **Do not modify or stop ssh.service, remove devesh's administrator groups, terminate the entire owner login, or stop Docker/LXD/libvirt workloads.** From a separate trusted owner console, run the read-only snapshot and review the reported agent PIDs:

```sh
python3 -I -B host_boundary/gate.py snapshot
```

Stop the identified old Photon/coding-agent processes through their normal exit controls. Recheck the snapshot until `privileged_agent_processes` is empty. PID names are a focused check, not an exhaustive inventory of renamed runtimes: owner must also stop their privileged command/tool hosts and ensure no owner-authenticated SSH, hypervisor or root-command broker remains callable by Photon. The owner SSH/admin shell stays available. Do not install the VM key while the old admin-UID agent/tool host continues running.

Install only this reviewed helper into a new root-protected location; refuse an existing helper rather than overwrite another deployment:

```sh
(
set -eu
test ! -e /usr/local/libexec/proofgate-host-boundary
test ! -L /usr/local/libexec/proofgate-host-boundary
sudo install -d -o root -g root -m 0755 /usr/local/libexec/proofgate-host-boundary
sudo install -o root -g root -m 0644 host_boundary/gate.py /usr/local/libexec/proofgate-host-boundary/gate.py
sudo python3 -I -B /usr/local/libexec/proofgate-host-boundary/gate.py prepare --domain proofgate-issuer-canary-01
)
```

The domain argument names the **host's libvirt domain**, not a guest SSH address. If the actual domain name differs from the hostname, supply that actual domain; do not invent a disk path or proceed on failure. Prepare reads only host-side libvirt metadata for active/inactive local disk paths, never guest files or disk contents. Unknown network disks and directly listening Docker/LXD/libvirt TCP admin endpoints stop for owner review. It creates/validates the dedicated `pg-photon-host` account and private `/var/lib/proofgate-photon-host` home, writes one new non-secret root-owned baseline, and leaves owner groups/services/VM configuration unchanged.

Test the kernel-enforced profile without starting a model or reading any VM disk bytes:

```sh
sudo python3 -I -B /usr/local/libexec/proofgate-host-boundary/gate.py launch -- /usr/bin/python3 -I -B /usr/local/libexec/proofgate-host-boundary/gate.py probe
```

Expected: `passed:true`, dedicated UID with no privileged/inherited groups, zero effective/permitted/ambient/bounding capabilities, no-new-privileges, no owner agents/environment/descriptors, denied Docker/libvirt socket connections, denied/masked `/dev/kvm` and actual VM disks, and denied noninteractive sudo. The probe sends **no daemon API requests**, reads **no disk contents**, and issues **no device ioctls**. A missing or masked endpoint cannot establish a live LXD denial. `lxd_path_denial_observed` records pathname permission denial only; `lxd_live_denial_verified` remains false, even if a masked directory returns EACCES. Any unexpected successful connection/open is a failure and stops key installation. An inactive/refused socket is inconclusive, not a permission denial.

This command tests the proposed profile, not an active Photon model. The fastest first-trial path is to keep all old privileged Photon processes **stopped** while performing the owner-only VM steps. Before resuming Photon while the VM retains its key, launch the actual runtime with this same helper and have its actual tool context run the probe again:

```sh
sudo python3 -I -B /usr/local/libexec/proofgate-host-boundary/gate.py launch -- /absolute/root-owned/Photon-executable <its-non-secret-arguments>
```

The executable is the one genuine owner-supplied installation input; it must resolve to root-owned code under protected ancestors. Do not guess a path or copy owner GitHub/SSH/Docker/LXD credentials. The helper's transient unit uses a clean dedicated account, empty capability sets, private devices/tmp, protected owner homes, masked daemon/DBus/hypervisor/actual disk paths, and a clean environment. Each host runtime is bounded to 1GiB memory, no swap, 128 tasks, one CPU and 30 minutes; a limit failure requires owner review, not privilege removal. Configure only the dedicated runtime's permitted model access separately. Test from the actual restarted runtime/tool host, not merely sudo-u or a wrapper retaining the old owner's tools. Owner must review any remote/connected administrative tools outside this local OS check. Retest if group memberships, privileged TCP listeners, daemon socket permissions or VM storage topology change.

Recovery: exit/stop only the newly named `proofgate-photon-<nonce>` unit from the owner console. Owner administration and existing daemons are unchanged. Do not restore admin groups, sockets or owner credentials to the agent as a workaround. The helper does not delete accounts, baselines, disks, services or data; removal/replacement is a separate owner recovery decision. If this host cannot exclude every Photon administrative route, keep the key absent and use an independently administered VM host instead.

## 2. Inside the owner VM, after the host gate

The owner supplies the reviewed source bundle to their own existing VM console/SSH session; the agent does not connect or receive SSH credentials. The existing no-key VM bundle has SHA256 `7abc3b6aca720aa8fdd11b53f19ab1161bae95b011f4efeae2bfe534096dd80c`.

```sh
(
set -eu
test "$(hostname -s)" = proofgate-issuer-canary-01
printf '%s  %s\n' '7abc3b6aca720aa8fdd11b53f19ab1161bae95b011f4efeae2bfe534096dd80c' 'owner-bootstrap-b68850a.tar.gz' | sha256sum --check -
stage=$(mktemp -d ./proofgate-owner-install.XXXXXXXX)
tar --no-same-owner --no-same-permissions -xzf owner-bootstrap-b68850a.tar.gz -C "$stage"
sudo python3 -I -B "$stage/owner_vm/bootstrap.py" prepare --fresh-isolated-vm
sudo /var/lib/proofgate-canary/runtime/bin/owner-control preflight
)
```

Only acknowledge `--fresh-isolated-vm` after the host mitigation/containment above is true. Prepare chooses all guest UIDs/paths, verifies pinned code/wheels and runs the real namespace/cgroup preflight. It does not start the issuer or create/import a key. Verify no credentials are present and the binding is exact:

```sh
sudo python3 -I -B - <<'PY'
import json, pathlib, subprocess
c = json.loads(pathlib.Path('/etc/proofgate-canary/issuer.json').read_text())
assert (c['app_id'], c['installation_id'], c['repository_id']) == (5690450, 180587357, 1452255523)
assert c['repository'] == 'deveshkakkar/ProofGate-authority-canary'
assert c['owner_isolation_verified'] is True
assert not pathlib.Path(c['key_path']).exists()
assert subprocess.run(['systemctl','is-active','--quiet','proofgate-canary-issuer.service']).returncode != 0
print(json.dumps({'binding_verified':True,'key_absent':True,'issuer_inactive':True}))
PY
```

## 3. Owner key import, genuine App PR and human A14

After the host boundary passes and old privileged Photon/tool hosts remain stopped or are replaced and actually tested, owner generates the App key and transfers it privately to the VM admin home (0400/0600, no symlink ancestors). No key/token goes to Photon, Git, CI or this conversation.

```sh
(
set -eu
sudo /var/lib/proofgate-canary/runtime/bin/owner-control import-key "$HOME/<owner-key-file>"
sudo /var/lib/proofgate-canary/runtime/bin/owner-control trial
)
```

Expected live report: App5690450/installation180587357, `token_scope_exact:true` for repository1452255523 only; completed fixed worker; PR author `proofgate-coder[bot]`; `revocation_verified:true` and `revocation_http_status:401`. Preserve the entire sanitized report, including failures. These outcomes are expected, **not yet observed on the owner VM**. If any privilege, identity or revocation result differs, stop and contain installation180587357 through the separate owner route; never broaden permissions.

Follow the returned actual PR URL. Wait for required CI, genuinely review/approve the exact head in GitHub and perform the merge yourself. Then:

```sh
sudo /var/lib/proofgate-canary/runtime/bin/owner-control observe-a14 <actual-pr-number> --human-ui-approval-and-merge
```

Share only the actual public PR URL and sanitized result/verification metadata. No command here approves or merges a PR. PR1/PR2 are not merged or bypassed. A13 remains UNVERIFIED; complete coding-agent isolation/adversarial checks follow A14. Production is untouched and issue28 stays open.

References: [Docker group authority](https://docs.docker.com/engine/install/linux-postinstall/), [LXD security](https://canonical.com/lxd/docs/latest/explanation/security/), [systemd identity and capabilities](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
