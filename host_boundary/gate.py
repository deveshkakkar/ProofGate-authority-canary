#!/usr/bin/python3
"""No guest connection, disk reads, Docker/LXD API requests or key handling."""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import uuid

ACCOUNT = 'pg-photon-host'
HOME = Path('/var/lib/proofgate-photon-host')
BASELINE = Path('/etc/proofgate-photon-host.json')
INSTALLED = Path('/usr/local/libexec/proofgate-host-boundary/gate.py')
FORBIDDEN = {'docker', 'lxd', 'incus-admin', 'libvirt', 'libvirtd', 'kvm', 'sudo', 'wheel', 'disk', 'adm'}
SOCKETS = ['/run/docker.sock', '/var/run/docker.sock', '/var/snap/lxd/common/lxd/unix.socket',
           '/var/lib/lxd/unix.socket', '/run/lxd/unix.socket', '/run/libvirt/libvirt-sock',
           '/run/libvirt/virtqemud-sock', '/run/libvirt/virtproxyd-sock']
MASK = ['/run/docker.sock', '/var/run/docker.sock', '/var/snap/lxd/common/lxd', '/var/lib/lxd',
        '/run/lxd', '/var/lib/libvirt', '/run/libvirt', '/dev/kvm', '/run/dbus/system_bus_socket']


class Stop(Exception):
    pass


def need(value, code):
    if not value:
        raise Stop(code)


def command(args):
    p = subprocess.run(args, capture_output=True, timeout=15,
                       env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})
    need(p.returncode == 0 and len(p.stdout) <= 262144, 'owner_metadata_command_failed')
    return p.stdout.decode()


def protected(path):
    path = Path(path)
    for part in [*reversed(path.parents), path]:
        s = part.lstat()
        need(not stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022, 'root_protected_path_required')
    need(path.is_file(), 'regular_file_required')
    return path


def status(pid='self'):
    raw = Path('/proc', str(pid), 'status').read_text()
    return dict(line.split(':', 1) for line in raw.splitlines() if ':' in line)


def group_names(groups):
    result = []
    for gid in groups:
        try: result.append(grp.getgrgid(gid).gr_name)
        except KeyError: result.append('unknown_gid_' + str(gid))
    return sorted(result)


def old_agents():
    rows = []
    try: safe_uid = pwd.getpwnam(ACCOUNT).pw_uid
    except KeyError: safe_uid = None
    for path in Path('/proc').iterdir():
        if not path.name.isdigit(): continue
        try:
            row = status(path.name)
            if row['Name'].strip().lower() in ('codex', 'photon'):
                uid = int(row['Uid'].split()[0])
                if uid != safe_uid:
                    rows.append({'pid': int(path.name), 'name': row['Name'].strip(), 'uid': uid})
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return rows


def snapshot():
    groups = os.getgroups()
    return {'uid': os.getuid(), 'euid': os.geteuid(), 'groups': group_names(groups),
            'unsafe_groups': sorted(set(group_names(groups)) & FORBIDDEN),
            'privileged_agent_processes': old_agents(), 'key_installation_authorized': False}


def disk_paths(text):
    paths = []
    for line in text.splitlines():
        fields = line.split(None, 3)
        if len(fields) != 4 or fields[1] != 'disk': continue
        kind, _, _, source = fields
        need(kind in ('file', 'block') and source.startswith('/')
             and re.fullmatch(r'/[A-Za-z0-9_./-]+', source), 'unsupported_disk_source_owner_review_required')
        path = str(Path(source).resolve(strict=True))
        need(Path(path).is_file() or stat.S_ISBLK(Path(path).stat().st_mode), 'disk_source_type')
        paths.append(path)
    need(paths, 'no_local_disk_metadata')
    return paths


def prepare(domain):
    need(os.getuid() == 0, 'owner_root_required')
    need(not old_agents(), 'stop_old_privileged_photon_processes_first')
    need(re.fullmatch(r'[A-Za-z0-9_.-]+', domain), 'invalid_domain_name')
    active = command(['virsh', '--connect', 'qemu:///system', 'domblklist', domain, '--details'])
    inactive = command(['virsh', '--connect', 'qemu:///system', 'domblklist', domain, '--details', '--inactive'])
    disks = sorted(set(disk_paths(active) + disk_paths(inactive)))
    # Do not claim a clean account fixes an unreviewed daemon's TCP administration route.
    listeners = command(['ss', '-H', '-lntp'])
    need(not any(name in listeners for name in ['"dockerd"', '"lxd"', '"libvirtd"', '"virtqemud"', '"virtproxyd"']),
         'privileged_tcp_listener_requires_owner_review')
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        command(['useradd', '--system', '--user-group', '--create-home', '--home-dir', str(HOME),
                 '--shell', '/usr/sbin/nologin', ACCOUNT])
        account = pwd.getpwnam(ACCOUNT)
    need(account.pw_uid > 0 and account.pw_dir == str(HOME) and account.pw_shell == '/usr/sbin/nologin'
         and grp.getgrgid(account.pw_gid).gr_name == ACCOUNT
         and set(os.getgrouplist(ACCOUNT, account.pw_gid)) == {account.pw_gid}, 'account_not_clean')
    need(HOME.is_dir() and not HOME.is_symlink() and HOME.stat().st_uid == account.pw_uid, 'home_not_owned')
    os.chmod(HOME, 0o700)
    data = {'schema': 1, 'domain': domain, 'expected_account': ACCOUNT,
            'uid': account.pw_uid, 'gid': account.pw_gid, 'vm_disks': disks,
            'privileged_tcp_listeners_absent_at_capture': True,
            'actual_photon_runtime_verified': False,
            'guest_access_performed': False, 'private_key_installed': False}
    need(not BASELINE.exists() and not BASELINE.is_symlink(), 'baseline_exists_review_before_replacing')
    fd = os.open(BASELINE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as stream:
        os.fchmod(stream.fileno(), 0o644)
        stream.write(json.dumps(data, indent=2) + '\n'); stream.flush(); os.fsync(stream.fileno())
    return data


def denied_socket(path):
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(0.5)
            connection.connect(path)  # Deliberately send no daemon API request.
        return 'UNEXPECTED_ACCESS'
    except PermissionError: return 'DENIED'
    except FileNotFoundError: return 'ABSENT_OR_MASKED'
    except (ConnectionRefusedError, TimeoutError): return 'INCONCLUSIVE'
    except OSError: return 'INCONCLUSIVE'


def denied_open(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        os.close(fd)  # Never read a VM disk or perform a device ioctl.
        return 'UNEXPECTED_ACCESS'
    except PermissionError: return 'DENIED'
    except FileNotFoundError: return 'ABSENT_OR_MASKED'
    except OSError: return 'INCONCLUSIVE'


def inherited_authority(disks):
    """Inspect descriptor metadata only. Never read data or send a request."""
    blocked = ['/home/', '/root/', '/var/lib/libvirt/', '/var/lib/lxd/', '/var/snap/lxd/', *disks]
    count = 0
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd <= 2: continue
        try:
            target = os.readlink('/proc/self/fd/' + name)
            if any(target.startswith(value) for value in blocked):
                count += 1
            if stat.S_ISSOCK(os.fstat(fd).st_mode):
                with socket.socket(fileno=os.dup(fd)) as connection:
                    try:
                        connection.getpeername()
                        count += 1  # An unexplained inherited connection is not an acceptable clean start.
                    except OSError:
                        pass
        except (FileNotFoundError, OSError):
            continue
    return count


def probe():
    result = snapshot()
    need(os.getuid() != 0, 'must_test_unprivileged_runtime')
    baseline = json.loads(protected(BASELINE).read_text())
    row = status()
    clean = (os.getuid() == baseline['uid'] == os.geteuid()
             and set(os.getgroups()) <= {baseline['gid']} and os.getgid() == baseline['gid']
             and not result['unsafe_groups'] and not result.get('privileged_agent_processes')
             and row['NoNewPrivs'].strip() == '1'
             and all(int(row[name].strip(), 16) == 0 for name in ['CapEff', 'CapPrm', 'CapAmb', 'CapBnd']))
    result.update(identity_and_kernel_profile_clean=clean, pid=os.getpid(), checks={})
    if not clean:
        result['passed'] = False
        return result
    require_absent = ['SSH_AUTH_SOCK', 'GPG_AGENT_INFO', 'DOCKER_HOST', 'DOCKER_CONTEXT',
                      'LXD_CONF', 'LIBVIRT_DEFAULT_URI', 'GH_TOKEN', 'GITHUB_TOKEN']
    result['owner_environment_absent'] = not any(name in os.environ for name in require_absent)
    result['owner_home_hidden'] = not os.access('/home', os.R_OK) and not os.access('/root', os.R_OK)
    result['unexpected_inherited_descriptors'] = inherited_authority(baseline['vm_disks'])
    if result['unexpected_inherited_descriptors']:
        result.update(passed=False, stop='inherited_authority_detected')
        return result
    for path in SOCKETS:
        outcome = denied_socket(path); result['checks'][path] = outcome
        if outcome == 'UNEXPECTED_ACCESS':
            result.update(passed=False, stop='unexpected_privileged_socket_access')
            return result
    for path in ['/dev/kvm', *baseline['vm_disks']]:
        outcome = denied_open(path); result['checks'][path] = outcome
        if outcome == 'UNEXPECTED_ACCESS':
            result.update(passed=False, stop='unexpected_hypervisor_or_disk_access')
            return result
    p = subprocess.run(['/usr/bin/sudo', '-n', '--', '/usr/bin/true'], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    result['sudo_denied'] = p.returncode != 0
    result['passed'] = (result['owner_environment_absent'] and result['owner_home_hidden'] and result['sudo_denied']
                        and all(value in ('DENIED', 'ABSENT_OR_MASKED') for value in result['checks'].values()))
    result['lxd_path_denial_observed'] = any(result['checks'][p] == 'DENIED' for p in SOCKETS if 'lxd' in p)
    result['lxd_live_denial_verified'] = False  # Masked paths cannot establish whether an endpoint exists.
    result['coverage'] = 'Local OS privilege paths only; remote tools/brokers and old process termination require owner verification.'
    return result


def launch(argv):
    need(os.getuid() == 0 and argv and Path(argv[0]).is_absolute(), 'owner_root_and_absolute_runtime_required')
    protected(INSTALLED)
    argv = [str(protected(Path(argv[0]).resolve(strict=True))), *argv[1:]]
    baseline = json.loads(protected(BASELINE).read_text())
    need(not old_agents(), 'stop_old_privileged_photon_processes_first')
    need(pwd.getpwnam(ACCOUNT).pw_uid == baseline['uid']
         and set(os.getgrouplist(ACCOUNT, baseline['gid'])) == {baseline['gid']}, 'account_membership_drift')
    masks = [*MASK, *baseline['vm_disks']]
    need(all(re.fullmatch(r'/[A-Za-z0-9_./-]+', value) for value in masks), 'mask_path')
    unit = 'proofgate-photon-' + uuid.uuid4().hex
    args = ['systemd-run', '--quiet', '--pty', '--wait', '--collect', '--unit=' + unit,
            '--property=User=' + ACCOUNT, '--property=Group=' + ACCOUNT,
            '--property=NoNewPrivileges=yes', '--property=CapabilityBoundingSet=', '--property=AmbientCapabilities=',
            '--property=PrivateTmp=yes', '--property=PrivateDevices=yes', '--property=ProtectHome=yes',
            '--property=ProtectSystem=strict', '--property=ProtectControlGroups=yes', '--property=ProtectKernelTunables=yes',
            '--property=ProtectKernelModules=yes', '--property=RestrictSUIDSGID=yes', '--property=RestrictNamespaces=yes',
            '--property=LockPersonality=yes', '--property=UMask=0077', '--property=KillMode=control-group',
            '--property=MemoryMax=1G', '--property=MemorySwapMax=0', '--property=TasksMax=128',
            '--property=CPUQuota=100%', '--property=RuntimeMaxSec=30min',
            '--property=ReadWritePaths=' + str(HOME), '--property=WorkingDirectory=' + str(HOME),
            '--property=InaccessiblePaths=' + ' '.join('-' + value for value in masks),
            '--property=Environment=HOME=' + str(HOME),
            '--property=ExecStartPre=/usr/bin/env -i HOME=' + str(HOME) +
            ' PATH=/usr/local/bin:/usr/bin:/bin /usr/bin/python3 -I -B ' + str(INSTALLED) + ' probe',
            '/usr/bin/env', '-i', 'HOME=' + str(HOME), 'PATH=/usr/local/bin:/usr/bin:/bin',
            'TERM=xterm-256color', *argv]
    return subprocess.call(args, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'TERM': 'xterm-256color'})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    sub.add_parser('snapshot'); sub.add_parser('probe')
    owner = sub.add_parser('prepare'); owner.add_argument('--domain', default='proofgate-issuer-canary-01')
    runtime = sub.add_parser('launch'); runtime.add_argument('argv', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.mode == 'launch':
            return launch(args.argv[1:] if args.argv[:1] == ['--'] else args.argv)
        result = snapshot() if args.mode == 'snapshot' else prepare(args.domain) if args.mode == 'prepare' else probe()
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if args.mode != 'probe' or result.get('passed') is True else 1
    except Exception as error:
        code = str(error) if type(error) is Stop else type(error).__name__
        print(json.dumps({'passed': False, 'error': code, 'key_import_blocked': True}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
