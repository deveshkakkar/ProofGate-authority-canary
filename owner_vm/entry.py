"""Fixed owner-installed sandbox executable accepting the issuer's private pipe."""
import json
import os
from pathlib import Path
import resource
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from owner_vm.common import config, require
from owner_vm.sandbox import execute


def main():
    require(os.getuid() == 0, 'owner_only')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    cfg = config()
    fd = int(os.environ['PROOFGATE_TOKEN_FD'])
    with os.fdopen(fd, 'rb') as stream: raw = stream.read(16385)
    require(len(raw) <= 16384, 'lease_bound')
    lease = json.loads(raw)
    execute(cfg, mode='pr', token=lease['token'])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(2)
