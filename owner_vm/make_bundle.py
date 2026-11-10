"""Developer-only deterministic file manifest; no deployment or credentials."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.iterdir())
         if p.is_file() and p.name != 'bundle-manifest.json'
         and p.suffix in ('.py', '.json', '.lock', '.md')}
(root / 'bundle-manifest.json').write_text(json.dumps({'schema': 1, 'files': files}, indent=2) + '\n')
