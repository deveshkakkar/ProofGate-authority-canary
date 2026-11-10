# Disposable ProofGate authority canary

Synthetic test repository, separate from production ProofGate.

The [owner issuer kit and integration contract](issuer/INTEGRATION.md) provide a fixed canary-only credential service and launcher adapter. They are not deployed. Real host paths, OS identities, key custody and the isolated worker launcher must be supplied and verified by the owner.

Run credential-free regressions with `python3 -m unittest discover -s issuer -t . -v`.
