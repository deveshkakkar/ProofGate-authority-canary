# A14 read-only recovery on the existing owner VM

The deployed b68850a observer received a genuine merged PR response without `merge_commit_sha` and raised KeyError. Public GitHub API version2026-03-10 also reproduces this omission for PR4. The immutable issuer5609432116921acad9f10ef05c17140c170d72fb and the existing owner VM deployment are not edited. No authenticated trial is repeated and no new positive PR is created.

## Existing VM: use the side-by-side recovery artifact only

Transfer `owner-a14-recovery-v1.tar.gz` and its published SHA256 file through your existing owner-controlled route. Verify against the independently published digest, then run this in your owner VM console (not Photon). Keep the existing isolated environment and key custody unchanged. No SSH credentials go to the agent.

```sh
(
set -eu
test "$(hostname -s)" = proofgate-issuer-canary-01
sha256sum --check owner-a14-recovery-v1.sha256
stage=$(mktemp -d ./proofgate-a14-recovery.XXXXXXXX)
tar --no-same-owner --no-same-permissions -xzf owner-a14-recovery-v1.tar.gz -C "$stage"
sudo /usr/bin/python3 -I -B "$stage/owner_vm/a14.py" 4 --human-ui-approval-and-merge
)
```

The flag acknowledges the owner's genuine GitHub UI approval and human merge of the exact PR head, already reported for PR4. It never submits an approval or merge. The command verifies the existing installed code/issuer pins and repository configuration; it does not read the App key, contact the issuer, start a service, issue a token or launch a worker. It performs only unauthenticated GET requests to fixed public canary GitHub API routes. Proxy environment, bearer credentials and redirects are not used. A denied, rate-limited, paginated, oversized, malformed or ambiguous response fails closed. Do not issue an App token to work around a public API failure; wait for its rate limit/reset and rerun only this observer.

Do not run bootstrap.py, import-key, trial, or the old installed owner-control observe-a14 for this recovery. In particular, the old control exception handler overwrites controlfailure.json; this command avoids that handler entirely. The source fix also prevents future observe-a14 failures from replacing that historical failure file. The full corrected bootstrap artifact is for separate fresh deployments only; its changed bundle digest deliberately refuses adoption into the existing managed VM.

## Evidence and failure behavior

Recovery requires exactly one existing protected local successful `trial*.json` receipt for PR4: App5690450, installation180587357, repository1452255523, fixed-worker completion, original bot author ID/head/base/run ID, revocation verified and recorded HTTP401. Prior observer receipts with integer `result.pr` are not mistaken for a new trial. Missing, duplicate or invalid original trial evidence stops before any GitHub request. It never fabricates or repairs that receipt.

All existing `trial*.json` files and `controlfailure.json` are read and hashed, and must remain byte-identical across recovery. No original file is written. Successful recovery appends one exclusive root-private `/var/lib/proofgate-canary/results/a14recovery<nonce>.json`, containing original evidence hashes, observer source hash, API-response hashes, actor/check identities, recovered merge SHA and explicit A13/independent-admission limitations. A failed provider verification appends a distinct failed recovery report. Earlier input/config failures produce a nonzero CLI error without modifying old evidence. Concurrent evidence mutation invalidates recovery; existing output files are never overwritten. Keep failed and successful reports.

For missing/null PR merge SHA, recovery requires a unique GitHub `merged` timeline event with owner41484281 and the PR's exact merged_at time. Its commit ID must resolve to an actual two-parent merge commit whose second parent is the original trial head. GitHub compare metadata must confirm that the original trial base is an ancestor of the first parent. If the PR supplies a merge SHA, it must agree with the event. Squash/rebase merges are deliberately unverified by this bounded merge-commit observer. Missing/malformed/contradictory merge metadata is never replaced with user-entered constants.

The original bot identity, same-repository main target, original run branch/head, latest meaningful owner review on that head before merge, and latest offline check from GitHub Actions App15368 on that exact head must all match. Duplicate review/check IDs, a later dismissed/changes-requested review, a newer failed check, an after-merge approval/check, or missing fields block success.

Expected independently observed public metadata for this incident (not embedded acceptance constants): PR4 head e91ff7d2618be24e4c4f851df9414f294ec4a386; merge9a2e59b84290cc0cfecd3bc4033c94efb903b77b; event35857562279; owner review5867148142; offline check130879852465 from App15368. Six live unauthenticated metadata reads validated these bindings during preparation. That public crosscheck does not verify the owner VM's local receipt; the owner command above must do so. The original trial and failed observation's revoked tokens are not reused.

A successful report records `A14=OWNER_ATTESTED_HUMAN_UI_AND_GITHUB_MERGE_OBSERVED`, `original_evidence_unchanged=true`, `new_tokens_issued=false`, `trial_repeated=false` and `independent_admission_verified=false`. Share only the sanitized report or its public PR link and selected hashes. No original key/token/process-memory contents are needed. A13 stays UNVERIFIED, production is untouched, and issue28 remains open until independent policy ownership/admission/freshness enforcement is proven.

Rollback: stop using the side-by-side recovery command. There is no deployed code/service/configuration replacement to reverse, and no token to revoke from this recovery. Preserve all original and appended reports. Do not delete/reset evidence or weaken existing protections.

References: [GitHub pull-request API](https://docs.github.com/en/rest/pulls/pulls#get-a-pull-request), [GitHub timeline API](https://docs.github.com/en/rest/issues/timeline#list-timeline-events-for-an-issue), [GitHub commit comparison](https://docs.github.com/en/rest/commits/commits#compare-two-commits).
