# External devices no longer disable inventory-scoped webhook snapshots

- Tested candidate: `4baffb83c2dcbc541b18af51c8d102ea5cadc901`.
- Tested tree: `214a5554ea5f28d302fee137d31e2c117066faf8`.
- Formal verification: 2026-10-16, 06:41:06–06:42:31 UTC, Codex.
- Candidate was built and tested from a clean, detached checkout with Go 1.26.8,
  `CGO_ENABLED=0`, Linux/amd64.
- Binary SHA-256: `2c410fb9353d6186fc90f2c447924f8302f75c8ec3dca27aebfb5f6db1bb3eeb`.
- Container base image ID: `sha256:45159672220dfed33f2c7ee0ef3e0458a51b2758c14f9f7e1b3b7ef9383dd39d`.

## Acceptance and target

The previous C22 contract required every present roster host to match an
inventory address, so adding an external NFS appliance disabled publication
of otherwise valid users, groups, hosts, and access. C22 now explicitly limits
host entities and host references to inventory scope. Declared external devices
are excluded, external-only access rules are omitted, and nonexistent/absent
roster references or ambiguous inventory address matches still fail closed.

The actual target was the operator's existing control-node container image,
with the current workspace and history database mounted read-only. Inventory
facts were read with the actual `ansible-inventory --graph` pipeline (exit 0).
The inventory contains 26 managed hosts; the canonical roster also contains
one external NFS appliance with no inventory address match. Alignment decision:
correct the projection contract rather than introduce Ansible management of
the appliance. The observed inventory graph fingerprint was
`93ffed7961c5e60d468057fba3ddc282b95b696b08b5b7a3b86e2ae85e04badf`.

## Results

| Check | Actual result |
|---|---|
| Regression sensitivity before implementation | External-device and external-target cases failed against the old resolver |
| Formal webhook/CLI test selection | 150 passing test/subtest results; 0 failures, 0 skips |
| Spec regression and shell syntax | 6 passing results; 0 failures, 0 skips |
| Spec lint | 30 rows, 0 findings, 0 errors |
| Development run of complete outbound and CLI packages | 1615 passing test/subtest results, exit 0 |
| Existing binary with current external-NAS roster | HTTP 204; `available=false`, `source_complete=false`, `projection_unavailable`, no snapshot |
| Candidate binary with the same workspace and roster | HTTP 204; `available=true`, `source_complete=true`, full snapshot: 26 hosts, 118 users, 38 groups, 12 hostgroups |
| Candidate repeated with unchanged sources | Same complete snapshot and identical snapshot ID |
| Candidate with a temporary dangling hostgroup reference | HTTP 204 terminal metadata; `available=false`, `projection_unavailable`, no snapshot |
| Source/configuration/history preservation | Source fingerprints identical before and after all container probes |

Container probes invoked the real `pilot webhook send-test` command and real
Ansible inventory resolution. Only the candidate binary was mounted into the
existing image. Every HTTP request went to a loopback receiver inside the
disposable container, using a synthetic bearer credential. The external
consumer and durable outbox were untouched. As designed, `send-test` events
are synthetic and non-authoritative; the projection/envelope regression also
verified that a real successful workflow can retain authoritative, complete
snapshot publication with an external device present.

The targeted tests cover direct and nested hostgroup targets, static HBAC,
static sudo, temporary grants, sudo grants, and active breakglass grants.
Mixed target rules retain only managed hosts. External-only rules disappear
without becoming all-host rules; withdrawing the final managed target produces
access deletions while preserving users and managed hosts.

No apply playbook changed, so Ansible apply/rollback/idempotency steps were not
part of this projection-only verification. The repeated projection and stable
snapshot ID establish deterministic publication. The existing deployed image
tag was not replaced.

## Execution-affecting file hashes

| File | SHA-256 |
|---|---|
| `internal/outbound/projection.go` | `dcd3e7c113c74824edcc250475f93651b85adbc3da0b662d99be2d2f9a222ac2` |
| `internal/outbound/projection_external_hosts_test.go` | `a5ba998a8df61225b5c26c88cf66e34616312a155ebf901f1222a5caf82599c6` |
| `internal/outbound/projection_test.go` | `d3efc681774c403031cf95829ce3e089c1f2e444eb83190a3fd4616f63e038e2` |
| `docs/verification/outbound-webhook.md` at candidate | `d9c8cda447902f54463312efc8d3b520cecd94a7c60ae21f94f91f0efe426f59` |
| `docs/superpowers/specs/2026-09-15-outbound-state-webhook-spec.md` | `66385d8dee24625c2e53208bb49dc68a7d4b3f21e37e8ed0c84791b91accc240` |

Publication redactions: host/user/group identities, IP addresses, private
endpoint URLs, operational directory names, and all credential values. Counts,
verdicts, candidate/tree, image/binary identities, and fingerprints are retained.
