# Shared cache lifecycle — Issue #236

Test date: 2026-11-03. Tested revision:
`2ddb5a513e5acb2b7600c4b6f48990cbf5ae5af2`; tested tree:
`093be26e9d7f5ea93d6e6d2bf406142ef824315e`.

## Target and provenance

The candidate binary was built from a clean `git archive` outside the writer
checkout. Its SHA-256 is
`1ece5889379c87b6dc2aaa153ea78653c2f346ba01e350f7ede493b69658e609`.
Native tests ran on a dedicated disposable Ubuntu 24.04 KVM host, with Docker
29.1.3, Compose 2.40.3, libvirt 10.0.0 and QEMU 8.2.2. Two nested Ubuntu guests
used the host's actual default network gateway, `192.168.123.1`.
Generated inventories were captured before guest checks. This synthetic network,
credentials and Docker data were isolated from the existing host cache and VMs.

Raw stdout, exit codes and results are retained locally under
`.git/issue-to-pr-236/`; local check receipts and negative controls are under
`/var/tmp/issue236-coder-evidence/`. Published machine results and harnesses
accompany this summary; they contain synthetic identities only.
Changed-source and harness fingerprints are in [provenance.json](provenance.json);
official container content IDs are in [image-identities.txt](image-identities.txt).

## Observations

- Concurrent healthy attach from independent processes and VM data directories
  retained all 11 container IDs and StartedAt values. State, configuration, CA
  and credential bytes and mtimes were unchanged.
- Durable registrations survived provisioning-command exit. With two real guests,
  ordinary down, purge and repair all failed before mutation. Teardown removed
  only its own registration; the remaining guest fetched cache metadata.
- All 54 continuous actual APT-cache metadata requests succeeded during attach and guest
  teardown. The final harness checks the surviving guest's response SHA and
  compares all container identities after both guest teardowns.
- A native lock waiter canceled on SIGTERM. Killing a distinct lock holder
  released its kernel lock and the next attach succeeded.
- Pausing Pulp caused ordinary attach to fail with a repair-required diagnostic;
  Pulp remained paused until the harness explicitly unpaused it. With no consumers,
  explicit down followed by repair succeeded and the cache served metadata again.
- Final SHA-bound local checks passed: services/vmtarget race tests (160 passing
  cases/subcases), relevant CLI tests (18 passing cases/subcases), build, vet and
  golangci-lint. These two test logs contain zero skipped cases. Independent
  real-binary signal tests cover SIGTERM/SIGINT for services wait and remote exec.
- Negative controls fail for the intended invariants when healthy attach rewrites
  root ownership, maintenance ignores consumers, or global signal interception
  swallows the first termination signal.

## Failure paths encountered

The exploratory earlier candidate `a41c811` first hit a transient Harbor jobservice
readiness failure; the waiting ordinary attach correctly refused incomplete state.
A subsequent explicit repair hit a Pulp HTTP polling timeout while importing real
upstream metadata under host resource pressure. Both failures were retained as
failures. Explicit repair later completed successfully. These exploratory runs
are not substituted for the final candidate's native results.

The reviewer found an introduced global signal-interception regression in that
earlier candidate. The final candidate scopes interception to context-aware
services handlers; an independent subprocess counterexample confirms closure.

## Limits

This validates same-UID host cache management and durable VM consumers, including
real Docker and nested KVM. It does not establish cross-UID coordination, a general
profile migration engine, or authentication recovery beyond existing seed logic.
Legacy unregistered guests require explicit maintenance acknowledgement; abandoned
registrations remain protective until verified teardown or exact scoped release.
No existing operational cache, VM, identity or credential was mutated.
Both nested guests, the synthetic cache data and the outer test VM were removed
after evidence capture; cleanup output remains with the raw local artifacts.
