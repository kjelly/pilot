# Issue 235: native validation blocked during legacy fixture setup

Outcome: **BLOCKED — no native migration acceptance and no PR quality-gate pass.**
Recorded 2026-11-03 UTC. No success `LATEST.md` is published.

## Revisions and scope

| Input | Immutable identity |
|---|---|
| Implementation candidate | `96f057dca9fffe25a0089e0a061549612228ed2e` |
| Candidate tree | `61c3701b335d501ac3d853ab8d207252ea64798e` |
| Legacy fixture source | `613c36162bc5cfbeac929c5b4224ec9689a54f3b` |
| Candidate binary SHA-256 | `6065af7aa21ef41c0ad6208ea998823b4b4149621496349986859641568ae928` |
| BASE binary SHA-256 | `f20268f6734dfe6a85a30778a335593e9bb54091bc48f1178a00d59b3faa2f18` |
| Disposable Ubuntu cloud image SHA-256 | `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94` |
| Synthetic profile SHA-256 | `1767d6583cea0741e8d6ac719cea147d762f0c8528a2c0468725309b78d33946` |
| Final fixture scheduling script SHA-256 | `34f948b85a20df6961e44953c2f93f353bc9606abe7c06f3eaff62abd5dc8612` |

Source was extracted with Git archive. The candidate binary was built from its
isolated archive with build VCS stamping disabled; two archive directories and
identical binaries were copied into the disposable VM. **Neither archive ran the
candidate migration:** establishing a valid legacy source failed first. The BASE
binary was built from a BASE archive nested below the checkout; its embedded VCS
metadata reports the enclosing checkout as dirty and is not evidence of a clean
VCS stamp. Archive provenance and the exact binary hash identify that fixture.

The dedicated Ubuntu 24.04 VM, its network, Docker projects and credentials were
created for this attempt. Its actual generated inventory contained one host,
`i235-cache-host-1103`, connecting as root. Native services ran inside that VM on
its own libvirt gateway. No existing user stack was adopted, stopped or modified.
This is native Docker/Compose fixture execution, not an Ansible apply/verify or
fresh guest package-install acceptance chain.

## Observed results

| Check | Result and boundary |
|---|---|
| Candidate services/config regression receipt | PASS, clean candidate SHA; subprocess discovery, migration and lock tests execute. |
| Candidate CLI regression receipt | PASS, service resolver/flags and direct VM bootstrap consumers. |
| Candidate importer package receipt | PASS, command entrypoints, agentcontroller, repair, tools and vmtarget. |
| Candidate static analysis and whitespace receipts | PASS. |
| Independent review | No unresolved P0–P2 code findings at the candidate. The stale-migration-authority finding was fixed and independently retested. Final approval remains blocked on native evidence. |
| Initial host fixture | FAIL before baseline publication: the official Harbor log mapping collided with an existing loopback port. Only this attempt's projects were removed; validation moved into the disposable VM. |
| Native VM BASE startup | FAIL: Compose reported Harbor jobservice unhealthy before successful state publication. The service later became healthy. |
| Ordinary BASE retry | FAIL: Harbor registry seeding returned HTTP 401; independent authenticated API requests also returned 401. |
| Fixture-only Harbor database recreation | First core log records schema creation and initial admin-password initialization; a direct native admin API request returned HTTP 200. No candidate migration had run. |
| BASE retry after recreation | FAIL: normal BASE prepare/reconciliation again reached Harbor seeding HTTP 401. The persisted secret matched rendered config and container environment; equality does not prove database credential equality or establish the cause. |
| One bounded startup timing experiment | FAIL, BASE exit 1: only the disposable jobservice was paused until core health and native admin authentication, then resumed. Native Compose still reported jobservice unhealthy. No state was fabricated and no image/configuration was patched. |
| Later container health | All eleven fixture containers eventually reported healthy. This does not replace successful BASE state publication or prove cache content/authentication preservation. |
| Candidate adoption, dual-process runtime identity, content retention, conflicts and down/up/purge | NOT RUN; no valid normally published legacy source was available. Prepared scripts are not acceptance evidence. |

Focused local checks are recorded under `/tmp/issue235-state/`, bound to the
candidate with clean-before/after and unchanged-HEAD receipts. The reviewer
separately executed 34 services, 3 config, 12 command and 2 VM bootstrap top-level
tests, with 11 nested cases and no skips. Topology service consumption was traced
to the executed direct-bootstrap path; no topology-specific native run is claimed.

## Native tooling and image fingerprints

The disposable guest used Docker 29.1.3 and Compose
2.40.3+ds1-0ubuntu1~24.04.1. Public images were transferred from the host's existing
image cache. These are immutable local image IDs, not a claim that upstream
manifest provenance was independently revalidated.

| Image | Local image ID SHA-256 |
|---|---|
| Pulp 3.85.25 | `fdda85e59606224b2211219c84e83b30e0609cc861d9ffb0d4f8b5767499a90f` |
| apt-cacher-ng 3.7.4-20220421 | `a2df7c66da9f529214343b7aa571ea52142eb1fb04ffd50c541bf65220b6a4b8` |
| Harbor prepare v2.15.1 | `99532c375af37d8153fe6644945d52fb2317687e268b0895b5fce91d1e6d4d62` |
| Harbor core v2.15.1 | `7ad3c287d9c9d3eddf0060fae583f25c83fb48e300373323ffee0fa91e3f2921` |
| Harbor DB v2.15.1 | `6e60aa1d05f7dccbeb7bc915189c2a08595669173aac649360bc3d99a2cdf07a` |
| Harbor jobservice v2.15.1 | `960cbf4860fa30b1afb80351c19b25289ce5c8340179e7b9b585f312b87bef89` |

## Failure paths and arms

The normal BASE retry and the fixture-only database recreation/timing control
are setup arms, not successful migration or authentication-repair validation.
The first unhealthy result, later 401 results, first-core initialization log and
final timing failure remain in the ignored local artifact directory
`tmp/issue235-validation/logs/`. Its parent artifact directory retains source
archives and external fixture scripts; the actual inventory is in the logs. Full operational logs,
credential values, environment payloads and database data are not committed here.

Individual local artifacts, relative to that logs directory:

- `guest-base-up.log`: initial native Compose jobservice failure.
- `guest-base-up-retry.log` and `guest-base-healthy.log`: BASE seeding HTTP 401.
- `guest-core-first-reinit.log`: initial schema and admin-password initialization.
- `guest-establish-final.log` and `guest-establish-base.log`: scheduling fixture
  assertion and the underlying BASE jobservice failure.
- `guest-final-facts.log`: native tooling, image IDs and later container health.
- `inventory.yaml`: actual generated target inventory.

Standalone API status and secret/config/environment equality checks were operator
observations in the session's tool results; their stdout was not separately saved
in those artifacts. They are not durable authentication or credential-integrity
proof. The final scheduling script and its failure trace support that arm's
transient admin-authentication assertions, not successful baseline publication.

The failure class overlaps the separately tracked [Harbor authentication work
#237](https://github.com/kjelly/pilot/issues/237), but this record does not identify
the initial mismatch cause or establish that #237's proposed repair would resolve
the fixture. The startup health failure is also retained independently of 401.

## Not covered / limits

All native migration acceptance remains outstanding: one healthy published
legacy baseline; interrupted adoption/retry; two real checkout processes with
different VM directories sharing identity, generation, endpoints and CA; native
content and management-authentication preservation; conflict rejection before
render/Compose; and ordinary lifecycle retention/purge boundaries. The candidate
has no GitHub PR or CI result. It must not be represented as ready for review.

The pre-existing first-bootstrap two-file CA interruption limitation is separate
from migration and was not repaired. Cross-user sharing, maintenance leases,
health fast paths and cache-hit/upstream-byte measurements remain outside #235.
This summary contains synthetic fixture identifiers and fingerprints only; it
omits credentials and identifiers of unrelated resources.

The dedicated VM/network and failed host-side fixture containers were removed.
Their disposable database/cache and VM image files were cleaned up; failure logs,
source archives, external fixtures and local check receipts remain available.
