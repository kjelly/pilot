# Harbor persistent credential recovery — Issue #237

Test date: 2026-11-04. Tested revision:
`9e2fe255da79850cb40e9f97f093661737fb8493`; tested tree:
`517432db4cffa1975a28e1042a301fb776fc272e`.

## Target and provenance

The binary was built with Go 1.26.8 from a clean, isolated candidate archive,
with VCS stamping disabled. Binary SHA-256:
`4affaec272032b3522ac1882bf1cf27f508e13080d0950e2cf446804f85fc3c0`.
Two independent candidate archive workspaces, separate executable copies and
different VM data directories shared one discovery root.

Native execution used a dedicated disposable Ubuntu 24.04 KVM host. Its actual
inventory contained only `all/i237-harbor-auth-final`. The synthetic service
network was `192.168.237.0/24`. Versions were Docker 29.1.3, Compose 2.40.3,
kernel 6.8.0-124, Harbor 2.15.1 and Pulp 3.85.25. Harbor and Pulp used real
persistent databases and native APIs. A native createrepo HTTPS fixture supplied
RPM metadata with an explicitly trusted test CA; TLS verification stayed enabled.

Twelve official linux/amd64 images were transferred read-only from an existing
cache. Source repository digests were verified, and ordered filesystem layers
plus runtime-configuration fingerprints matched after loading. Image-ID display
differences between Docker stores were not treated as content equivalence.

| Image | Verified official source repository digest |
|---|---|
| Harbor DB 2.15.1 | `sha256:7944d8594a48a8d014e1fa440bc788348f2a779fa2c612ed6b79390cd767e6db` |
| Harbor core 2.15.1 | `sha256:887a85b8ea98b76bfc9f715f1a0785bb99f9a1034241513902dd6e95be922a83` |
| Harbor registry 2.15.1 | `sha256:ebf0325c2661729dbb317cbf839608eb8b15cfa158911a94976f2c21563c466e` |
| Pulp 3.85.25 | `sha256:19190f04021c9e5ae36dcec04383f9325e61e3717656621b38ef08a583acd58e` |
| Cached BusyBox 1.37 manifest | `sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` |

This is a native Go lifecycle feature; it introduces no Ansible apply playbook.
Private credential bindings, passwords and per-run artifacts are excluded from
this self-contained sanitized summary.

## Observed acceptance results

| Boundary | Actual result |
|---|---|
| Initial seed failure | A stopped synthetic RPM origin caused a real Pulp task failure. Missing admin credentials blocked repair without regeneration. Authorized reassociation and explicit repair completed with the original DB credential, CA, instance and generation retained. |
| Shared healthy reuse | Two processes in separate candidate workspaces/data directories retained all 11 container IDs/start times. Bundle, discovery, credential, CA and private-binding bytes/mtimes stayed unchanged. |
| Missing/wrong admin and DB secrets | Up, JSON status and repair refused. Invalid imports preserved missing/old associations. Valid imports and repeat imports authenticated without service recreation or service-state changes. |
| Entire Harbor secrets directory lost | Database and admin associations were independently restored from restricted authorized files; ordinary up then succeeded. |
| SIGKILL before publication | The observed durable intent preceded the secret rename; exit -9 retained the prior association. Retry authenticated and completed. |
| SIGKILL after publication | The validated candidate was present before exit -9; retry authenticated and completed the private binding/audit. |
| SIGTERM during temporary-file fsync | The real CLI returned failure, retained old bytes, removed its new temporary file and supported a successful retry. |
| External admin change | A synthetic fixture changed the native admin password. Ordinary up rejected the old association; explicit import authenticated the replacement before publication. |
| Cache preservation | All seven baseline committed blobs retained their paths and SHA-256 contents. Every current blob matched its content address. Removing the local client image and pulling through Harbor again returned the identical manifest digest. |
| Stopped maintenance | Wrong local credentials were refused before activation. Down followed by repair with the valid imported association succeeded; native API authentication, cache, instance and generation were retained. |
| Secret safety and permissions | A final audit scanned 67 output/trace/JSON/audit files, including 56 logs: 0 secret matches. Harbor secret files/private binding were mode 0600; the secrets directory was mode 0700. |

Fresh initialization and the complete recovery/maintenance verification stages
passed. The successful stopped-maintenance repair took 171.354 seconds. Required
failures, signal exits and retries remain separate observations rather than
being counted as successful commands.

## Failure paths and verification corrections

Independent review reproduced publication after SIGTERM during temporary-file
persistence. The corrected helper rechecks cancellation immediately before
entering rename. Local and native signal tests verify old-byte retention,
temporary-file cleanup and retry. An entered rename syscall is the documented
irreversible commit window.

Native calibration showed official Harbor DB loopback TCP accepts arbitrary
passwords. The first probe correctly rejected that negative control. The final
shared probe uses the container hostname: wrong-password authentication fails,
correct credentials return the expected query result, and the mandatory
negative control remains enabled. Active HBA and native stderr informed the
regression, whose parent counterexample fails for that specific boundary.

An outdated downstream VM-consumer fixture initially failed the new live-auth
contract. Its test-only correction supplies independent credential authority,
authenticated identity responses and strict read-only Docker/stdin shims for
every reconstructed manager. Wrong credentials prevent registration and domain
creation; removing identity responses or accepting all passwords fails the
intended gate. All selected importer, services and CLI cases then passed.

Initial Harbor startup returned a readiness failure after 125.934 seconds; its
original containers later became healthy. Explicit repair then reached the
intentional upstream seed failure; after reassociation and restoring the fixture
origin, completion repair succeeded in 109.481 seconds. The baseline startup
path can require an explicit retry; deterministic first-attempt startup is not
claimed. Independent BASE/HEAD review found no demonstrated causal aggravation.

The first cache-set equality check observed growth from four to five committed
blobs: one addition, no removal and no modified hash. Its cause was not
established. Requiring an identical complete set was overstrict for preservation.
The corrected verification requires every baseline path/hash to remain, validates
all current content addresses and requires the re-pulled manifest digest to
match. It permits additions while rejecting loss or corruption.

Incomplete-startup teardown can also retain Harbor containers before its Compose
path is published; independent review confirmed that limitation on the base.
Earlier fixture cleanup exposed it and the missing-secret guard refused the
resulting state. The final candidate ran on a new dedicated VM with zero existing
containers and an empty synthetic service data directory.

## Limits and cleanup

The supported boundary is one OS user across processes/workspaces/VM data
directories. Cross-UID sharing, product password reset/rotation, general database
corruption diagnosis, full RPM payload delivery and upstream-offline/cache-hit
accounting were not established by this run. Unverified services fail closed;
generic server failures do not prove corruption.

All mutations targeted the dedicated synthetic VM. Existing operational cache,
VMs, credentials and user data were not targeted. The dedicated VM and overlay
were removed after artifact capture and cleanup was verified.
