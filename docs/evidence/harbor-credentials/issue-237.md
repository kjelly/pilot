# Harbor persistent credential recovery — Issue #237

Test date: 2026-11-04. Tested revision:
`4c75f08955be097b26ea76f9a4a62ad6d2099ee5`; tested tree:
`d88425e14dced6a3433b0433d8b6267524bc2eb8`.

## Target and provenance

The native binary was built from a clean, isolated candidate archive, outside
the writer checkout, with Go 1.26.8 and VCS stamping disabled. Binary SHA-256:
`9cbd776d33e5e632f14aaf267fb0acf00a7fb4607c1161a26c2c4e21425b747a`.
The same binary ran from two independent candidate archive workspaces and
different VM data directories against one shared discovery root.

The dedicated disposable Ubuntu 24.04 KVM host used Docker 29.1.3, Compose
2.40.3 and kernel 6.8.0-124. Its generated inventory contained only
`all/i237-harbor-auth`; the synthetic service network was `192.168.237.0/24`.
Harbor 2.15.1 and Pulp 3.85.25 used real persistent databases and native APIs.
A small, native createrepo HTTPS origin supplied RPM metadata. Its dedicated
test CA was installed on the disposable Pulp remote through the native API;
TLS verification remained enabled. Actual Docker Hub proxy-cache blobs supplied
the cache-retention oracle.

Selected immutable image identities:

| Image | Repository digest |
|---|---|
| Harbor DB 2.15.1 | `sha256:7944d8594a48a8d014e1fa440bc788348f2a779fa2c612ed6b79390cd767e6db` |
| Harbor core 2.15.1 | `sha256:887a85b8ea98b76bfc9f715f1a0785bb99f9a1034241513902dd6e95be922a83` |
| Harbor registry 2.15.1 | `sha256:ebf0325c2661729dbb317cbf839608eb8b15cfa158911a94976f2c21563c466e` |
| Pulp 3.85.25 | `sha256:19190f04021c9e5ae36dcec04383f9325e61e3717656621b38ef08a583acd58e` |
| Cached BusyBox 1.37 | `sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec` |

Private raw stdout/stderr, result JSON, signal traces, all 13 image identities,
candidate/source fingerprints and independent reviews are retained under the
task artifact directory `/tmp/issue-237-state/` and the isolated build cache.
Private credential bindings and secret files are excluded from publication.
This native Go lifecycle feature introduces no Ansible apply playbook.

## Observed acceptance results

| Boundary | Actual result |
|---|---|
| Initial seed failure | An intentionally stopped RPM origin caused a real Pulp task failure. Missing Harbor admin credentials then blocked repair without regeneration; authorized reassociation and explicit repair completed with the original DB credential, CA, instance and generation retained. |
| Shared healthy reuse | Two processes in separate candidate workspaces/data directories reused all 11 container IDs and start times. Bundle, discovery, credential, CA and private-binding bytes/mtimes were unchanged. |
| Missing/wrong credentials | Admin and database variants rejected up, JSON status and repair. Invalid imports preserved the missing/old association. Valid imports and repeat imports authenticated successfully without container recreation or service-state changes. |
| Entire Harbor secrets directory lost | Database and admin associations were independently restored from authorized restricted files. Ordinary startup succeeded after the complete set was restored. |
| SIGKILL before publication | The observed durable intent preceded the secret rename; termination retained the prior association. Retry authenticated and completed. |
| SIGKILL after publication | The validated candidate was present before termination; retry authenticated and completed the private binding/audit. |
| SIGTERM during temporary-file fsync | The real CLI returned failure, retained old bytes, removed its new temporary file and supported a successful retry. |
| External admin change | A synthetic fixture changed the native Harbor admin password. Ordinary startup rejected the old association; explicit import authenticated the replacement before publishing. |
| Cache preservation | Six committed content-addressed blobs retained exactly the same paths and SHA-256 contents through all reassociations and interruptions. Removing the local client image and pulling it again through Harbor succeeded. |
| Stopped maintenance | Wrong local credentials were refused before activation. A later explicit repair retry completed; native admin authentication, cache, CA, instance and generation were retained. Subsequent ordinary up was idempotent. |
| Secret safety | 65 output/trace/JSON/audit files were scanned against native and synthetic credential values: 0 matches. Harbor secret files/private binding were mode 0600 and the Harbor secrets directory was mode 0700. |

## Failure paths and corrections

Independent review found cancellation during temporary-file persistence could
publish despite SIGTERM. The exact-binary counterexample failed before the fix;
the corrected candidate checks cancellation immediately before invoking rename.
Both local and native signal traces prove old association retention and retry.
The entered rename syscall remains the documented irreversible commit window.

Native calibration found the official Harbor DB accepts arbitrary passwords on
loopback TCP. The initial candidate correctly rejected its negative control,
making normal operations unavailable. The final shared probe uses the container
hostname: native wrong-password authentication fails, correct credentials return
the expected query result, and the mandatory negative control remains enabled.
The active native HBA and actual stderr were captured; the regression's parent
counterexample fails for this specific authentication boundary.

Initial Harbor startup and the first stopped-maintenance repair returned bounded
readiness failures; the original containers subsequently became healthy. The
failed maintenance attempt took 219.39 seconds. An explicit retry completed in
103.983 seconds and passed the final API, retention, permission and secrecy checks.
Independent BASE/HEAD review traced the terminal readiness error to the existing
startup/recovery path; no causal aggravation was established. Deterministic
first-attempt startup is not claimed.

An incomplete-startup cleanup also retained Harbor containers whose Compose path
had never been published. This behavior exists on the base revision. The next
attempt correctly refused missing credentials. Only the dedicated fixture's
verified container names and instance were reset; the final initialization run
started with zero containers and an empty synthetic data directory.

The first proxy blob-set comparison failed before before/after sets were saved;
its cause remains unproven. The final run first required three stable snapshots
of committed content-addressed blobs, saved baseline/current hashes and retained
strict equality checks. No product assertion was weakened to accept missing or
modified cached content. An initial HTTP-origin fixture was also rejected before
service creation and corrected to the HTTPS fixture described above.

## Limits and cleanup

This validates same-UID credential reassociation and the exercised failure paths.
Cross-UID sharing, password resets/rotation as a product feature, general database
corruption diagnosis, full RPM payload delivery and upstream-offline/cache-hit
accounting are outside this run. Unreachable or unverified services fail closed;
generic server failures do not establish corruption.

All mutations targeted the dedicated synthetic VM. No existing operational
cache, VM, credential or user data was an authorized mutation target. The test
VM and its overlay were removed after artifact capture; cleanup was recorded.
