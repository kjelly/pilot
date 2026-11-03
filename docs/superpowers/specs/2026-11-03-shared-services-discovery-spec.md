# Shared host services discovery (#235)

## Intent and scope

Host cache services belong to the operating-system user, independently of a
checkout, inventory workspace, VM target state directory, or disposable VM.
Native Go orchestration owns this contract; no Ansible apply playbook is involved.
Fast-path reconciliation, consumer leases, maintenance, authentication repair,
additional health capabilities, and general cache-hit suites belong to follow-ups.

## Acceptance contract

| ID | Observable acceptance | Oracle |
|---|---|---|
| S1 | Two checkouts using different VM data directories discover the same default stack, instance ID, generation, endpoints and CA. | Separate CLI processes; compare status and nonsecret VM bootstrap contracts. |
| S2 | Service discovery precedence is explicit services directory, service environment override, service config value, then the OS-user default. General data-directory overrides do not select a new stack. | Resolver integration tests with conflicting values. |
| S3 | A compatible legacy stack is registered in place. Existing database/cache mounts, CA, private keys and credentials remain at their original paths and retain their bytes. VM state is untouched. | Actual mounted paths plus before/after hashes and cache/database usability. |
| S4 | Interrupted initialization/adoption retries retain identity and data. Simultaneous processes cannot create different identities, overwrite credentials, or mutate one physical stack concurrently. | Independent subprocesses, crash/retry and canonical/symlink path aliases. |
| S5 | Conflicting legacy roots, discovery ownership, profile fingerprints or bind endpoints fail before rendering or Compose mutation. Corrupt or missing state beside persistent data fails closed. | Specific errors, unchanged artifact hashes and zero runner calls. |
| S6 | Up, status, down, purge and VM/topology bootstrap use the same discovery resolver. Down retains data; confirmed purge removes only the registered service bundle. | CLI wiring, manager lifecycle tests, isolated real-stack lifecycle. |
| S7 | Default discovery creates one shared stack. An explicit services-directory override isolates the scope and does not automatically adopt the user's unrelated default legacy stack. | Two-process default test and isolated override counterexample. |

## Discovery and migration design

The default discovery directory is `~/.local/share/pilot-services`, independent
of `data_dir`. Overrides are `--services-dir`, `PILOT_SERVICES_DIR` and
`services_dir` in the existing pilot configuration file, in that order.
`--services-adopt-from` identifies an arbitrary old pilot data directory explicitly.
Without a services-directory override, bounded migration candidates are the old
default pilot directory, the current general data directory and the configured
general data directory. There is no filesystem-wide search. With an override,
only an explicit adoption source is considered.

Versioned, atomically persisted discovery state registers the actual canonical
cache root and a stable nonsecret instance ID and generation. Adoption registers
existing paths; it does not move or duplicate cache data or host credentials.
Operation locks cover discovery/registration and the full physical-root
probe/mutate/state transaction. Canonical paths prevent symlink aliases from
creating independent ownership. A persisted physical-root owner rejects a second
discovery registry trying to manage the same bundle.

The legacy state is input to migration; the registered discovery state becomes
authoritative. Old pilot binaries that do not implement discovery must not manage
an adopted stack concurrently. Missing/corrupt discovery or legacy state beside
existing persistent data requires operator diagnosis rather than fresh secrets.

## Validation boundary and delivery evidence

Target validation is required: a frozen clean candidate must run against a
uniquely named isolated Docker stack, with a bounded synthetic home/discovery
scope. Existing user-owned resources are outside mutation authority.
Separate checkouts/processes must prove reuse, in-place migration, conflict
rejection, data retention and lifecycle behavior. Focused Go tests cover config,
resolver, physical locks and VM/bootstrap propagation. Real-run evidence records
candidate/tree, actual mounts, fingerprints, commands, results and limitations in
`docs/evidence/shared-services-discovery/issue-235.md`; unexecuted operational
commands are not published in runbooks or verification specs.
