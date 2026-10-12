# Hufu Pilot integration team

This team retains the runtime-enforced PREPARE → AUDIT → EXECUTE → VERIFY
pipeline. The Execute adapter is the sole mutation owner, including resource
monitoring and stopping its disposable VMs after a resource-policy stop.

## Resource stop contract

`resource-policy.json` defines the typed limits. `HUFU_RESOURCE_POLICY` may
provide a JSON object with explicitly named overrides. Unknown or duplicate
fields, invalid types, non-finite values and out-of-range limits fail before
campaign execution. The launcher validates this contract before creating state.
The effective policy is pinned in checkpoint `facts/resource-policy.json`;
changing it on resume fails closed.

The default sampling interval is 15 seconds. Guest samples come from live
`/proc/meminfo`, memory PSI, the OOM counter and boot identity through Pilot's
read-only VM exec path. A stale libvirt balloon sample is marked stale, and QEMU
RSS is never interpreted as guest available memory. Missing probes remain
unknown. Eight consecutive missing guest observations stop execution.

A newly observed OOM kill stops immediately. Three consecutive fresh samples
below 512 MiB host / 128 MiB guest availability, or at least 30% full memory PSI
avg60, stop the workflow. At startup a host below these limits refuses to start
any mutation. KiB and MiB conversions use factors of 1024.

On a resource stop the guard first terminates its workflow child, saves resource
samples and a `receipts/resource-stop.json` non-success record, and stops only
`nexus`, `client-vm`, and `freeipa-server` when the configured stop option is true.
It tries shutdown before bounded destroy; disk images and VM definitions remain.
An unconfirmed shutdown is recorded as unknown. Normal deployment failures keep
VMs available for investigation.

The adapter returns a typed `environment` failure; this does not satisfy
execution or acceptance. No automatic replay, phase bypass, or relaxed
verification is enabled. Resource fixtures exercise stop and unknown-state paths
without provisioning or contacting VMs.

## Progress and evidence contract

Before the Execute child starts, `facts/source-snapshot.json` pins the actual
Pilot executable, Go sources and dependency files, transitive playbooks and
templates, reference documents, team JSON/Python/shell sources, launcher and
helper scripts. The snapshot records SHA-256 digests, modes and the repository
revision. Added, removed or changed files fail the stage boundary and final
verification. The executable hash identifies the binary actually invoked;
it does not assert that an existing binary was built from the captured source.

`logs/stages.jsonl` records stage starts and actual exits with timestamps,
private raw-log references, byte lengths and hashes. Bounded stderr frames
report stages and resource heartbeats to Hufu. These observations never satisfy
acceptance or reset verified progress. The read-only verifier requires the full
pipeline, component coverage and sealed proofs independently.

Ordinary failures, handled cancellation and resource stops create a separate
`receipts/failed-evidence.json` pointer to an immutable failure manifest and
copies of available logs/facts. Resume can append working logs without changing
previous failure evidence. The seal records the last stage and failing command
when available; it excludes argv, stdin and exception text from metadata.
Timeouts and signals terminate owned child groups before recording their exit.
A hard kill can interrupt sealing; durable stage records remain partial evidence
and cannot pass verification.

A success manifest remains `pipeline_complete: false` until all fixed Execute
stages exit successfully and source inventory is rechecked. The supervisor then
seals the final stage ledger, resource samples, source snapshot, execution
receipt, raw logs and component reports. The verifier detects proof tampering
and source drift, including added transitive tasks and binary changes. These
regression fixtures do not provision or contact VMs.
