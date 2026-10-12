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
