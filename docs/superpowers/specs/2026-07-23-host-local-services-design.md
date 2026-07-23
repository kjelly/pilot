# Host-local services for portable vm-target environments

## Status

Approved design. Implementation is intentionally not included in this document.

## Goal

Allow a developer to move the repository and the host running `pilot` to another
machine, start a local package/image service stack, and create VM targets that
use that stack from their first boot. The services must not run inside a
disposable `vm-target` VM, and cache/release data must survive VM teardown and
host reboots.

## Scope and non-goals

The first bundle contains apt-cacher-ng, Pulp RPM, and Harbor. `pilot` manages
their host-side Docker Compose lifecycle and persistent data; it does not
install or configure them inside a VM. Pulp uses the official OCI single
container layout; Harbor uses its official installer to generate the supported
Compose stack. Podman is not a first-version backend.

The design does not make cache contents portable by themselves. Moving an
existing populated cache requires moving the persistent data directory or
restoring a backup; a new host can always recreate the services and refill the
cache from upstream.

## User-facing lifecycle

```text
pilot services up --profile dev-lite
pilot services status
pilot vm-target up --name dev-vm --services local
pilot services down
pilot services purge --confirm
```

`services up` creates a Compose project below
`~/.local/share/pilot/cache/`, starts the selected profile, and waits for all
health checks. `down` stops containers but retains data. `purge` is the only
explicit destructive operation and requires confirmation.

`vm-target up --services local` requires the service stack to be present and
healthy. It does not silently start a missing stack or bypass it with public
upstreams.

## Host-side architecture

The generated Compose project has separate persistent paths for:

- apt-cacher-ng cache;
- Pulp's official OCI single-container layout: `settings`, `pulp_storage`,
  `pgsql`, `containers`, and `container_build`;
- Harbor registry data, PostgreSQL/Redis data, and Harbor configuration;
- generated CA material, service metadata, profile fingerprint, and health
  state.

The paths are outside the VM overlay/seed directory. Services bind only to an
address reachable from the selected libvirt network, not to every host
interface. The selected profile defines upstream allowlists, repository
snapshot/release policy, image proxy projects, storage limits, and retention
policy. The first `dev-lite` profile may use on-demand package retrieval; a
future reproducible profile promotes verified repository snapshots and image
digests into immutable release locations.

## VM bootstrap and endpoint discovery

`vm-target up` resolves the selected libvirt network's host/gateway address
from libvirt network metadata; it never assumes `192.168.122.1`. It renders a
stable VM-local name such as `cache.pilot.internal` to that address, injects
the generated CA, and writes OS-specific client configuration through
cloud-init:

- Ubuntu APT proxy/repository configuration;
- Alma/RHEL Pulp repository definitions, signing keys, and CA trust;
- Docker Hub mirror and Harbor proxy-project configuration.

Cloud-init performs fail-closed probes for APT/DNF metadata and container
registry access. Failure of endpoint discovery, TLS validation, repository
metadata, or registry access makes provisioning fail; no direct-upstream
fallback is permitted. The generated inventory and target state record the
selected service profile and endpoint fingerprint for diagnostics.

The topology document may set a single `services: local` field at its root,
applying the same profile to every node; per-node overrides are out of scope for
the first version. Nodes remain disposable; the host service data is not part
of topology snapshots or VM rollback.

## Configuration and security

Profiles are declarative and contain endpoints, upstream allowlists, snapshot
references, image proxy mappings, limits, and retention rules. Secrets are
provided through host-side environment/secret files and are not copied into VM
user-data. The generated CA is trusted only by opted-in VM targets. The service
ports are restricted to the libvirt network and host firewall policy.

The implementation must validate profile values before generating Compose or
cloud-init (including URLs, repository names, image references, network names,
and storage paths), use atomic state writes, and redact credentials from CLI
output and evidence.

## Failure and recovery

- Missing Docker Compose, invalid profile, unavailable libvirt gateway, or
  unhealthy service causes a clear error before VM mutation where possible.
- A VM bootstrap failure removes the newly-created VM according to existing
  `vm-target up` cleanup semantics; `--keep-on-failure` remains available for
  investigation.
- `services down` preserves data. Service recreation from the same profile
  reuses the data directory. A changed profile gets a new fingerprint and
  must not be reported as the old verified release.

## Testing and acceptance

The implementation requires:

1. Unit tests for profile validation, persistent path layout, Compose rendering,
   libvirt gateway discovery, endpoint fingerprinting, and fail-closed policy.
2. CLI tests proving `services up/status/down/purge` behavior and that `purge`
   cannot run without confirmation.
3. VM tests proving Ubuntu and Alma/RHEL cloud-init output, CA installation,
   local name resolution, and no-public-upstream fallback.
4. Integration testing on a real disposable VM: start services, create a VM,
   install a package and pull a test image through the local services, reboot
   the VM, recreate the VM, stop/start services, and verify persistent data.
5. Idempotency and failure tests: repeat `services up`, interrupt startup,
   make one endpoint unhealthy, and assert `vm-target up` fails without
   producing a usable target.

The final runbook/spec commands must follow the repository's actual-run and
evidence rules and be executed against the selected host and VM network before
being documented as verified.
