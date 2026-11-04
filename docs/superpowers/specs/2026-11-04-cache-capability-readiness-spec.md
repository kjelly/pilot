# Shared cache capability readiness (#238)

The shared stack has one durable identity and content store. A consuming client
declares a validated set of `apt`, `rpm`, and `oci` requirements. Omission means
all three for backward compatibility; unknown, duplicate, or explicitly empty
sets are errors. Selection is explicit and never inferred from a guest OS.

VM CLI selection is `--service-capabilities`. Topology YAML supports
`service_capabilities` globally and on each node; a node override replaces the
global selection. Preflight checks the union before provisioning, and each node
receives and registers only its own requirements. Direct Manager.Up uses the
same bootstrap validation and registration gate.

Each fresh observation reports initialization, native health, management
authentication, data readiness and UTC observation time per capability.
Observations are separate from the canonical client identity and are not written
by status or client lookup. All capabilities remain visible even when only one
is required. A selected capability requires successful native health and a real
data read; unrelated failure is nonblocking. Management failure is visible but
does not override independently successful data reads. Management, adoption and
credential import retain the established credential gates.

Native health parsing must reject 200/unhealthy, initializing and malformed
bodies, authentication denial, 5xx and transport failures. Pulp requires a connected
database and live workers/content applications; Redis is optional when Pulp caching
is disabled and is not an unconditional readiness requirement. Harbor requires healthy
aggregate status and unique, named healthy components including core/database/registry.
APT requires the native report title (case/whitespace normalized). Management
authentication requires typed current-admin identity or a nonnull Pulp users
array with named users; an authenticated empty users array is valid. Anonymous
registry token readers require an object and string-valued nonnull token fields
on host and guest, and reject malformed/trailing JSON.
Data descriptors in the profile specify an actual APT proxy resource, Pulp
repository metadata/package, or immutable Harbor manifest/blob. Responses must
match a configured SHA-256 or content marker; OCI always requires a digest.
Missing descriptors are unknown and fail closed for selected capabilities.
The compatibility boundary is deliberate: omitted selection still means all,
but legacy/default OCI consumers without a descriptor receive an actionable
`data_probes` diagnostic until configured. Management up/repair/import remains
usable without a consuming OCI descriptor; malformed unrelated descriptors
do not block an independently selected capability. Durable consumer records
store the canonical capability selection.
The built-in profile can derive an APT InRelease and RPM repomd.xml read; an OCI
resource digest must be explicitly supplied because a mutable tag cannot prove
immutable content. Existing profiles without descriptors remain loadable.

Probes use bounded bodies, per-request and overall deadlines, caller
cancellation and no retries or implicit repair. Consumption discovery of an
already registered stack validates ownership, client identity and CA without
requiring management secret readiness. Discovery adoption still validates all
credentials. No endpoint, configuration, secret or cache content is changed by
probes; cache misses may naturally populate the shared cache through native GET.

Acceptance uses HTTP integration tests with independent fixture state and native
services on an owned disposable KVM target. The dependency matrix includes APT
healthy/Harbor management denied, APT unavailable/Harbor usable, management and
data disagreement, required/unrequired failure, missing descriptors, timeouts,
cancellation, malformed and initializing health, readonly state hashes, mixed
topology scopes and guest files. Negative controls replace selection with all
and replace native health validation with status-only acceptance; each must fail
the corresponding behavioral assertion. Actual-run evidence must bind to a clean
candidate revision and record the real inventory and limits.

No apply playbook or services lifecycle mutation is introduced. Fresh/check,
apply/verify/idempotency and failure recovery of the authorized native fixture
belong to the target evidence. Operational stacks and other VMs are outside the
mutation boundary. Cross-OS-user sharing remains unsupported.

Cancellation publication contract: the original caller context is checked after
observations and immediately before successful return/publication. Running-state
and consumer publication use cancellable store lock waits, check again after
callbacks/serialization, and check immediately before atomic rename after temp
file persistence. Already-entered rename is the atomic commit boundary and is
not promised to be interruptible. Canceled status returns partial observations
with `running=false` and the context error, skipping Compose inspection when
already canceled. An internal probe deadline remains a capability failure and
does not cancel unrelated successful requirements.
