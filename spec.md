Pilot Optional-Host Deployment Availability Specification

Repository: kjelly/pilot
Target branch: main
Document purpose: implementation specification for a coding agent
Status: Proposed
Date: 2026-08-21

1. Executive summary

Pilot must support environments where many managed VMs are powered on and off by external personnel outside Pilot's control.

A VM being intentionally powered off must not cause pilot deploy or pilot reconcile to fail when that host is explicitly declared as allowed to be unavailable.

Pilot MUST NOT manage VM power state. It MUST NOT add pilot host start, pilot host stop, libvirt power management, Proxmox power management, or equivalent lifecycle commands as part of this work.

The required architecture is:

Keep the complete desired topology in the canonical inventory at all times.

Add a per-host deployment availability policy:

required

optional

Before remote Ansible execution, Pilot calculates an effective execution scope.

required hosts that are unavailable block deployment before mutation.

optional hosts that are unavailable are deferred and excluded from the effective Ansible --limit.

Pilot still validates the full inventory statically, including offline optional hosts.

Pilot must also tolerate the race where an optional host becomes transport-unreachable after the initial availability probe but while Ansible is running.

Only transport-style UNREACHABLE results on optional hosts may be downgraded to "deferred". Normal task failures, authentication failures, host-key failures, malformed inventory, controller errors, and unreachable required hosts remain fatal.

Contract/provider dependencies must be considered before mutation so Pilot does not attempt a consumer deployment that is guaranteed to fail because a required provider endpoint is unavailable.

The canonical inventory MUST NOT be rewritten to contain only online hosts.

This feature is an execution-scope layer above the desired inventory. It is not a power-management subsystem and it is not an Ansible ignore_unreachable workaround.

2. Repository baseline and current behavior

The implementation must start by re-reading the current main branch before editing. The following observations were verified against main while this specification was prepared.

Relevant current files include:

internal/inventory/inventory.go

simplified hosts.yml model

Host

Parse

Lint

Generate

current inspected blob SHA: 7d9c36f522e3f6595279c0b417ee119444b7acc6

hosts.example.yml

canonical simplified-host example

current inspected blob SHA: e0f6158b5a20749dc897cb73a05617f177438283

cmd/pilot/cmd/deploy.go

deploy wizard

inventory resolution

runPreflight

resolvePatternHosts

resolveInventoryVariables

site and component deployment funnels

current inspected blob SHA: fd34e6b289bd107c2bf65defb7e02387238829b7

playbooks/preflight.yml

static validation play

remote ansible.builtin.ping play

current inspected blob SHA: 0b805dc447d90ad1cc295dd758c0d1c450d35517

playbooks/site.yml

aggregate site entry point

imports preflight.yml

explicitly recommends --limit for host restriction

has a localhost safety play that must not be accidentally excluded

current inspected blob SHA: 33fda1c30d406af3ce18760a9ee41418a200f53f

internal/delivery/component_plan.go

contract dependency planning

internal/delivery/preflight.go

contract-aware preflight logic

internal/delivery/transaction.go

deployment transaction/rollback semantics

cmd/pilot/cmd/ansible_json_result.go

existing structured Ansible per-host stats model:

Failures

Unreachable

other recap fields

current inspected blob SHA: c58842e3756963e6597a54ecf6d1eb794159e5f0

ansible_callback/

existing Ansible callback plugin infrastructure

ansible.cfg

current Ansible runtime defaults

current inspected blob SHA: cca1e2d7d0c1b2caae7bd81ea09ada6201abf004

2.1 Current failure mode

playbooks/preflight.yml currently has:

- name: "Preflight B — 連線檢查(SSH 是否通)"
  hosts: all
  gather_facts: false
  tags: [connect]
  tasks:
    - name: "[{{ inventory_hostname }}] ping(確認 SSH/帳號/金鑰)"
      ansible.builtin.ping:

Therefore an intentionally powered-off VM that remains in the inventory is seen as Ansible UNREACHABLE.

playbooks/site.yml imports preflight.yml, so a normal site deployment can also encounter the same host even if the wizard previously ran a separate preflight.

2.2 Existing mechanisms that MUST be reused

Do not create parallel targeting systems when existing mechanisms already provide the required semantics.

Pilot already has:

--limit propagation in deployment transactions.

resolvePatternHosts(...).

resolveInventoryVariables(...), backed by ansible-inventory --list.

contract dependency metadata.

component/site tag metadata.

structured Ansible host-stat parsing.

deployment transaction and rollback infrastructure.

The new feature should extend these funnels instead of bypassing them.

3. Problem statement

The managed environment will contain many VMs with the following operational characteristics:

Pilot owns their desired configuration.

Pilot does not own their power lifecycle.

External personnel may power them on or off at any time.

A powered-off VM must remain part of the desired topology.

When the VM is powered back on, the next applicable Pilot deployment must be able to configure it without requiring the host to be re-added to inventory.

Core infrastructure hosts may still need to be mandatory.

The current model treats every unreachable host as an infrastructure/deployment failure. This is incorrect for intentionally offline on-demand VMs.

4. Goals

The implementation MUST satisfy all of the following.

G1. Preserve desired topology

Offline hosts remain present in:

hosts.yml

generated inventory.yml

inventory role groups

topology graph

contract calculations

static validation

G2. Explicit availability policy

Every host resolves to one of:

required
optional

If no policy is specified, the effective policy MUST be:

required

This default is mandatory for backward compatibility and safety.

Existing inventories must not silently become permissive.

G3. Optional offline hosts do not fail Pilot-managed deployment

If an optional host is transport-unavailable before mutation:

it is excluded from the effective execution scope,

no remote Ansible task is intentionally sent to it,

it is reported as deferred,

deployment may still return exit code 0.

G4. Required offline hosts block before mutation

If a required host in the selected deployment scope is transport-unavailable:

Pilot stops before any apply/check mutation against the selected scope,

Pilot returns non-zero,

output identifies the blocking host(s).

G5. Handle shutdown races

If an optional host was reachable during the initial probe but becomes transport-unreachable during Ansible execution:

remaining reachable hosts continue using normal Ansible behavior,

Pilot records that host as deferred,

Pilot may reclassify the Ansible non-zero result as semantic success only when the structured result proves there were no real task failures or other fatal errors.

G6. Do not hide configuration defects

The following MUST remain fatal even for an optional host:

task/module failure,

assertion failure,

failed validation,

SSH authentication failure,

host-key verification failure,

invalid identity/key configuration,

malformed inventory,

invalid Ansible options,

syntax/parser errors,

controller-side failures,

callback/result corruption,

unknown UNREACHABLE reason that is not safely classified as an offline transport failure.

G7. Dependency-safe execution

Pilot must not execute a consumer component when a required provider endpoint is known to be unavailable and the consumer cannot safely deploy without it.

For v1, conservative whole-host deferral is acceptable and preferred over unsafe component execution.

G8. No new power-management commands

No hypervisor lifecycle API is required or desired.

G9. No new mandatory interactive prompt

Availability resolution must be deterministic from inventory policy and observed reachability.

Existing --actions / prompt automation flows must not require a new availability prompt.

5. Non-goals

The following are explicitly out of scope.

Starting VMs.

Stopping VMs.

Rebooting VMs.

Querying libvirt/Proxmox/vSphere power state.

Adding a hypervisor provider abstraction.

Wake-on-LAN.

Scheduling VM power operations.

Removing offline hosts from canonical inventory.

Maintaining inventory-online.yml as a second canonical inventory.

Treating every Ansible failure on an optional host as ignorable.

Globally adding ignore_unreachable: true.

Rewriting every playbook with when: host_is_online.

Guaranteeing success if a host experiences an actual task failure during shutdown; only safely recognized transport-unreachable outcomes may be deferred.

Changing direct, manually invoked ansible-playbook behavior outside Pilot-managed deploy/reconcile flows.

6. Terminology

Desired host

A host present in the canonical inventory.

Deployment availability

A policy declaring whether inability to reach a host should block the selected deployment.

Required host

A selected host whose deployment availability is required.

Optional host

A selected host whose deployment availability is optional.

Candidate host

A host selected by:

deployment scope,

component role membership,

site tags,

user --limit,

current contract plan.

It has not yet passed availability filtering.

Support host

A provider/dependency host that may not itself be mutated in the current run but whose endpoint availability is required by a selected consumer.

Example:

deploy only web-01/freeipa-client

ipa-1/freeipa-server can be a support host even if --limit web-01 prevents Pilot from applying the FreeIPA server playbook.

Effective execution scope

The final set of managed hosts that may receive Ansible tasks in the current invocation.

Deferred host

An optional host omitted or removed from this run because it is currently unavailable or because its required provider endpoint is unavailable.

Deferred is not the same as successfully converged.

Fatal host

A host whose current condition requires Pilot to fail the deployment.

7. Inventory schema

7.1 Simplified hosts.yml

Add a first-class host field:

deployment_availability: required

or:

deployment_availability: optional

Example:

vars:
  ansible_user: ubuntu
  ansible_ssh_private_key_file: ~/.ssh/id_ed25519

hosts:
  ipa-1:
    ansible_host: 10.10.0.10
    roles:
      - freeipa-server
      - dns
      - ntp
    env: prod
    deployment_availability: required

  dev-vm-01:
    ansible_host: 10.10.10.21
    roles:
      - freeipa-client
      - freeipa-dns-client
      - linux-servers
      - host-monitoring
    env: prod
    deployment_availability: optional

  dev-vm-02:
    ansible_host: 10.10.10.22
    roles:
      - freeipa-client
      - linux-servers
    env: prod
    deployment_availability: optional

Required semantics

Missing field => effective required.

required => unavailability blocks if this host is part of the selected deployment requirement.

optional => transport unavailability may defer it.

Do not add always-on, on-demand, stopped, running, or power_policy; Pilot is not a power controller and cannot authoritatively observe power state.

7.2 internal/inventory.Host

Modify the typed model.

Suggested shape:

type Host struct {
    Name                   string
    AnsibleHost            string
    AnsibleUser            string
    SSHKeyFile             string
    Roles                  []string
    Env                    string
    DeploymentAvailability string
    Extra                  map[string]string
}

A named type is preferred:

type DeploymentAvailability string

const (
    DeploymentAvailabilityRequired DeploymentAvailability = "required"
    DeploymentAvailabilityOptional DeploymentAvailability = "optional"
)

Provide an effective-value helper:

func (h Host) EffectiveDeploymentAvailability() DeploymentAvailability

Behavior:

""         -> required
"required" -> required
"optional" -> optional

Unknown values are validation errors.

7.3 Parser behavior

Parse(...) must recognize deployment_availability as a first-class field rather than leaving it in Extra.

7.4 Lint behavior

Lint(...) must emit an error for values outside:

required
optional

Empty is valid and means default required.

7.5 Generate behavior

Generate(...) must preserve the field into full Ansible inventory when explicitly present.

Example output:

all:
  hosts:
    dev-vm-01:
      ansible_host: "10.10.10.21"
      deployment_availability: "optional"

Do not force-render required for old hosts that omitted the field unless doing so is necessary for an existing stable-output convention.

The effective default belongs in Pilot logic, not in a destructive inventory rewrite.

7.6 Full/manual inventory.yml

This feature must also work when the operator does not use simplified hosts.yml.

Resolve policy using the effective host variables returned by:

ansible-inventory -i <inventory> --list

Use the existing resolveInventoryVariables(...) path rather than adding a second YAML parser for runtime inventory behavior.

This also permits normal Ansible inheritance if an operator deliberately sets the variable through a group.

Unknown runtime policy value MUST fail before mutation even if the input bypassed hosts.yml lint.

8. Execution architecture

The required execution pipeline is:

canonical desired inventory
          |
          v
static validation of desired topology
          |
          v
resolve requested deployment scope
(component/site/tags/user limit)
          |
          v
resolve candidate mutation hosts
          |
          +--------------------------+
          |                          |
          v                          v
resolve dependency support hosts   load effective host vars
          |                          |
          +------------+-------------+
                       |
                       v
             parallel TCP availability probe
                       |
             +---------+----------+
             |                    |
             v                    v
      required unavailable   optional unavailable
             |                    |
           BLOCK                DEFER
                                  |
                                  v
                       effective execution scope
                                  |
                                  v
                     Ansible --limit <hosts>
                                  |
                                  v
                      structured run outcome
                                  |
                     +------------+-------------+
                     |                          |
                     v                          v
             real failure/fatal       optional transport race
                     |                          |
                   FAIL                       DEFER

Availability filtering is mandatory for Pilot-managed remote deployment. It is not part of the optional preflight prompt.

9. Availability probe

9.1 Probe definition

v1 uses TCP reachability to the effective Ansible SSH endpoint.

Resolve from host vars:

ansible_host
ansible_port
ansible_connection

Defaults:

ansible_port = 22
ansible_connection = ssh when omitted

The probe target is:

<ansible_host>:<ansible_port>

Do not use ICMP ping as the primary signal.

9.2 Interpretation

A successful TCP connection means:

candidate transport is reachable enough to let Ansible perform authoritative SSH/auth/module validation

It does not mean the host is fully valid.

This distinction is important:

TCP probe filters expected unavailable machines cheaply.

Ansible still detects credentials, host keys, Python/module issues, privilege escalation problems, etc.

9.3 Connection types

v1 only defines optional-host filtering for normal SSH-managed hosts.

Rules:

implicit SSH => probe.

explicit ansible_connection: ssh => probe.

localhost / local controller play => never remote-probe.

unsupported non-SSH connection declared optional => fail validation with a clear message until a safe prober exists for that connection type.

unsupported non-SSH connection declared/missing required => do not silently mark optional; normal execution behavior remains authoritative.

9.4 Concurrency

Probes MUST run concurrently.

Do not perform:

N hosts * sequential SSH timeout

Suggested initial constants:

probe timeout: 2 seconds
max concurrent probes: 32

These should be internal/testable defaults in v1, not necessarily new CLI flags.

The implementation must:

bound concurrency,

respect context cancellation,

close successful sockets immediately,

produce deterministic sorted output independent of completion order.

9.5 Test seam

Do not hard-wire net.DialTimeout directly into orchestration logic.

Use a small interface/function seam such as:

type Prober interface {
    Probe(ctx context.Context, endpoint Endpoint) ProbeResult
}

or inject a dial function.

Unit tests must not depend on real network timing.

10. Candidate scope resolution

Availability must only block hosts relevant to the selected operation.

An unrelated required host that is offline MUST NOT block a deployment that cannot target or depend on it.

Example:

ipa-2 is required but belongs only to an unrelated component
operator deploys dashboard only
dashboard does not depend on ipa-2

ipa-2 must not block that deployment merely because it exists in inventory.

10.1 User limit

Honor existing --limit semantics.

Do not string-intersect arbitrary Ansible patterns manually.

Use existing Ansible-backed resolution helpers such as resolvePatternHosts(...) or equivalent established scope machinery to expand the requested limit into concrete host names.

The resulting effective limit passed to the actual run should be a deterministic list of concrete host names.

10.2 Site tags

For site.yml, availability checking must respect selected tags.

Do not block on a host belonging only to components outside the selected tag scope.

Use the contract catalog as the source of truth for:

component IDs,

roles,

site.include,

site.tags,

dependency relationships.

Do not add a second hard-coded role/tag table.

10.3 Single component / reconcile

Use the already selected contract plan and role scope.

Required contract dependencies included by current planning remain part of scope calculations.

11. Effective execution scope model

Add a pure model in an appropriate package, preferably internal/delivery for policy resolution and a small internal/availability package for transport probing.

Suggested types:

type HostAvailabilityPolicy string

const (
    HostRequired HostAvailabilityPolicy = "required"
    HostOptional HostAvailabilityPolicy = "optional"
)

type ProbeState string

const (
    ProbeReachable   ProbeState = "reachable"
    ProbeUnreachable ProbeState = "unreachable"
)

type ProbeResult struct {
    Host     string
    Endpoint string
    State    ProbeState
    Err      error
}

type DeferredReason string

const (
    DeferredUnavailable          DeferredReason = "unavailable"
    DeferredDependencyUnavailable DeferredReason = "dependency_unavailable"
    DeferredRuntimeUnreachable   DeferredReason = "runtime_unreachable"
)

type DeferredHost struct {
    Host       string
    Policy     HostAvailabilityPolicy
    Reason     DeferredReason
    Dependency string
}

type ExecutionScope struct {
    Candidates []string
    Included   []string
    Deferred   []DeferredHost
    Blocking   []string
}

Names may differ, but the responsibilities and semantics must remain.

Pure resolver functions must be unit-testable without invoking Ansible or opening sockets.

12. Required vs optional decision table

12.1 Initial probe

Policy

Probe

Result

required

reachable

include

required

unavailable

block

optional

reachable

include

optional

unavailable

defer

missing

reachable

include as required

missing

unavailable

block as required

invalid

any

fail validation

12.2 No remaining mutation hosts

If all selected mutation hosts are optional and currently unavailable:

Nothing to deploy.
Deferred:
  dev-vm-01 — unavailable
  dev-vm-02 — unavailable

Return exit code:

0

Do not invoke the apply playbook.

This is a successful no-op, not a claim that those hosts are converged.

12.3 Explicit single-host limit

If the user explicitly limits to an optional offline host:

pilot deploy ... --limit dev-vm-01

Pilot still follows policy:

optional + unavailable => deferred

Do not turn this into an implicit power-management request.

Do not add an interactive "start the VM" prompt.

13. Site localhost safety requirement

playbooks/site.yml contains a controller-side safety play on localhost.

An automatically generated effective limit MUST NOT accidentally exclude it.

For aggregate site deployment:

effective remote hosts:
  ipa-1
  dev-vm-02

the actual limit must include localhost, for example:

localhost,ipa-1,dev-vm-02

Use a dedicated helper and regression tests.

Do not add localhost to ordinary single-component playbook limits unless that playbook's existing scope requires it.

14. Static preflight behavior

Offline optional hosts MUST remain part of static validation.

The static portion of playbooks/preflight.yml already does not require remote connectivity.

Preserve this property.

Desired behavior:

all desired hosts
    |
    v
preflight --tags static

before remote availability filtering when the operator selected a preflight mode that includes static validation.

Static validation must still detect errors on an offline optional host, including:

malformed/empty connection fields,

placeholders,

duplicate IPs,

bad inventory membership,

invalid deployment availability policy,

other existing static checks.

14.1 Availability resolution is not skippable

The existing preflight prompt may remain optional/skippable.

However:

deployment availability filtering

is execution safety and MUST run regardless of the user's preflight choice.

Do not couple availability filtering to "完整前置檢查".

14.2 Refactor recommendation

Current runPreflight(...) mixes:

user choice,

static validation,

connect validation.

Refactor it into concepts such as:

type preflightMode int

const (
    preflightFull preflightMode = iota
    preflightStaticOnly
    preflightSkip
)

func promptPreflightMode(...) (preflightMode, error)
func runStaticPreflight(...)
func runConnectPreflight(..., effectiveLimit string)

Keep the existing prompt position and choices if possible so automation traces do not need gratuitous renumbering.

Remote connect preflight must use the effective limit.

15. Embedded site preflight

site.yml imports preflight.yml.

Do not remove this safety mechanism merely to implement optional hosts.

Because the aggregate site run receives the effective --limit, its embedded remote preflight will naturally avoid hosts filtered before execution.

It is acceptable that an explicitly requested wizard "full preflight" results in a pre-check plus the site's own embedded preflight, because similar duplication already exists in the current flow.

The correctness requirement is:

site.yml never receives the pre-probe optional-offline hosts in its effective remote limit

and the localhost site safety play remains executable.

16. Dependency availability

Simple host reachability filtering is insufficient.

Example:

ipa-1:
  component: freeipa-server
  state: unavailable

dev-vm-02:
  component: freeipa-client
  state: reachable

The FreeIPA client contract has a required provider endpoint dependency on the FreeIPA server.

Running the client because its own SSH port is reachable can still produce a guaranteed failure.

16.1 Dependencies considered by availability gating

v1 MUST gate dependencies that represent runtime provider endpoints, especially relationships expressed through:

required dependency
+
relation: providerEndpoint

and/or a contract binding sourced from a provider endpoint.

Do not assume every required dependency necessarily means a separately reachable remote provider; same-host/software ordering dependencies must continue to use existing contract planning semantics.

16.2 Support-host probing

A provider host may need to be probed even when it is not a mutation target.

Example:

user --limit dev-vm-02
freeipa-client on dev-vm-02 requires freeipa-server on ipa-1

Pilot may probe ipa-1 as a support host without adding ipa-1 to the mutation limit.

16.3 Conservative v1 deferral

The current main execution primitive is host-level --limit.

Therefore v1 may conservatively defer an entire optional host if any selected component on that host has a required provider endpoint that is unavailable.

Example:

dev-vm-02:
  freeipa-client      -> dependency unavailable
  host-monitoring     -> otherwise runnable

v1 may output:

dev-vm-02 deferred — required provider freeipa-server unavailable

and skip the whole host.

This is intentionally conservative.

Do not create a complex runtime inventory/group rewrite in v1 solely to run the unrelated component on the same host.

A future component-by-host execution-unit implementation may refine this behavior.

16.4 Dependency failure policy

If a selected consumer cannot run because its required provider endpoint is unavailable:

consumer host policy optional => defer consumer host.

consumer host policy required => block deployment before mutation.

16.5 Provider cardinality

Reuse existing contract/binding source-selection semantics where available.

Do not invent provider choice rules that contradict:

hostCardinality

binding sourceSelection

existing topology resolution.

If a dependency permits multiple equivalent providers, a reachable valid provider may satisfy availability according to the existing contract semantics.

17. Mid-run shutdown race

Pre-run probing alone cannot satisfy the operational requirement.

An external operator can power off an optional VM after the probe but during:

preflight,

check/diff,

apply,

verification.

Pilot must distinguish:

optional host became transport-unreachable

from:

optional host encountered a real configuration failure

17.1 Do not solve this with global ignore_unreachable

Do not add:

ignore_unreachable: true

globally.

Reasons:

it obscures required-host failures,

it does not distinguish authentication/configuration errors,

it makes playbook output harder to reason about,

it pushes policy into every play rather than the Pilot execution layer.

17.2 Structured callback

Add a lightweight Ansible notification callback dedicated to machine-readable run outcomes.

Suggested files:

ansible_callback/pilot_result.py
ansible_callback/test_pilot_result.py

Use Python standard library only.

The callback MUST NOT replace the current stdout callback.

The operator must continue to receive normal streaming Ansible output.

The callback writes a per-invocation event file selected by an environment variable such as:

PILOT_ANSIBLE_RESULT_FILE

Pilot-managed runs create the file under the existing private Ansible runtime directory.

Permissions must be restrictive.

17.3 Callback events

Record at least:

{"event":"unreachable","host":"dev-vm-01","reason":"connection_timeout"}
{"event":"failed","host":"dev-vm-02"}
{"event":"stats","hosts":{"dev-vm-01":{"failures":0,"unreachable":1}}}

Exact schema may differ but MUST include enough information to safely classify the final process result.

Do not record:

module arguments,

secret values,

task result payloads,

vault content,

environment secrets.

17.4 Unreachable reason classification

Only known transport-offline classes may be tolerated for optional hosts.

Suggested safe reason codes:

connection_refused
connection_timeout
network_unreachable
host_unreachable
no_route
connection_reset
connection_closed

Explicitly non-tolerable examples:

authentication_failed
host_key_verification_failed
identity_file_error
permission_denied
unsupported_connection
unknown

Classification should be conservative.

Unknown text => fatal.

Do not downgrade an error merely because Ansible labels it UNREACHABLE.

17.5 Final stats are mandatory for downgrade

Pilot may reclassify a non-zero Ansible process result to semantic success only if:

the structured callback produced a valid final stats event,

stats show zero task failures on every host,

every host with unreachable > 0 is policy optional,

every unreachable event for those hosts is classified as a tolerated transport-offline reason,

no required host was unreachable,

there is no global/controller/callback parsing error,

there is no non-host fatal condition.

If these conditions are not provably true:

fail closed

17.6 Reuse existing stats concepts

cmd/pilot/cmd/ansible_json_result.go already models:

type AnsibleHostStats struct {
    Ok          int
    Changed     int
    Failures    int
    Unreachable int
    Skipped     int
    Rescued     int
    Ignored     int
}

Reuse or move/share this type rather than creating incompatible duplicate recap semantics.

18. Semantic deployment result

Introduce a result layer separate from raw process exit code.

Suggested shape:

type DeploymentOutcome struct {
    RawExitCode   int
    Success       bool
    DeferredHosts []DeferredHost
    Fatal         []string
}

18.1 Raw exit 0

Normal success.

18.2 Raw non-zero with only tolerated optional transport unreachable

Semantic result:

success with deferred hosts

Pilot command exit:

0

18.3 Any task failure

Semantic result:

failure

even if the failing host is optional.

18.4 Required unreachable

Semantic result:

failure

18.5 Unknown/non-host failure

Semantic result:

failure

18.6 Rollback

Rollback must be driven by semantic failure, not raw Ansible non-zero alone.

If the only issue is tolerated optional-host transport disappearance:

do not initiate rollback merely because Ansible returned a raw unreachable exit code.

If there is a real semantic failure:

preserve current rollback behavior.

an optional host becoming unreachable during rollback must never erase or convert the original failure.

19. Deployment output

Output must clearly distinguish "not run" from "successfully converged".

Suggested pre-run output:

═══ Deployment availability ═══

Required
  ✓ ipa-1        reachable

Optional
  ✓ dev-vm-02    reachable
  ○ dev-vm-01    unavailable — deferred
  ○ dev-vm-03    unavailable — deferred

Effective deployment scope: 2 managed hosts

Dependency example:

Optional
  ○ dev-vm-02    deferred — required provider freeipa-server@ipa-1 unavailable

Blocking example:

Deployment blocked before mutation.

Required host unavailable:
  ipa-1 (10.10.0.10:22)

Final successful result with deferral:

Deployment successful with deferred hosts.

Applied/reached:
  ipa-1
  dev-vm-02

Deferred:
  dev-vm-01 — unavailable before execution
  dev-vm-03 — became unreachable during execution

Do not print:

all hosts successfully converged

when some hosts were deferred.

Output order must be deterministic.

20. Deploy integration

20.1 Shared funnel

Do not implement availability only in one TUI branch.

It must apply to every Pilot-managed deployment path that uses the same deployment transaction, including as applicable:

interactive pilot deploy

site deploy

single-component deploy

pilot reconcile

automation-driven deploy prompts

check/diff stage

apply stage

automatic verification where the verification is scoped to the deployment hosts

Prefer one shared availability/semantic-result funnel.

20.2 Current runSiteDeploy

Today runSiteDeploy(...) collects:

stage,

user --limit,

tags,

vault,

extra vars,

then calls the recorded deployment path.

Availability resolution must occur after enough scope information exists to know which hosts/components/tags are relevant, but before preview/apply mutation.

Conceptual order:

collect site inputs
resolve selected components/tags
resolve user-limited candidate hosts
resolve policies and support dependencies
probe availability
block/defer
build effective limit
run connect preflight if requested
execute recorded deployment using effective limit
classify runtime outcome

20.3 Current single-component flow

Apply the same semantics after the selected contract/dependency plan and user limit are known.

Do not pre-probe every inventory host for a single-component deployment.

20.4 Reconcile

pilot reconcile is a day-2 deployment path and must use the same availability semantics.

An offline optional reconciler target is deferred, not a deployment failure.

21. Effective limit construction

Create one helper responsible for building the final Ansible limit.

Requirements:

sorted deterministic host names,

no duplicate hosts,

intersected with user-requested scope,

pre-probe optional-offline hosts removed,

dependency-deferred hosts removed,

localhost added for aggregate site.yml,

no mutation of canonical inventory.

Suggested API:

func BuildEffectiveLimit(playbook string, includedHosts []string) string

or equivalent.

Examples:

site:
localhost,ipa-1,dev-vm-02

single component:
dev-vm-02

If no managed hosts remain for site:

do not run site merely with localhost and claim deployment happened,

return successful no-op with deferred summary before launching apply.

22. Runtime inventory variable resolution

Use one ansible-inventory --list call per resolved inventory snapshot where practical.

Build a runtime view containing at least:

type RuntimeHost struct {
    Name                   string
    AnsibleHost            string
    AnsiblePort            int
    AnsibleConnection      string
    DeploymentAvailability HostAvailabilityPolicy
}

Do not independently parse generated inventory.yml with ad-hoc YAML logic just to obtain host vars.

This feature must respect Ansible's resolved host-var precedence.

23. Interaction with topology and graphs

Topology output represents desired topology, not current availability.

Therefore:

pilot deploy graph

must continue to show offline optional hosts.

Do not remove optional-offline hosts from topology projection.

It is acceptable to later annotate availability in the graph, but that is not required in v1.

24. Interaction with monitoring and other generated configuration

An offline host being deferred from the current Ansible execution does not mean it ceases to exist.

Therefore do not automatically remove it from:

monitoring target definitions,

FreeIPA desired membership,

DNS desired records,

NFS desired topology,

backup desired topology,

any configuration derived from desired inventory,

unless the existing component's declarative semantics independently say to do so.

Availability filtering controls where Ansible executes now, not what the desired topology contains.

25. Security and failure-closed requirements

25.1 Default required

Missing/unknown policy must never silently become optional.

25.2 Event file

Structured result event files must:

live under Pilot's private data/runtime directory,

use restrictive permissions,

be cleaned after processing where consistent with existing evidence retention,

contain no secrets.

25.3 Callback failure

If Pilot needs structured result data to decide whether a non-zero Ansible exit may be tolerated, but:

callback file is missing,

JSON is malformed,

final stats are missing,

schema is inconsistent,

Pilot MUST treat the run as failed.

25.4 No message-string-only global success rule

Do not implement:

if strings.Contains(stdout, "UNREACHABLE") {
    return nil
}

Human output parsing is not sufficient for semantic success.

25.5 Auth failures

Optional policy is not permission to hide broken credentials.

Tests must explicitly cover:

optional host + TCP reachable + SSH permission denied => FAIL

26. Recommended file changes

The coding agent should verify exact current file layout before implementation.

Expected changes/new files are approximately:

internal/inventory/inventory.go
internal/inventory/*_test.go

hosts.example.yml
inventory.example.yml
DELIVERY.md

internal/availability/probe.go
internal/availability/probe_test.go

internal/delivery/availability_scope.go
internal/delivery/availability_scope_test.go

cmd/pilot/cmd/deploy.go
cmd/pilot/cmd/reconcile.go
cmd/pilot/cmd/deploy_availability.go
cmd/pilot/cmd/deploy_availability_test.go

internal/ansible/runner.go
internal/ansible/*_test.go

ansible_callback/pilot_result.py
ansible_callback/test_pilot_result.py

playbooks/preflight.yml
playbooks/site.yml

preflight.yml and site.yml may need only documentation/comment adjustments if command-side effective limits fully preserve their behavior.

Do not change playbook task semantics unnecessarily.

27. Implementation phases

The coding agent should implement in dependency order and keep each phase green.

Phase 1 — Inventory policy

Implement:

typed deployment availability field,

parser,

lint,

generator,

examples,

round-trip tests,

default-required semantics.

Acceptance:

old hosts.yml without field => same effective behavior as before
optional field survives generation
invalid value is rejected

Phase 2 — Runtime host view and probe

Implement:

resolved hostvar loader using existing Ansible inventory path,

SSH endpoint resolution,

concurrent bounded TCP prober,

deterministic results,

fake-dial test seam.

Acceptance:

optional offline can be detected without invoking ansible-playbook
required/optional policy is resolved from full inventory hostvars

Phase 3 — Pure execution-scope resolver

Implement:

candidate list input,

policy decisions,

included/deferred/blocking output,

no-op behavior,

effective limit helper,

site localhost preservation.

Acceptance:

all decision-table unit tests pass without shell/network dependencies.

Phase 4 — Contract dependency availability

Implement:

support-host discovery using contract/provider endpoint metadata,

support-host probing,

conservative host-level dependency deferral/blocking.

Acceptance:

reachable freeipa-client + unavailable required freeipa provider
optional client => deferred
required client => block

Phase 5 — Deploy/reconcile integration

Implement:

refactored preflight mode,

mandatory availability resolution after requested scope is known,

effective limit passed through current transaction path,

no new prompt,

stable automation behavior where possible.

Acceptance:

offline optional hosts never reach initial remote preflight/apply argument scope.

Phase 6 — Runtime race classification

Implement:

structured callback,

final stats,

transport reason classification,

semantic deployment outcome,

rollback gating based on semantic failure.

Acceptance:

optional host disconnects mid-run => semantic success with deferred host
optional host task fails => failure
optional host auth fails => failure
required host disconnects => failure
non-host Ansible error => failure

Phase 7 — Regression/evidence/documentation

Run full suite and add end-to-end evidence.

28. Required tests

28.1 Inventory unit tests

Must cover:

no availability field => effective required,

explicit required,

explicit optional,

invalid value,

generate preserves optional,

unknown extra fields still preserved,

existing inventory snapshots remain stable except intentional new fixture changes.

28.2 Probe unit tests

Must cover:

connection succeeds,

connection refused,

timeout,

context cancellation,

bounded concurrency,

deterministic output order,

non-default ansible_port,

unsupported optional non-SSH connection.

28.3 Scope resolver unit tests

Must cover:

required reachable => include,

required unavailable => block,

optional reachable => include,

optional unavailable => defer,

missing policy unavailable => block,

all optional unavailable => success no-op,

user limit excludes unrelated required offline host,

site limit contains localhost,

no duplicate host names,

stable ordering.

28.4 Dependency tests

Must cover at least:

required provider endpoint reachable,

required provider endpoint unavailable + optional consumer,

required provider endpoint unavailable + required consumer,

provider is support-only because user limit selects consumer,

unrelated offline provider does not block unrelated component,

multiple providers according to existing source-selection/cardinality semantics.

Use real contract fixtures where practical, especially freeipa-client.

28.5 Structured callback tests

Pure Python tests, no external libraries.

Must cover classification of representative messages for:

tolerated transport classes

connection refused,

connection timed out,

no route to host,

network unreachable,

connection reset,

connection closed.

fatal unreachable classes

permission denied,

publickey/authentication failure,

host key verification failed,

missing identity file,

unknown message.

Also test:

failed task event,

final stats emission,

event file unavailable => callback degrades in a way Pilot can detect safely,

no secret/task-arg serialization.

28.6 Semantic result tests

Must cover:

raw exit 0 => success,

raw nonzero + final stats + only optional tolerated unreachable => success/deferred,

same unreachable on required => fail,

optional unreachable with auth reason => fail,

optional host failures > 0 => fail,

missing final stats => fail,

malformed callback JSON => fail,

global error with no host events => fail,

optional pre-probe deferred plus runtime optional deferred are merged/deduplicated.

28.7 Command-level tests

Use shims/fakes rather than real infrastructure.

Verify command argv:

site

ansible-playbook playbooks/site.yml ...
--limit localhost,ipa-1,dev-vm-02

and never includes known pre-probe optional-offline hosts.

single component

Only relevant reachable hosts are limited.

required unavailable

Apply command must not be invoked.

no-op

Apply command must not be invoked and command exits cleanly.

reconcile

Same availability semantics as deploy.

28.8 Race integration test

Provide at least one integration-style test using a deterministic Ansible/callback shim or controlled fixture:

host optional
pre-probe reachable
Ansible structured result reports transport unreachable
no task failures
final stats present

Expected:

Pilot exit 0
host reported deferred
no rollback

A second test must use the same setup with a real task failure and expect non-zero.

29. Acceptance scenarios

The entire feature is not complete until all scenarios below behave exactly as specified.

Scenario A — ordinary mixed fleet

Inventory:

ipa-1      required
vm-01      optional
vm-02      optional
vm-03      optional

Observed:

ipa-1      reachable
vm-01      unavailable
vm-02      reachable
vm-03      unavailable

Expected:

included: ipa-1, vm-02
deferred: vm-01, vm-03
Pilot deployment exit: 0 if reachable hosts succeed

Scenario B — required infrastructure unavailable

Observed:

ipa-1 required unavailable

Expected:

blocked before mutation
apply not invoked
Pilot exit non-zero

Scenario C — optional host explicitly limited

Requested:

limit vm-01

Observed:

vm-01 optional unavailable

Expected:

successful no-op
vm-01 deferred
no apply
exit 0

Scenario D — optional host has bad credentials

Observed:

TCP 22 reachable
Ansible SSH authentication fails

Expected:

FAIL

Do not classify this as expected offline.

Scenario E — optional host powers off after probe

Observed:

initial probe reachable
during Ansible connection is closed/times out
structured stats failures=0, unreachable>0
reason classified as tolerated transport offline

Expected:

host deferred
other hosts continue
semantic success if nothing else failed
exit 0

Scenario F — optional host task failure

Observed:

task executes and fails

Expected:

FAIL

Scenario G — unavailable provider

Topology:

ipa-1:
  freeipa-server
  unavailable

vm-02:
  freeipa-client
  reachable
  optional

Expected:

vm-02 deferred due required provider endpoint unavailable
do not run freeipa-client against vm-02

Scenario H — required consumer with unavailable provider

Same as G but:

vm-02 deployment_availability=required

Expected:

block before mutation
exit non-zero

Scenario I — unrelated required host offline

Operator deploys a component with no dependency on ipa-2.

ipa-2 is required but outside selected component/tag/limit/dependency scope and is offline.

Expected:

ipa-2 does not block this run

Scenario J — all optional hosts offline

Selected deployment contains only optional offline VMs.

Expected:

Nothing to deploy
all selected hosts listed as deferred
exit 0
no ansible-playbook apply invocation

30. CLI and compatibility requirements

Do not add a new power-management CLI.

No mandatory new deployment flag is required for v1.

Existing user-facing deploy choices should remain as stable as practical.

If a future strict override is desired, it may later add something like:

--strict-availability

but it is not required by this specification and should not distract from the core policy.

Backward compatibility

An inventory with no new field must behave as if every host were:

required

Therefore existing users continue to receive failure on unreachable hosts unless they explicitly opt a host into optional availability.

31. Automation compatibility

The repository now has Huh-backed prompt automation and --actions workflows.

Availability resolution must not introduce a new interactive choice for each unavailable host.

Required behavior:

optional unavailable => deterministic defer
required unavailable => deterministic error

If prompt-related function signatures change:

update automation tests,

preserve screen IDs/choice IDs where unrelated,

do not rename existing prompt labels unnecessarily,

do not make availability depend on cursor-driven confirmation.

Availability decisions should be visible in normal output and evidence, not represented as a prompt.

32. Evidence and observability

A successful run with deferred hosts must leave enough information to understand what happened.

At minimum, normal output must include:

included hosts,

pre-run deferred hosts,

dependency-deferred hosts,

runtime-deferred hosts,

fatal hosts if any.

If the existing recorded deployment evidence format has an extensible metadata area, add:

effective hosts
deferred hosts + reason
raw Ansible exit code
semantic result

Do not place secrets or raw unreachable payloads in evidence.

If extending evidence schema would create disproportionate unrelated work, normal deterministic output plus unit/integration evidence is acceptable for v1, but document the limitation.

33. Documentation updates

Update at least:

hosts.example.yml

inventory.example.yml

DELIVERY.md

relevant runbook/preflight comments

Documentation must explain:

deployment_availability is deployment reachability policy, not VM power policy.

default is required.

use optional for externally controlled/on-demand VMs.

optional offline hosts remain part of desired inventory.

Pilot skips/defer unavailable optional hosts during Pilot-managed deployment.

configuration/authentication failures are not ignored.

direct manual ansible-playbook calls do not automatically receive Pilot's availability resolver unless the operator manually provides an equivalent limit.

Suggested example:

dev-vm-01:
  ansible_host: "10.10.10.21"
  roles: [freeipa-client, linux-servers, host-monitoring]
  deployment_availability: optional

34. Prohibited implementations

A coding agent MUST NOT complete this task by doing only any of the following:

P1

ignore_unreachable: true

P2

Adding ignore_errors.

P3

Adding when: around every playbook task.

P4

Deleting offline hosts from hosts.yml.

P5

Generating a second persistent "online-only canonical inventory".

P6

Treating every non-zero result from an optional host as success.

P7

Treating SSH auth failure as expected offline.

P8

Adding hypervisor start/stop logic.

P9

Only modifying preflight.yml while leaving the actual site/apply execution scope unchanged.

P10

Only doing a pre-run probe and ignoring the mid-run shutdown race.

P11

Parsing human PLAY RECAP text as the sole basis for downgrading a non-zero apply.

P12

Defaulting missing policy to optional.

35. Coding quality requirements

Follow existing Pilot package boundaries and naming conventions.

Prefer pure decision functions for policy/scope logic.

Inject network seams in tests.

Keep output deterministic.

Preserve context cancellation.

Avoid goroutine leaks.

Avoid unbounded concurrency.

Do not add external Python dependencies for callback code.

Do not add a new Go dependency unless the standard library/existing dependencies are insufficient.

Keep Ansible as the authoritative validator after initial reachability filtering.

Fail closed whenever semantic success cannot be proven.

Keep normal Ansible output streaming.

Reuse existing contract and transaction abstractions instead of adding a second deployment engine.

36. Verification commands

The coding agent must adapt to current repository targets, but the completed work should pass the repository's normal quality gates.

At minimum run:

gofmt -w <changed-go-files>
go test ./...
go vet ./...
go build ./cmd/pilot

Run callback tests using the repository's established Python/callback test command, for example:

make test-callback

if that target remains current.

Also run any relevant focused tests while iterating:

go test ./internal/inventory/...
go test ./internal/availability/...
go test ./internal/delivery/...
go test ./cmd/pilot/cmd/...

Do not claim completion if the full test suite is red for changes caused by this implementation.

37. Definition of done

This work is done only when all of the following are true.

deployment_availability exists with required|optional.

Missing policy defaults to required.

Simplified and full inventories both work.

Canonical inventory always retains offline hosts.

Optional pre-run unavailable hosts are excluded from the actual remote Ansible scope.

Required selected unavailable hosts block before mutation.

Availability is resolved only for relevant selected/dependency scope, not every unrelated host.

site.yml effective limit preserves localhost.

Contract provider-endpoint availability prevents guaranteed consumer failures.

Mid-run optional transport disappearance is detected through structured results.

Optional transport disappearance may produce success-with-deferred.

Optional task failures remain fatal.

Optional auth/host-key/key errors remain fatal.

Required unreachable remains fatal.

Missing/corrupt structured result data fails closed.

Semantic success prevents unnecessary rollback on tolerated optional disappearance.

Real failures preserve existing rollback behavior.

No new VM power-management commands exist.

No global ignore_unreachable.

Existing automation flows do not gain per-host availability prompts.

Documentation/examples are updated.

Focused tests pass.

Full Go tests pass.

Vet/build pass.

Callback tests pass.

End-to-end evidence demonstrates at least one mixed online/offline optional-host deployment completing successfully.

38. Coding-agent execution instruction

Before changing code:

Re-read AGENTS.md.

Re-read the current versions of every file named in this specification.

Inspect recent commits touching deploy/TUI/inventory code so this implementation does not regress the Huh v2 migration or automation contracts.

Identify the current single shared transaction funnel and integrate there rather than patching only one entry point.

Write focused failing tests first for:

default-required policy,

optional pre-probe deferral,

required blocking,

localhost preservation,

runtime optional disconnect downgrade,

optional auth/task failure remaining fatal.

Implement in the phases listed above.

Run focused tests after each phase.

Run the full repository gates before declaring completion.

If the current main implementation has moved since the baseline recorded here, preserve the behavioral requirements of this specification and adapt file/function names to the new structure instead of mechanically forcing old line-level assumptions.
