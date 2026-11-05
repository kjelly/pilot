# Selecting deployment components in CI

The `deploy` command accepts repeatable `--component <contract-id>` flags.
An explicit selection replaces the scope and component menu answers; the same
catalog entries, contract plan, input collection and deployment transactions
serve both the CLI and TUI. Use contract IDs such as `host-monitoring` or `ntp`.
The aggregate menu key `core-infra-provider` is not a contract ID.

For unattended integration, combine the selected IDs with `--preview-only` or
`--force`, the workspace `--dir`, an inventory path, an optional `--limit`, and
the intended `--stage`. Both modes work with closed stdin. Workspace defaults,
including `.vault/main.yaml`, follow the interactive flow. Missing required
inputs and ambiguous exactly-one targets still fail. Secret values belong in
the workspace vault, not command arguments or CI logs.

Every selected ID must be eligible for the deploy workflow. Unknown IDs,
experimental components hidden without `--show-experimental`, and day-2-only
reconcilers are rejected before controller initialization, inventory regeneration
or roster migration. Use `reconcile` for those reconcilers. Repeated identical
IDs select one request. `--component` and scenario-driven `--actions` conflict.
Omitting `--component` retains the existing interactive/default scope flow.

An explicit selection runs each component's declared lifecycle playbook directly.
Required same-host dependencies and providers declaring `applyBeforeConsumer`
run first with their own resolved host scope. A support-only provider edge does
not authorize applying that provider or its dependencies. Unselected roles on
the provider host are not deployed. The requested consumer limit does not become
the limit for a provider's same-host prerequisite.

`--preview-only` exits successfully only when every planned playbook actually
previewed successfully; it performs no apply and persists no accepted auto host
variables. A failed preview or a playbook deferred on every target returns an
error. `--force` authorizes the complete plan once, then previews and applies
each playbook in order. Earlier successful applies remain if a later preview or
apply fails. Preview results are never reused between invocations or component
sets. Stage, inventory completeness, availability, preflight, recorded execution
and contract verification gates still apply. Production stage also requires the
existing staging-attestation flag.

CI should retain the process exit code and deployment evidence, and publish the
terminal operation as `deploy` with the complete requested component set. A
contract with automatic verification disabled still needs explicit spec
verification in its acceptance workflow. Keep generic workflow integration in
the calling repository; this repository does not assume access to a private
`infra-deploy` workflow.

The disposable-target acceptance harness is
[`scripts/test-deploy-components.sh`](../scripts/test-deploy-components.sh).
Its `host-monitoring` mode checks a real missing-package repair, authentication,
service state, full spec verification and repeat-apply idempotency. Its `topology`
mode uses the explicitly synthetic fixture under
[`playbooks/test/fixtures/deploy-components`](../playbooks/test/fixtures/deploy-components/acceptance.md)
to check native per-host effects across two dependency hops. The caller provides
the clean candidate binary, dedicated target inventory, private artifact directory
and consumer host, and owns target provisioning and cleanup. These fixture roles
exercise selection semantics; they do not install the products whose public IDs
they reuse.
