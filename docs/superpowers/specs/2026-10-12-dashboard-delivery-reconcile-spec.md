# Dashboard delivery through deploy and reconcile

## Requirement and boundaries

Selecting dashboard through either pilot deploy or pilot reconcile must configure its Thanos provider and Grafana datasource in one ordered operation. The operator should not need separate Thanos and dashboard invocations or fixed-IP hosts entries for co-located containers.

The already accepted Docker DNS contract remains unchanged: co-located Grafana uses the Query container's `thanos-query-backend` alias and internal port 10902; remote providers use their configured DNS URL / published port. This change extends delivery orchestration, not DNS or metric retention behavior. No production rollout is authorized by implementing or testing this feature.

## Design

- Add the backward-compatible dependency property `applyBeforeConsumer` to the existing schemaVersion 1 parser and fixture schema. It is valid only on a required `providerEndpoint` dependency. Default false preserves existing endpoint dependencies as bound services rather than implicitly deployed providers.
- Dashboard opts into this property for Thanos Query. Both required sameHosts dependencies and explicitly opted-in endpoint dependencies execute once in dependency-first order. Other provider dependencies (including Thanos's S3 provider) remain prerequisites, not mutation targets.
- Compute mutation scopes by following only executed dependency edges. A sameHosts prerequisite follows its consumer's resolved hosts; an opted-in provider uses its declared inventory role and must resolve unambiguously. Do not expand a Docker mutation to a bound S3 host or unrelated Docker hosts.
- Replace consumer `target_group` overrides for dependency runs with each dependency's own role and resolved host limit. Do not inherit consumer row tags. Preserve stage and confirmation flags; the existing host environment cross-checks remain mandatory.
- Resolve missing endpoint binding inputs from the actual inventory before confirmation; preserve explicit extra-vars, inventory values and vault inputs. Do not ask a second host-address question midway through the approved plan or persist inferred addresses as Grafana hosts pins.
- Deploy and reconcile render the complete ordered host/playbook plan before one execution authorization. On a failed dependency, stop before the consumer; report completed dependency results in durable delivery records.
- Enable dashboard and thanos-query in the reconcile catalog. Their reconciliation changes service/network endpoints (Query alias / upstream selection and Grafana datasource URL), so both declare the existing `network.endpoints` effect. This deliberately extends the outbound webhook component/effect mapping without inventing a new effect or labeling these changes as scrape-target edits.

## Acceptance

1. Both catalogs expose dashboard and thanos-query with contract-backed effects.
2. Selecting only dashboard plans its Docker prerequisites, then Thanos Query, then dashboard in both deploy and reconcile.
3. Provider dependencies without the opt-in flag and optional dependencies are never auto-applied; decommission/non-apply runs never trigger installation.
4. A split-host inventory applies Docker only to the selected dashboard/Query hosts; Query only to its provider host; S3 and unrelated Docker hosts are not mutated.
5. Missing or ambiguous opted-in providers fail before any apply. Explicit consumer target overrides and tags cannot retarget or skip a provider's required tasks.
6. Binding defaults follow current inventory and preserve supplied values. All authorization questions finish before mutation; cancelling the plan performs no apply.
7. A provider apply failure prevents dashboard apply and retains the successfully completed prefix in evidence.
8. On a disposable actual deployment, selecting dashboard through deploy and reconcile produces a working container-side datasource (dashboard C8); a repeat operation converges without changes.
9. The formal run uses an immutable candidate and a clean checkout; record real CLI decisions, inventory, exit codes and execution results. Existing unrelated TUI timeouts are not represented as passing tests.

## Assumptions and unknowns

- Required services and credentials outside the mutation chain (S3, metric sites, vault inputs) already exist and pass the normal contract checks.
- The opted-in provider is managed by this inventory; an external URL override does not authorize creating an arbitrary remote service.
- A single operation spanning different environment groups can be rejected by existing stage gates; this feature does not infer or bypass production authorization.
- Delivery rollback remains per-component. If an approved provider succeeds and the consumer fails, the provider's completed configuration is recorded rather than claimed globally rolled back.

## Evidence plan

Use pure graph/limit tests, parser rejection tests, recorder/runner integration tests for both paths and failure/cancellation, then the real built CLI against an isolated VM inventory. Exercise provider setup and repeated convergence; preserve the dashboard's existing acceptance commands and Expected values. Store actual-run artifacts separately and link the accepted candidate in the current runbook.
