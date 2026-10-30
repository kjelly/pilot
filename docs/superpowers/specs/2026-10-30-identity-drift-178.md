# Identity drift / apply parity (#178)

Status: staged implementation; live vm-target acceptance pending.

## Acceptance contract

The observer must describe what the existing identity apply reconciler actually
does. An object absent from the roster is report-only; explicit `state: absent`
is a delete only where apply implements deletion. Direct and indirect membership
must remain distinct. Authoritative group membership removes extra direct members;
additive membership reports extras without claiming they will be removed.

Phase 1 (opt-in `--include-users-groups` until live acceptance) covers normalized canonical users and groups: create/delete, enable/disable,
managed attributes, SSH public-key fingerprints, direct user and nested-group
membership. Apply and drift load the same Ansible normalization tasks. Passwords
and credential lifecycle are outside this phase; no password, vault text, key
material or free-form attribute value may enter a report. JSON is versioned,
sorted and uses empty arrays rather than null. Partial coverage is explicit.

Phase 2 adds handwritten and compiled HBAC/sudo attachments, enabled state,
categories, services and command groups. Reuse the existing grant compiler and
apply normalization; do not compile grant lifecycle again in the observer.

Phase 3 adds hosts, hostgroups and netgroups, and evaluates a common read-only
check-mode entry point. In particular, current hostgroup normalization filters
absent entries but apply has no hostgroup delete task: do not advertise deletion.

Each phase requires a fresh isolated vm-target, immutable candidate/tree and
actual FreeIPA/Ansible acceptance: perturb the covered state, observe the exact
planned operations, apply, observe convergence, and apply again for idempotency.
Phase 1 cases include new/deleted users, direct and nested memberships, additive
membership, empty grants, key replacement/clearing and sentinel redaction. The
full issue remains open until handwritten rules and all remaining objects pass.

## Existing models and reuse

- `accessgrants.Plan` compiles grants and security policy axes, not the complete
  identity roster; `ReconcileOnce` invokes the entire Ansible identity playbook.
- Canonical user/group defaults and active selection are defined in Ansible.
  Extract those normalization tasks unchanged rather than implementing Go defaults.
- `freeiparpc.Find` already rejects truncated/incomplete results. Captured FreeIPA
  4.13.4 fixtures pin `all=true`, scalar `nsaccountlock`, public keys and direct
  `group_find.member_user/member_group`. `user_find.memberof_group` is transitive
  and must never authorize direct-member removal.
- Existing drift probe provides vault-first credentials and a private Kerberos
  cache. Reuse this authentication/targeting path without changing #179/#187.
- Go SSH/RPC reconcile is still a proposal beyond its transport/fixture phase;
  the read model must remain transport-independent so it can reuse this plan.

CI exit contract (opt-in `--exit-code`): 0 = fully covered and clean, 1 = error,
2 = actionable drift, 3 = incomplete coverage or report-only differences. During
staged delivery, a clean subset must not be mistaken for full apply parity.
