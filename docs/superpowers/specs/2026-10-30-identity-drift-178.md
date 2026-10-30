# Identity drift / apply parity (#178)

Status: staged implementation; live vm-target acceptance pending.

## Acceptance contract

The observer must describe what the existing identity apply reconciler actually
does. An object absent from the roster is report-only; explicit `state: absent`
is a delete only where apply implements deletion. Direct and indirect membership
must remain distinct. Authoritative group membership removes extra direct members;
additive membership reports extras without claiming they will be removed.

Phase 1 (opt-in `--include-users-groups` until live acceptance) covers normalized canonical users and groups: create/delete, enable/disable,
managed attributes, SSH public keys, direct user and nested-group
membership. Apply and drift load the same Ansible normalization tasks. Passwords
and credential lifecycle are outside this phase; no password, vault text, key
material or free-form attribute value may enter a report, and the drift probe
asks the shared normalization not to produce credential fields at all
(`pilot_identity_normalize_credentials: false`). JSON is versioned,
sorted and uses empty arrays rather than null. Partial coverage is explicit.

Changes to the first draft, from the live vm-target run of PR #204 (each is a
case where apply and the observer disagreed):

- SSH key identity is the digest of FreeIPA's normalized key entry
  (`ipapython.ssh.SSHPublicKey(k).openssh()`: options, type, blob and comment),
  because apply's `user-mod --sshpubkey` is a modification exactly when that
  normalized set differs (comment-only and options-only changes included). Keys
  are parsed only for users whose roster row manages `ssh_keys`, so a key the
  roster does not manage can never fail the observation. A raw LDAP value in a
  spelling FreeIPA would normalize cannot be seen through `user_find`; apply
  would rewrite it and drift cannot show that (known limit).
- A desired `email` without `@` is compared with FreeIPA's default e-mail domain
  appended (`config_show`), as FreeIPA stores it.
- Preserved users (`user-del --preserve`) are invisible to `user_find`, so they
  are read with a second complete search (`preserved=True`). Roster `absent` +
  preserved is a delete (apply removes it for good); roster `present` + preserved
  is `user_preserved`/`manual`: apply cannot create it and fails at the group
  step, so an operator must restore or delete it first. `manual` is a new action;
  with `report` (apply never touches it) and the mutating actions the vocabulary
  is create, delete, update, add_member, remove_member, manual, report, and
  `--exit-code` treats everything except `report` as actionable.
- Pilot's own `pilot-internal-history-g-<sha256>` marker groups are bookkeeping,
  not objects outside the roster.
- The observer prints one fixed error class on failure and nothing derived from
  an exception, a reply or the roster; each class has a probe gate and a fixed
  message, and an unknown failure is `unclassified`.
- The observer and every task that needs the probe's Kerberos ticket are
  `run_once` and carry the same tags as the kinit (`identity`, `drift`).

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
