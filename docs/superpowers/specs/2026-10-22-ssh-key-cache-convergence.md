# SSH key cache convergence — issue #114

Status: live multi-host acceptance passed on candidate `e42f50c96a763272cbdfcc720e10eeb598dca87e` (tree `a226935f9d323934af85506d31cbac4c77457690`); see [accepted evidence](../../evidence/freeipa-identity-ssh-cache/2026-10-22-e42f50c-live.md).

## Decision

Use bounded, per-user SSSD invalidation after SSH-key reconciliation, with a
durable pending journal on the single identity provider. Do not shorten the
fleet's cache TTL. Preserve #115's authoritative empty-list handling.

| Approach | Security and timing | Load | Deployment / failure |
|---|---|---|---|
| Shorter `entry_cache_user_timeout` | Reduces online staleness; cannot bound offline fallback, replication or responder caches | Recurring identity LDAP reads, approximately active host/user pairs divided by TTL; 5400→60s can approach 90× that component, not 90× total KDC traffic | Changes every client, may require reload; no per-reconcile completion evidence |
| Per-user invalidation + key-set verification | Bounds each attempt and reports unsatisfied pairs; only declares completion when every in-scope host observes the desired set | Work proportional to changed users × enrolled inventory hosts; no steady-state extra host calls | Requires controller SSH/become to clients and a durable server journal; failed/deferred pairs survive retries |

SSSD invalidation does not erase offline credentials. LDAP replication and an
offline SSSD backend can still prevent convergence. A successful invalidation
process alone is insufficient evidence of revocation.

## Acceptance

1. Scope is the union of inventory `freeipa-client`, `freeipa-server`,
   `freeipa-server-replica`, and the reconcile provider itself. Inventory must
   enumerate all enrolled hosts; excluded hosts carry no timing guarantee.
   Deduplicate aliases operationally; delegated hosts must satisfy stage gates.
2. Only explicitly managed active-user SSH keys participate. Omitted/null keys
   keep #115's unmanaged meaning. Existing pending work cannot be discarded by
   omitting a user from a later roster.
3. Before changing keys, persist pending work. A generation distinguishes
   A→B→A, including failed B attempts. Only a generation-matching verified result
   can acknowledge a pair. Serialize identity applies against one provider.
4. Invalidate only the named IPA-domain user, then read
   `sss_ssh_authorizedkeys` and compare the entire normalized key set. Reject
   command errors, malformed output, extra keys and missing keys. No SSSD
   restart, cache database deletion, or fleet-wide expiry for SSH-key changes.
5. Each client attempt has a 30s subprocess budget and a 45s Ansible task
   budget, with SSH connection timeout 5s. Attempts are sequential; N pending
   pairs therefore have a client-attempt budget of 45×N seconds plus controller
   and journal overhead. There is no unconditional 60s fleet-wide SLA.
6. A completed apply means every in-scope pair is verified. Test new SSH
   connections on every client within 10s of completion: removed key must fail
   specifically at public-key authentication; surviving/new key must succeed.
   Disable multiplexing, password/GSSAPI fallback and agent identities. Existing
   sessions are outside the revocation contract. A network error is not proof
   of a denied key.
7. Partial failure: try remaining clients; retain failed/unreachable/deferred
   pairs; emit their host/user identities and fail the apply (nonzero). Never
   restore a revoked IPA key to compensate. Retry the same roster; successful
   pairs do not run again. An identical fully completed apply performs no
   client operations. First adoption performs one verification per managed pair.
8. A crash before/after IPA mutation leaves retryable work. A fresh invocation
   must not infer completion from IPA's `no modifications` response.
9. Non-SSH authorization cache behavior is a separate compatibility concern:
   retain the existing global-refresh option only for actual non-key identity
   mutations; SSH-only changes and no-op applies must never invoke it.
   Every tag selection that can run a non-key mutation, including component
   and row tags, durably records the refresh obligation before mutating and
   settles it afterwards. A selection that does not run the refresh
   (anything without `identity`/`client-cache`, or `--skip-tags client-cache`)
   leaves the obligation pending and says so; the next apply that runs the
   refresh delivers it even when IPA reports `no modifications`. Read-only
   selections neither record nor clear it. Turning the refresh option off
   defers delivery the same way; it does not drop the obligation. A journal
   without authorization state (first adoption) refreshes once.

## Required evidence matrix

Use a clean immutable candidate on an isolated FreeIPA provider plus two
enrolled clients. Warm the old key caches before changing the roster. Cover
last-key revoke, one-of-two revoke, addition, unmanaged keys, empty no-op,
identical reapply, client timeout/unreachable/deferred, retry, interrupted
mutation, A→B→A, and real SSH allow/deny on both clients. Preserve candidate/tree,
execution-affecting hashes, platform versions, timings and truthful verdicts.
Local fakes exercise orchestration and failure handling; they do not replace
real FreeIPA/SSSD/sshd evidence.

## Sources

- https://github.com/kjelly/pilot/issues/114
- https://github.com/kjelly/pilot/pull/115
- https://github.com/SSSD/sssd/blob/master/src/man/sssd.conf.5.xml
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/6/html/deployment_guide/sssd-cache
- https://sssd.io/troubleshooting/basics.html
