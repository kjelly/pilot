# Shared cache lifecycle acceptance contract (#236)

## Intent and scope

One OS user shares one persistent host cache across processes, checkouts and VM
state directories. Existing global Compose, discovery and canonical root locks
already serialize management; this change retains that transaction and makes
waiting cancelable. Cross-user coordination and automatic profile migration are
outside this change. This is a native Go lifecycle feature, with no apply playbook.

## Observable acceptance criteria

1. All management entry points, including discovery/adoption construction, honor
   context cancellation while another process holds any management lock. A process
   exit releases the kernel lock. Waiters reload state after acquiring the lock.
2. Ordinary startup of the same effective profile/bind address and healthy,
   completed stack returns its existing client contract without changing bundle
   bytes, file timestamps, ownership, credentials, CA, generation, container IDs or
   start times. It performs no render, prepare, Compose mutation, seed or publish.
3. Failed health probes, stopped stacks, incomplete registrations and older client
   contracts fail closed on ordinary startup. They require explicit repair;
   profile/bind conflicts continue to require a separate operator decision.
   An uncertain probe never grants permission to recreate a shared service.
4. Explicit repair may reconcile/recreate the existing compatible stack; normal
   down, purge and repair refuse while any durable consumer registration exists.
   No VM teardown or agent exit stops/purges the cache. No implicit upgrade engine
   or force bypass is introduced.
5. The central VM manager registers a pending consumer before guest provisioning,
   atomically with respect to service maintenance. It checks instance, generation
   and profile/client identity under the service lock. Its durable target record
   retains discovery directory, registration ID and domain identity. Registration
   survives CLI exit, crash and missing VM state; it never expires by PID or TTL.
6. A VM consumer is released automatically only after teardown proves the owned
   domain absent. Failed domain identity/absence probes and failed teardown retain
   protection. Unknown or incomplete cleanup is an error, never a successful release.
   An explicit release operation targets one exact registration and requires
   confirmation of its interruption risk; it does not silently release all clients.
7. Failure before successful completion never publishes a successful service
   contract. Locks cover the entire probe/mutate/publish or teardown transaction.

## Verification and negative controls

Local tests use real independent processes and native flock for simultaneous up,
up versus down/purge, wait cancellation, constructor cancellation and holder crash;
symlink/canonical paths share identity. A controlled HTTP endpoint and command
ledger prove healthy attach has no mutating commands or file/state writes, and
unhealthy attach refuses before mutation. Durable registration tests reopen both
managers and exercise successful release, retained pending/crashed registration,
identity conflict and probe-error refusal. A scratch negative control removes a
specific guard and must fail its corresponding behavioral assertion.

Target validation is required after freezing a clean candidate: dedicated
disposable Docker cache and VM, actual inventory, continuous effective cache
requests during ordinary attach and VM teardown, before/after container identity,
CA and generation, plus active-consumer maintenance refusal and explicit repair.
No existing shared cache, VM or operational credential is an authorized target.
Raw logs live outside the source checkout; sanitized evidence records identify
candidate/tree, tools, exercised boundaries and any unavailable validation.

## Risks and recovery boundaries

Conservative durable registrations can outlive a failed provisioning operation or
lost state directory. This intentionally blocks maintenance until verified cleanup
or an operator's explicit scoped release. Existing guests predating registration
cannot be discovered reliably from arbitrary deleted VM state directories; the
compatibility boundary must remain explicit in documentation/evidence. Discovery,
root ownership and client identity must agree before registering new consumers.
No health matcher semantics are changed as part of this issue.

An existing/adopted state without the consumer-tracking marker is a legacy stack.
Maintenance requires explicit acknowledgement that unregistered guests may be
interrupted. This acknowledgement never bypasses a durable registration. New
stacks establish tracking before the first render, including interrupted startups.
The exact per-domain lock also serializes VM provisioning and teardown so a
concurrent down cannot release a pending registration while up is still booting.
