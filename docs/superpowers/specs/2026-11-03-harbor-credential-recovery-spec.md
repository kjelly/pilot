# Harbor persistent credential association and recovery

Issue: #237. This contract precedes implementation. Native target validation is
required on a dedicated disposable Ubuntu host with real Harbor API and database;
HTTP fixtures prove only client behavior. No operational services are test targets.

## Acceptance contract

1. Generate the Harbor admin/database and Pulp credentials once, only for a
   demonstrably fresh bundle. Persist restricted owned regular files using
   same-directory atomic replacement, file sync and directory sync. Missing,
   empty, unreadable, unsafe or replaced credentials in an initialized or partly
   initialized bundle fail closed; render and repair never invent replacements.
2. Existing attach, client projection and status authenticate the stored Harbor
   admin through its current-user API and require the admin identity and system
   administrator privilege. Check the stored database password through a native
   TCP PostgreSQL connection, independently of the Harbor API. No successful
   running status is returned after a credential failure.
3. Classify authentication (401), authorization (403 or insufficient privilege),
   unreachable and initializing/server failure separately. Generic server errors
   are not evidence of database corruption. Never include response bodies,
   credentials, command output or arbitrary subprocess errors in diagnostics.
4. Before repair changes state, files or containers, validate the established
   credential association. A stopped stack is the necessary offline-auth
   exception: explicit repair may activate only its unchanged retained Compose
   files after a private binding check (or original-render comparison for legacy
   state), then must authenticate live before render, prepare, recreate, seed or
   successful running publication. Wrong local files fail before activation.
   This preserves the supported down → repair lifecycle without granting an
   implicit password reset or recreation. Preserve canonical root ownership, CA, shared locks,
   instance/generation, consumer protection and all existing cache data.
5. An explicit credential import accepts a restricted, owned regular secret file
   for exactly one of the Harbor admin or database identities. It bypasses only
   the broken local Harbor credential prerequisites, retains discovery/root/CA/Pulp
   checks, validates the candidate against the running service, and publishes
   atomically under the existing global → discovery → physical-root locks.
   Both Harbor files may be lost together, so each identity is independently
   recoverable even while the other is missing. Ordinary operations continue to
   fail until the complete set is restored. This avoids a circular prerequisite
   between two sequential imports. It never resets passwords, recreates services,
   seeds resources or deletes data.
6. Failed validation preserves the previous association. Cancellation before
   publication preserves the previous association. Atomic publication is the
   commit point: interruption afterward leaves the validated candidate usable;
   retry validates again and completes without a service mutation. A durable
   nonsecret intent/completion audit distinguishes interrupted operations.
7. Passwords travel neither in process arguments nor user-visible output. Native
   database validation supplies the password on stdin. Sentinel tests cover
   stdout, stderr, JSON and hostile Compose/API diagnostics.

## Scope, assumptions and risks

The supported ownership model is one UID coordinating multiple processes,
checkouts and VM directories. Cross-UID sharing is unsupported. Recovery requires
the running original Harbor endpoint and an independently authorized valid
secret source. This is reassociation, not password rotation. Database validation
requires the existing Docker runner's stdin capability; inability to prove the
native database credential is a hard failure, never an API-derived substitute.
An unreachable/stopped Harbor must be restored before reassociation; explicit
repair can perform the bounded retained-configuration activation described above;
the import operation does not gain service maintenance authority.

## Validation plan

Targeted tests exercise the real Cobra command, strict file contracts, failed
initial seed, missing and wrong credentials, HTTP diagnostic categories, no
mutation before failed validation, import retries/cancellation, audit safety and
independent processes sharing one lock. Native candidate validation must prove
fresh initialization, reuse, missing/wrong credentials, authorized recovery,
interruption and idempotency while comparing container IDs, generation, CA and
cache/database sentinels. The base version is the negative control for the
credential-loss and anonymous-health acceptance failures. Evidence is published
separately after a clean immutable candidate has actually run.
