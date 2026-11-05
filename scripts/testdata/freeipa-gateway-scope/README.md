Native API captures from the disposable AlmaLinux 9 / FreeIPA server
`ipa.ipa227.test` on 2026-11-04, Issue #227. `native-api.json` contains selected
unmodified result envelopes from Root's `native-captures-v2.json`, including
raw/nonraw attribute spelling, direct/indirect memberships, first/repeated
removal and automember conditions, and the local LDAP operational entryUUID.
No credentials are included. Test mutations are an explicitly separate typed
state model; real IPA authorization and automember rebuild remain VM gates.

`native-authorization-types.json` retains selected HBAC/sudo attribute values
and their in-process type descriptors from Root's native `ipa.ipa227.test`
probe on 2026-11-04, before JSON serialization. The probe used transient rules
with `admin`/`ipaservers`; those values do not prove the lifecycle fixture's
scope correctness. Behavioral tests reconstruct the captured sequence types,
then supply explicit synthetic scoped policy values and execute the real
fixture script. The source capture fingerprint is included in the metadata.

`native-short-host.json` preserves the real native `host_show('keep')` FQDN
result and its before-JSON tuple/str descriptor from the same disposable
authority on 2026-11-04. Unrelated host attributes are omitted. Tests exercise
both native tuples and JSON lists, with explicit malformed/ambiguous semantic
counterexamples and a separate live same-short identity in another domain.
