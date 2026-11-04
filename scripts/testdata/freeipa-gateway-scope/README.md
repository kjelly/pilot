Native API captures from the disposable AlmaLinux 9 / FreeIPA server
`ipa.ipa227.test` on 2026-11-04, Issue #227. `native-api.json` contains selected
unmodified result envelopes from Root's `native-captures-v2.json`, including
raw/nonraw attribute spelling, direct/indirect memberships, first/repeated
removal and automember conditions, and the local LDAP operational entryUUID.
No credentials are included. Test mutations are an explicitly separate typed
state model; real IPA authorization and automember rebuild remain VM gates.
