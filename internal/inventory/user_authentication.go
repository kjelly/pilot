// user_authentication.go validates and compiles the v3.2 Identity &
// Credential Hardening spec's (spec.md §8, Phase 3) per-user
// `authentication:` block: which Kerberos/FreeIPA authentication
// mechanisms a user's own account may use (ipauserauthtype).
//
// This is a DIFFERENT FreeIPA object from auth_policies[].require_any's
// authentication INDICATOR requirement (krbPrincipalAuthInd, set on a
// host/target) — spec.md §8 keeps the two semantics distinct on purpose:
//
//	user.authentication.allowed  = mechanisms the identity itself may use
//	auth_policies[].require_any  = indicators a target requires present
//
// so this file deliberately does NOT reuse knownAuthIndicators
// (auth_policy.go), even though the two lists overlap in spelling.
package inventory

import (
	"fmt"
	"sort"
	"strings"
)

// knownUserAuthTypes is spec.md §8's illustrative set. §8 explicitly
// requires the implementation to verify the exact FreeIPA-supported set
// before relying on it for a real apply gate — internal/freeipa's
// capability probing (CapUserAuthTypes) is the live confirmation this
// structural list does not attempt to provide.
var knownUserAuthTypes = []string{"password", "otp", "pkinit", "radius"}

var knownUserAuthenticationKeys = []string{"allowed"}

// checkUserAuthentication validates one user's authentication: block. An
// absent block is not an error — it means "no opinion", the same posture
// omitting any other optional user field takes. Called from checkUsers
// (roster_validate.go); kept in its own file per this package's
// per-feature file convention (auth_policy.go, grant_security_policy.go).
func checkUserAuthentication(u map[string]any, label string) []RosterViolation {
	raw, has := u["authentication"]
	if !has {
		return nil
	}
	var out []RosterViolation
	auth := asMap(raw)
	if unk := unknownKeys(auth, knownUserAuthenticationKeys); len(unk) > 0 {
		out = append(out, RosterViolation{Rule: "user authentication keys", Detail: fmt.Sprintf("user %q: unknown authentication field(s) %s", label, strings.Join(unk, ", "))})
	}
	allowed := stringListField(auth, "allowed")
	if len(allowed) == 0 {
		out = append(out, RosterViolation{Rule: "user authentication allowed", Detail: fmt.Sprintf("user %q: authentication.allowed needs at least one authentication type", label)})
	}
	for _, t := range allowed {
		if !contains(knownUserAuthTypes, t) {
			out = append(out, RosterViolation{Rule: "user authentication type", Detail: fmt.Sprintf("user %q: authentication.allowed %q must be one of %s", label, t, strings.Join(knownUserAuthTypes, "/"))})
		}
	}
	return out
}

// CompiledUserAuthType is one user's desired ipauserauthtype set —
// compiled only for users that declare an explicit authentication: block.
// A user without one is left untouched, not cleared: unlike auth_policies/
// account_policies there is no roster-wide policy section whose coverage
// a user could "drop out of" between reconciles, so omission simply means
// "no opinion", never an implicit clear.
type CompiledUserAuthType struct {
	User string
	// Allowed is sorted and deduplicated.
	Allowed []string
}

// CompileUserAuthTypes compiles every present user's authentication:
// block. Callers MUST have already run ValidateRosterV3 (checkUsers /
// checkUserAuthentication) — this does not re-validate shape.
func CompileUserAuthTypes(root map[string]any) []CompiledUserAuthType {
	var out []CompiledUserAuthType
	for _, raw := range listField(root, "users") {
		u := asMap(raw)
		if stateOrDefault(u, "present") == "absent" {
			continue
		}
		authRaw, has := u["authentication"]
		if !has {
			continue
		}
		allowed := dedupe(stringListField(asMap(authRaw), "allowed"))
		sort.Strings(allowed)
		out = append(out, CompiledUserAuthType{User: stringField(u, "name"), Allowed: allowed})
	}
	return out
}

// CompileUserAuthTypesFile is CompileUserAuthTypes' file-reading
// counterpart, mirroring CompileAuthPoliciesFile's read/parse/dispatch
// shape.
func CompileUserAuthTypesFile(path string) ([]CompiledUserAuthType, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return CompileUserAuthTypes(root), nil
}
