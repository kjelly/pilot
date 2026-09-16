package freeipaaccess

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// pilotAnnotationPrefix mirrors internal/inventory.AnnotationUserClassPrefix
// verbatim (see Host's doc comment for why it is duplicated rather than
// imported).
const pilotAnnotationPrefix = "pilot.annotation."

// parseAnnotations extracts "pilot.annotation.<key>=<value>" entries from a
// host's raw userClass values. Malformed entries (no "=", or an empty key)
// are silently skipped rather than erroring — this is a read-only display
// path, not the write-side validator (internal/inventory.ValidateAnnotations
// already gates what can be written), and a stray foreign or hand-edited
// userClass value must never break the portal.
func parseAnnotations(userClass []string) map[string]string {
	var out map[string]string
	for _, uc := range userClass {
		rest, ok := strings.CutPrefix(uc, pilotAnnotationPrefix)
		if !ok {
			continue
		}
		key, value, ok := strings.Cut(rest, "=")
		if !ok || key == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string)
		}
		out[key] = value
	}
	return out
}

// This file parses FreeIPA's non-raw (all=true, no raw=true) *_show/*_find
// attribute maps into this package's normalized types.
//
// Deviation from spec.md §15/§17 ("hbacrule_find(all=true, raw=true)" /
// "sudorule_find(all=true, raw=true)"): Phase 1's live capture against a
// real FreeIPA server (docs/evidence/pilot-access-gateway/) found that
// raw=true returns member* attributes as full LDAP DNs (e.g.
// "cn=gpu-users,cn=groups,cn=accounts,dc=..."), requiring a DN parser that
// classifies each DN by its container RDN to split it into
// Users/Groups/Hosts/Hostgroups/etc. The non-raw form instead returns
// separate, already-classified attributes with plain resolved names
// (memberuser_user, memberuser_group, memberhost_host,
// memberhost_hostgroup, memberallowcmd_sudocmd,
// memberallowcmd_sudocmdgroup, ...) — no DN parsing needed at all, and sudo
// command names come back as their actual command text instead of an
// opaque ipaUniqueID. This package therefore uses non-raw exclusively; see
// the Phase 1 evidence doc for the side-by-side capture that justified it.
//
// A second, non-obvious real-API inconsistency this file works around:
// some single-valued attributes come back as a bare JSON scalar
// (nsaccountlock: false) while others of the same conceptual shape come
// back as a single-element JSON array (ipaenabledflag: [true]). attrBool/
// attrStrings below accept either form uniformly rather than assuming one.

// attrStrings reads a FreeIPA attribute as a string slice, accepting
// either a JSON array of strings or (rare, but observed) a bare string.
// A missing or nil key returns nil, never an error — most attributes are
// legitimately absent (e.g. a rule with no explicit host members because
// it uses hostcategory=all instead).
func attrStrings(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{t}
	default:
		return nil
	}
}

// attrString returns the first value attrStrings would return, or "".
func attrString(m map[string]any, key string) string {
	ss := attrStrings(m, key)
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}

// attrBool reads a FreeIPA boolean attribute, accepting either a bare JSON
// bool or a single-element array containing one (see file doc comment).
func attrBool(m map[string]any, key string, def bool) bool {
	v, ok := m[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case []any:
		if len(t) == 1 {
			if b, ok := t[0].(bool); ok {
				return b
			}
		}
		return def
	default:
		return def
	}
}

// attrCategoryAll reports whether a FreeIPA "*category" attribute is set
// to "all" (spec.md §15/§17's UserCategoryAll/HostCategoryAll/etc.).
func attrCategoryAll(m map[string]any, key string) bool {
	for _, v := range attrStrings(m, key) {
		if v == "all" {
			return true
		}
	}
	return false
}

// generalizedTimeLayout is LDAP GeneralizedTime as FreeIPA emits it for
// sudoNotBefore/sudoNotAfter — always UTC ("Z" suffix), no fractional
// seconds, per the live capture this was verified against.
const generalizedTimeLayout = "20060102150405Z"

func attrTimePtr(m map[string]any, key string) (*time.Time, error) {
	s := attrString(m, key)
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(generalizedTimeLayout, s)
	if err != nil {
		return nil, fmt.Errorf("parse %s %q: %w", key, s, err)
	}
	t = t.UTC()
	return &t, nil
}

func parsePing(env rpcEnvelope) (PingResult, error) {
	var r struct {
		Summary string `json:"summary"`
	}
	if err := json.Unmarshal(env.Result, &r); err != nil {
		return PingResult{}, fmt.Errorf("decode ping result: %w", err)
	}
	return PingResult{ServerVersion: r.Summary}, nil
}

func parseUser(m map[string]any) User {
	return User{
		Username:       attrString(m, "uid"),
		Enabled:        !attrBool(m, "nsaccountlock", false),
		DirectGroups:   attrStrings(m, "memberof_group"),
		IndirectGroups: attrStrings(m, "memberofindirect_group"),
	}
}

func parseGroup(m map[string]any) Group {
	return Group{
		Name:         attrString(m, "cn"),
		MemberUsers:  attrStrings(m, "member_user"),
		MemberGroups: attrStrings(m, "member_group"),
	}
}

func parseHost(m map[string]any) Host {
	return Host{
		FQDN:        attrString(m, "fqdn"),
		Annotations: parseAnnotations(attrStrings(m, "userclass")),
	}
}

func parseHostgroup(m map[string]any) Hostgroup {
	return Hostgroup{
		Name:                attrString(m, "cn"),
		MemberHosts:         attrStrings(m, "member_host"),
		MemberHostgroups:    attrStrings(m, "member_hostgroup"),
		IndirectMemberHosts: attrStrings(m, "memberindirect_host"),
	}
}

func parseHBACRule(m map[string]any) HBACRule {
	return HBACRule{
		Name:               attrString(m, "cn"),
		Enabled:            attrBool(m, "ipaenabledflag", false),
		UserCategoryAll:    attrCategoryAll(m, "usercategory"),
		Users:              attrStrings(m, "memberuser_user"),
		Groups:             attrStrings(m, "memberuser_group"),
		HostCategoryAll:    attrCategoryAll(m, "hostcategory"),
		Hosts:              attrStrings(m, "memberhost_host"),
		Hostgroups:         attrStrings(m, "memberhost_hostgroup"),
		ServiceCategoryAll: attrCategoryAll(m, "servicecategory"),
		Services:           attrStrings(m, "memberservice_hbacsvc"),
		ServiceGroups:      attrStrings(m, "memberservice_hbacsvcgroup"),
	}
}

func parseHBACServiceGroup(m map[string]any) HBACServiceGroup {
	return HBACServiceGroup{
		Name:     attrString(m, "cn"),
		Services: attrStrings(m, "member_hbacsvc"),
	}
}

func parseSudoRule(m map[string]any) (SudoRule, error) {
	notBefore, err := attrTimePtr(m, "sudonotbefore")
	if err != nil {
		return SudoRule{}, err
	}
	notAfter, err := attrTimePtr(m, "sudonotafter")
	if err != nil {
		return SudoRule{}, err
	}
	return SudoRule{
		Name:               attrString(m, "cn"),
		Enabled:            attrBool(m, "ipaenabledflag", false),
		UserCategoryAll:    attrCategoryAll(m, "usercategory"),
		Users:              attrStrings(m, "memberuser_user"),
		Groups:             attrStrings(m, "memberuser_group"),
		HostCategoryAll:    attrCategoryAll(m, "hostcategory"),
		Hosts:              attrStrings(m, "memberhost_host"),
		Hostgroups:         attrStrings(m, "memberhost_hostgroup"),
		CommandCategoryAll: attrCategoryAll(m, "cmdcategory"),
		AllowCommands:      attrStrings(m, "memberallowcmd_sudocmd"),
		AllowCommandGroups: attrStrings(m, "memberallowcmd_sudocmdgroup"),
		DenyCommands:       attrStrings(m, "memberdenycmd_sudocmd"),
		DenyCommandGroups:  attrStrings(m, "memberdenycmd_sudocmdgroup"),
		NotBefore:          notBefore,
		NotAfter:           notAfter,
	}, nil
}

func parseSudoCommand(m map[string]any) SudoCommand {
	return SudoCommand{Command: attrString(m, "sudocmd")}
}

func parseSudoCommandGroup(m map[string]any) SudoCommandGroup {
	return SudoCommandGroup{
		Name:     attrString(m, "cn"),
		Commands: attrStrings(m, "member_sudocmd"),
	}
}

func parseHBACTest(env rpcEnvelope) (HBACTestResult, error) {
	// hbactest's result is NOT wrapped in an inner "result" key the way
	// *_show/*_find are — env.Result decodes directly into this shape.
	var r struct {
		Matched []string `json:"matched"`
		Value   bool     `json:"value"`
	}
	if err := json.Unmarshal(env.Result, &r); err != nil {
		return HBACTestResult{}, fmt.Errorf("decode hbactest result: %w", err)
	}
	return HBACTestResult{Access: r.Value, Matched: r.Matched}, nil
}
