// Package identityreconcile is the Go engine for FreeIPA identity
// reconcile: it turns a canonical roster into a desired state, reads the
// live state, and plans the operations between them. Phase 1 only plans
// (docs/superpowers/specs/2026-10-30-freeipa-go-reconcile-phase1-spec.md);
// nothing here writes to FreeIPA.
//
// Semantics follow playbooks/apply/freeipa-identity-apply.yml, the engine
// this one must agree with, not the design documents where they differ.
package identityreconcile

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// ScopeUsersGroups is the part of the roster this engine reconciles.
const ScopeUsersGroups = "users-groups"

// DesiredUser is one roster user that is not state: absent, with the
// playbook's defaults ("Normalize canonical users") filled in.
type DesiredUser struct {
	Name        string  // FreeIPA login (the validator allows lower case only)
	First       string  // givenname; defaults to Name
	Last        string  // sn; defaults to Name
	DisplayName *string // nil: not managed
	Email       *string // nil: not managed
	UID         *int64  // nil: not managed
	GID         *int64  // nil: not managed
	Shell       string  // defaults to /bin/bash
	Home        string  // defaults to /home/<name>
	Enabled     bool    // defaults to state != disabled

	// HasInitialPassword says password.initial is declared. The value
	// itself is never loaded: a plan does not carry passwords.
	HasInitialPassword bool
	PreserveExisting   bool // password.preserve_existing, default true

	// SSHKeys is the normalized ssh_keys.values; nil when not declared
	// (unmanaged). An empty, non-nil slice clears every key.
	SSHKeys []string
	// SSHKeysInvalid lists declared keys that do not parse.
	SSHKeysInvalid int
}

// DesiredGroup is one roster group that is not state: absent.
type DesiredGroup struct {
	Name          string // as written: the history marker hashes this
	Description   string // defaults to Name
	GID           *int64 // nil: not managed
	Type          string // posix (default), nonposix or external
	Authoritative bool   // membership.authoritative, default true
	Users         []string
	Groups        []string
	// MembersDeclared says membership.users or membership.groups is
	// written; an authoritative group without them loses every direct
	// member of that kind.
	UsersDeclared, GroupsDeclared bool
}

// Desired is the users/groups part of a canonical roster.
type Desired struct {
	SchemaVersion int
	Principal     string // freeipa.admin.principal, default admin
	Users         []DesiredUser
	Groups        []DesiredGroup
	AbsentUsers   []string
	AbsentGroups  []string
	// NotInScope lists the roster sections present that this engine
	// leaves to the playbook.
	NotInScope []string
}

// inScopeSections are the top-level roster keys this engine reads; every
// other non-empty key is left to the playbook (spec §5.3).
var inScopeSections = map[string]bool{"schema_version": true, "freeipa": true, "users": true, "groups": true, "migration": true}

// FromRoster builds the desired state from a roster that already passed
// inventory.ValidateRoster. It rejects what the playbook would read
// through Ansible's own coercions (spec §5.1): Go does not repeat them.
func FromRoster(root map[string]any) (Desired, error) {
	var d Desired
	rawVersion, ok := root["schema_version"]
	if !ok {
		return d, fmt.Errorf("the roster has no schema_version: the Go engine reads canonical rosters only; reconcile a legacy roster with the Ansible engine")
	}
	version, ok := wholeNumber(rawVersion)
	if !ok || version < 1 || version > int64(inventory.CurrentRosterSchemaVersion) {
		return d, fmt.Errorf("roster schema_version %v is not supported", rawVersion)
	}
	if violations := inventory.ValidateRoster(root); len(violations) > 0 {
		return d, fmt.Errorf("the roster is invalid: %s: %s", violations[0].Rule, violations[0].Detail)
	}
	d.SchemaVersion = int(version)
	d.Principal = "admin"
	if fi, ok := root["freeipa"].(map[string]any); ok {
		if admin, ok := fi["admin"].(map[string]any); ok {
			if p, present := admin["principal"]; present && p != nil {
				s, ok := p.(string)
				if !ok || s == "" {
					return d, fmt.Errorf("freeipa.admin.principal must be a string")
				}
				d.Principal = s
			}
		}
	}

	for i, raw := range listOf(root["users"]) {
		u, _ := raw.(map[string]any)
		name, _ := u["name"].(string)
		where := fmt.Sprintf("users[%d] (%s)", i, name)
		state, err := stringOr(u, "state", "present")
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		if state == "absent" {
			d.AbsentUsers = append(d.AbsentUsers, name)
			continue
		}
		du, err := desiredUser(u, name, state)
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		d.Users = append(d.Users, du)
	}
	for i, raw := range listOf(root["groups"]) {
		g, _ := raw.(map[string]any)
		name, _ := g["name"].(string)
		where := fmt.Sprintf("groups[%d] (%s)", i, name)
		state, err := stringOr(g, "state", "present")
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		if state == "absent" {
			d.AbsentGroups = append(d.AbsentGroups, name)
			continue
		}
		dg, err := desiredGroup(g, name)
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		d.Groups = append(d.Groups, dg)
	}
	for section, v := range root {
		if !inScopeSections[section] && !empty(v) {
			d.NotInScope = append(d.NotInScope, section)
		}
	}
	for _, u := range listOf(root["users"]) {
		if m, ok := u.(map[string]any); ok && m["authentication"] != nil {
			d.NotInScope = append(d.NotInScope, "users[].authentication")
			break
		}
	}
	sort.Strings(d.NotInScope)
	return d, nil
}

func desiredUser(u map[string]any, name, state string) (DesiredUser, error) {
	du := DesiredUser{Name: name, PreserveExisting: true}
	var err error
	if du.First, err = stringOr(u, "first", name); err != nil {
		return du, err
	}
	if du.Last, err = stringOr(u, "last", name); err != nil {
		return du, err
	}
	if du.DisplayName, err = optionalString(u, "display_name"); err != nil {
		return du, err
	}
	if du.Email, err = optionalString(u, "email"); err != nil {
		return du, err
	}
	if du.UID, err = optionalID(u, "uid"); err != nil {
		return du, err
	}
	if du.GID, err = optionalID(u, "gid"); err != nil {
		return du, err
	}
	if du.Shell, err = stringOr(u, "login_shell", "/bin/bash"); err != nil {
		return du, err
	}
	if du.Home, err = stringOr(u, "home_directory", "/home/"+name); err != nil {
		return du, err
	}
	if du.Enabled, err = boolOr(u, "enabled", state != "disabled"); err != nil {
		return du, err
	}
	if pw, ok := u["password"].(map[string]any); ok {
		du.HasInitialPassword = pw["initial"] != nil
		if du.PreserveExisting, err = boolOr(pw, "preserve_existing", true); err != nil {
			return du, fmt.Errorf("password: %w", err)
		}
		if _, err = boolOr(pw, "force_change", false); err != nil {
			return du, fmt.Errorf("password: %w", err)
		}
	}
	if keys, ok := u["ssh_keys"].(map[string]any); ok {
		if values, present := keys["values"]; present && values != nil {
			list, ok := values.([]any)
			if !ok {
				return du, fmt.Errorf("ssh_keys.values must be a list")
			}
			du.SSHKeys = []string{}
			for _, k := range list {
				s, _ := k.(string)
				norm, err := NormalizeSSHKey(s)
				if err != nil {
					du.SSHKeysInvalid++
					continue
				}
				du.SSHKeys = appendUnique(du.SSHKeys, norm)
			}
			sort.Strings(du.SSHKeys)
		}
	}
	return du, nil
}

func desiredGroup(g map[string]any, name string) (DesiredGroup, error) {
	dg := DesiredGroup{Name: name, Authoritative: true}
	var err error
	if dg.Description, err = stringOr(g, "description", name); err != nil {
		return dg, err
	}
	if dg.GID, err = optionalID(g, "gid"); err != nil {
		return dg, err
	}
	if dg.Type, err = stringOr(g, "type", "posix"); err != nil {
		return dg, err
	}
	m, _ := g["membership"].(map[string]any)
	if dg.Authoritative, err = boolOr(m, "authoritative", true); err != nil {
		return dg, fmt.Errorf("membership: %w", err)
	}
	if dg.Users, dg.UsersDeclared, err = nameList(m, "users"); err != nil {
		return dg, fmt.Errorf("membership: %w", err)
	}
	if dg.Groups, dg.GroupsDeclared, err = nameList(m, "groups"); err != nil {
		return dg, fmt.Errorf("membership: %w", err)
	}
	return dg, nil
}

// nameList reads a list of names, lower-cased as FreeIPA stores them.
func nameList(m map[string]any, key string) ([]string, bool, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return nil, false, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, true, fmt.Errorf("%s must be a list", key)
	}
	var out []string
	for _, v := range list {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, true, fmt.Errorf("%s must hold names", key)
		}
		out = appendUnique(out, strings.ToLower(s))
	}
	sort.Strings(out)
	return out, true, nil
}

func stringOr(m map[string]any, key, def string) (string, error) {
	v, present := m[key]
	if !present || v == nil {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func optionalString(m map[string]any, key string) (*string, error) {
	v, present := m[key]
	if !present || v == nil {
		return nil, nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a string", key)
	}
	return &s, nil
}

func boolOr(m map[string]any, key string, def bool) (bool, error) {
	v, present := m[key]
	if !present || v == nil {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be true or false (the Go engine does not apply Ansible's | bool coercion)", key)
	}
	return b, nil
}

func optionalID(m map[string]any, key string) (*int64, error) {
	v, present := m[key]
	if !present || v == nil {
		return nil, nil
	}
	n, ok := wholeNumber(v)
	if !ok || n < 0 {
		return nil, fmt.Errorf("%s must be a non-negative integer", key)
	}
	return &n, nil
}

// wholeNumber accepts the integer forms a YAML decoder produces.
func wholeNumber(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float64:
		if n != math.Trunc(n) || math.Abs(n) > 1<<53 {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}

func listOf(v any) []any {
	l, _ := v.([]any)
	return l
}

func empty(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case []any:
		return len(x) == 0
	case map[string]any:
		return len(x) == 0
	}
	return false
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}
