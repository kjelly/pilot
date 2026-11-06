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
// through Ansible's own coercions (spec §5.1): Go does not repeat them. A
// value of the wrong type is refused with its field and object, never read
// as "not declared": inventory.ValidateRoster reads such a value as absent
// (asMap returns nil) and lets the roster through.
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
	// The sections that name the login are refused when they are not
	// mappings, not ignored: `admin: bob` read as no admin section would log
	// in as the default admin instead of the account the roster names.
	fi, err := optionalMapping(root, "freeipa")
	if err != nil {
		return d, err
	}
	admin, err := optionalMapping(fi, "admin")
	if err != nil {
		return d, fmt.Errorf("freeipa.%w", err)
	}
	if p, present := admin["principal"]; present && p != nil {
		s, ok := p.(string)
		if !ok || s == "" {
			return d, fmt.Errorf("freeipa.admin.principal must be a string")
		}
		d.Principal = s
	}

	users, err := rosterEntries(root, "users")
	if err != nil {
		return d, err
	}
	for i, e := range users {
		where := fmt.Sprintf("users[%d] (%s)", i, e.name)
		state, err := stringOr(e.fields, "state", "present")
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		if state == "absent" {
			if err := refuseWrongShapes(e.fields, "password", "ssh_keys"); err != nil {
				return d, fmt.Errorf("%s: %w", where, err)
			}
			d.AbsentUsers = append(d.AbsentUsers, e.name)
			continue
		}
		du, err := desiredUser(e.fields, e.name, state)
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		d.Users = append(d.Users, du)
	}
	groups, err := rosterEntries(root, "groups")
	if err != nil {
		return d, err
	}
	for i, e := range groups {
		where := fmt.Sprintf("groups[%d] (%s)", i, e.name)
		state, err := stringOr(e.fields, "state", "present")
		if err != nil {
			return d, fmt.Errorf("%s: %w", where, err)
		}
		if state == "absent" {
			if err := refuseWrongShapes(e.fields, "membership"); err != nil {
				return d, fmt.Errorf("%s: %w", where, err)
			}
			d.AbsentGroups = append(d.AbsentGroups, e.name)
			continue
		}
		dg, err := desiredGroup(e.fields, e.name)
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
	for _, e := range users {
		if e.fields["authentication"] != nil {
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
	// password, ssh_keys and (below) membership are refused when they are
	// present and not mappings, null included, not read as undeclared: for
	// membership that reading is "an authoritative group with no members",
	// which a writing engine turns into removing every direct member. The
	// message names the type, never the value: a password written as a string
	// must not reach an error.
	pw, err := declaredMapping(u, "password")
	if err != nil {
		return du, err
	}
	if initial, present := pw["initial"]; present && initial != nil {
		// The value is never loaded (a plan carries no password), but its
		// type is checked: a number, boolean or list is not a password, and
		// a Go engine that writes must not guess how Ansible would turn it
		// into one (spec §5.1: Go does not repeat Ansible's coercions).
		if _, ok := initial.(string); !ok {
			return du, fmt.Errorf("password: initial must be a string, not %T (quote the password so it stays a string)", initial)
		}
		du.HasInitialPassword = true
	}
	// A null inside these mappings is refused where Go would otherwise take
	// its own default for it (boolOr, nameList, ssh_keys.values below): the
	// playbook reads a null there as false, as a failure or as unmanaged, not
	// as the default. password.initial is the exception: a null initial is no
	// password in both engines.
	if du.PreserveExisting, err = boolOr(pw, "preserve_existing", true); err != nil {
		return du, fmt.Errorf("password: %w", err)
	}
	if _, err = boolOr(pw, "force_change", false); err != nil {
		return du, fmt.Errorf("password: %w", err)
	}
	keys, err := declaredMapping(u, "ssh_keys")
	if err != nil {
		return du, err
	}
	// inventory.ValidateRoster refuses a literal false, but its
	// boolFieldDefault answers the default for any value that is not a bool,
	// so a string passes it; the playbook runs `| bool` on the value.
	authoritative, err := boolOr(keys, "authoritative", true)
	if err != nil {
		return du, fmt.Errorf("ssh_keys: %w", err)
	}
	if !authoritative {
		return du, fmt.Errorf("ssh_keys: authoritative must be true: the declared keys replace the live set")
	}
	if values, present := keys["values"]; present {
		if values == nil {
			// Both engines leave the keys alone for a null (unmanaged, as if
			// absent), while `values: []` clears them: a stanza left empty
			// must not stand for either.
			return du, fmt.Errorf("ssh_keys: values must be a list, not null (leave it out, or write [] to clear every key)")
		}
		list, ok := values.([]any)
		if !ok {
			return du, fmt.Errorf("ssh_keys.values must be a list")
		}
		du.SSHKeys = []string{}
		for _, k := range list {
			// A value that is not a string is not a key: it is counted as
			// an invalid one and the plan blocks on it, not dropped.
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
	m, err := declaredMapping(g, "membership")
	if err != nil {
		return dg, err
	}
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

// nameList reads a list of names, lower-cased as FreeIPA stores them. Absent
// is not declared; null is an error, not "not declared".
func nameList(m map[string]any, key string) ([]string, bool, error) {
	raw, present := m[key]
	if !present {
		return nil, false, nil
	}
	if raw == nil {
		return nil, true, nullKeyError(key, "a list")
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

// stringOr, optionalString, boolOr and optionalID read a scalar of a roster
// object: absent is the default (or "not managed"), a present null is an
// error, never the default (nullKeyError), as is any other wrong type.
func stringOr(m map[string]any, key, def string) (string, error) {
	v, present := m[key]
	if !present {
		return def, nil
	}
	if v == nil {
		return "", nullKeyError(key, "a string")
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func optionalString(m map[string]any, key string) (*string, error) {
	v, present := m[key]
	if !present {
		return nil, nil
	}
	if v == nil {
		return nil, nullKeyError(key, "a string")
	}
	s, ok := v.(string)
	if !ok {
		return nil, fmt.Errorf("%s must be a string", key)
	}
	return &s, nil
}

// nullKeyError is the refusal of a key written without a value.
func nullKeyError(key, want string) error {
	return fmt.Errorf("%s must be %s, not null (leave it out, or give a value)", key, want)
}

func boolOr(m map[string]any, key string, def bool) (bool, error) {
	v, present := m[key]
	if !present {
		return def, nil
	}
	if v == nil {
		return false, nullKeyError(key, "true or false")
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be true or false (the Go engine does not apply Ansible's | bool coercion)", key)
	}
	return b, nil
}

func optionalID(m map[string]any, key string) (*int64, error) {
	v, present := m[key]
	if !present {
		return nil, nil
	}
	if v == nil {
		return nil, nullKeyError(key, "a non-negative integer")
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

// rosterEntry is one element of the roster's users or groups list: a mapping
// with a string name.
type rosterEntry struct {
	fields map[string]any
	name   string
}

// rosterEntries is root[key] (users or groups) as its entries: absent is an
// empty list; null, any other type, an element that is not a mapping and a
// name that is not a string are errors, not an object skipped or read with an
// empty name. inventory.ValidateRoster refuses the elements
// first (a name that does not match its pattern), but not a list of another
// type, and this must not depend on what the validator happens to refuse.
func rosterEntries(root map[string]any, key string) ([]rosterEntry, error) {
	raw, present := root[key]
	if !present {
		return nil, nil
	}
	if raw == nil {
		return nil, fmt.Errorf("%s must be a list, not null (leave it out, or write [])", key)
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list, not %T", key, raw)
	}
	out := make([]rosterEntry, 0, len(list))
	for i, item := range list {
		fields, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be a mapping, not %T", key, i, item)
		}
		name, ok := fields["name"].(string)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: name must be a string, not %T", key, i, fields["name"])
		}
		out = append(out, rosterEntry{fields: fields, name: name})
	}
	return out, nil
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

// refuseWrongShapes applies declaredMapping to the keys the playbook's gates
// call `.keys()` on for every entry of the list, a `state: absent` one too
// (the gates loop over all of them), and drops the result: only the shape of
// an entry that is not reconciled is checked, nothing inside it is read.
func refuseWrongShapes(fields map[string]any, keys ...string) error {
	for _, k := range keys {
		if _, err := declaredMapping(fields, k); err != nil {
			return err
		}
	}
	return nil
}

// declaredMapping is parent[key] as a mapping: absent is an empty one, null
// and any other type are errors. Unlike optionalMapping (which the login
// sections use, absent and null alike), a null here is refused because the
// playbook's gate on password, ssh_keys and membership,
// `(item.X | default({})).keys()`, fails on it (default() replaces an
// undefined value, not None; ansible-core 2.19.2): reading it as "not
// declared" would let a stanza left empty (`membership:`) act as an
// authoritative group with no members while the Ansible engine refuses the
// roster.
func declaredMapping(parent map[string]any, key string) (map[string]any, error) {
	raw, present := parent[key]
	if !present {
		return nil, nil
	}
	if raw == nil {
		return nil, fmt.Errorf("%s must be a mapping, not null (leave it out, or write {})", key)
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a mapping, not %T", key, raw)
	}
	return m, nil
}

// optionalMapping is parent[key] as a mapping: absent and null are an empty
// one, any other type is an error.
func optionalMapping(parent map[string]any, key string) (map[string]any, error) {
	raw, present := parent[key]
	if !present || raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a mapping, not %T", key, raw)
	}
	return m, nil
}
