package identityreconcile

import (
	"fmt"
	"sort"
	"strings"
)

// LiveUser is one FreeIPA user as user_find --all reports it (captured:
// internal/freeiparpc/testdata/user-find-states.json).
type LiveUser struct {
	Name          string // uid, lower case
	First         string // givenname
	Last          string // sn
	DisplayName   string
	Mail          []string
	UIDNumber     string
	GIDNumber     string
	Shell         string
	Home          string
	Locked        bool   // nsaccountlock
	LastPwdChange string // krblastpwdchange, "" when absent
	PwdExpiration string // krbpasswordexpiration, "" when absent
	SSHKeys       []string
	SSHKeysBad    int      // live keys that do not normalize
	MemberOf      []string // memberof_group: transitive, never direct
	Preserved     bool
}

// Group types as the planner compares them.
const (
	TypePosix        = "posix"
	TypeNonPosix     = "nonposix"
	TypeUnrecognized = "unrecognized"
)

// LiveGroup is one FreeIPA group as group_find --all reports it (captured:
// group-find-states.json, group-find-nested.json).
type LiveGroup struct {
	Name         string // cn, lower case
	Description  []string
	GIDNumber    string
	Type         string
	MemberUsers  []string // direct only (member_user)
	MemberGroups []string // direct only (member_group)
}

// nonPosixClasses is the captured object class set of a non-POSIX group;
// a POSIX group adds posixgroup and may add ipantgroupattrs. Anything
// else (external groups among them, not yet captured) is unrecognized.
var (
	nonPosixClasses = []string{"top", "groupofnames", "nestedgroup", "ipausergroup", "ipaobject"}
	posixExtra      = map[string]bool{"posixgroup": true, "ipantgroupattrs": true}
)

// ParseUsers decodes user_find --all entries. A value of an unexpected
// shape is an error: an unknown field is not an empty one.
func ParseUsers(entries []map[string]any) ([]LiveUser, error) {
	out := make([]LiveUser, 0, len(entries))
	for i, e := range entries {
		u, err := parseUser(e)
		if err != nil {
			return nil, fmt.Errorf("user_find entry %d: %w", i, err)
		}
		out = append(out, u)
	}
	return out, nil
}

func parseUser(e map[string]any) (LiveUser, error) {
	var u LiveUser
	var err error
	name, err := single(e, "uid", true)
	if err != nil {
		return u, err
	}
	u.Name = strings.ToLower(name)
	for _, f := range []struct {
		key string
		dst *string
	}{
		{"givenname", &u.First}, {"sn", &u.Last}, {"displayname", &u.DisplayName},
		{"uidnumber", &u.UIDNumber}, {"gidnumber", &u.GIDNumber},
		{"loginshell", &u.Shell}, {"homedirectory", &u.Home},
	} {
		if *f.dst, err = single(e, f.key, false); err != nil {
			return u, fmt.Errorf("%s: %w", u.Name, err)
		}
	}
	if u.Mail, err = strs(e, "mail"); err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	if u.MemberOf, err = strs(e, "memberof_group"); err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	if u.Locked, err = boolean(e, "nsaccountlock"); err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	if u.Preserved, err = boolean(e, "preserved"); err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	if u.LastPwdChange, err = datetime(e, "krblastpwdchange"); err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	if u.PwdExpiration, err = datetime(e, "krbpasswordexpiration"); err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	keys, err := strs(e, "ipasshpubkey")
	if err != nil {
		return u, fmt.Errorf("%s: %w", u.Name, err)
	}
	for _, k := range keys {
		norm, kerr := NormalizeSSHKey(k)
		if kerr != nil {
			u.SSHKeysBad++
			continue
		}
		u.SSHKeys = appendUnique(u.SSHKeys, norm)
	}
	sort.Strings(u.SSHKeys)
	return u, nil
}

// ParseGroups decodes group_find --all entries.
func ParseGroups(entries []map[string]any) ([]LiveGroup, error) {
	out := make([]LiveGroup, 0, len(entries))
	for i, e := range entries {
		var g LiveGroup
		name, err := single(e, "cn", true)
		if err != nil {
			return nil, fmt.Errorf("group_find entry %d: %w", i, err)
		}
		g.Name = strings.ToLower(name)
		if g.Description, err = strs(e, "description"); err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		if g.GIDNumber, err = single(e, "gidnumber", false); err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		classes, err := strs(e, "objectclass")
		if err != nil || len(classes) == 0 {
			return nil, fmt.Errorf("group %s: objectclass missing (find without all: true?)", g.Name)
		}
		g.Type = groupType(classes)
		if g.MemberUsers, err = lowerList(e, "member_user"); err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		if g.MemberGroups, err = lowerList(e, "member_group"); err != nil {
			return nil, fmt.Errorf("group %s: %w", g.Name, err)
		}
		out = append(out, g)
	}
	return out, nil
}

func groupType(classes []string) string {
	have := map[string]bool{}
	for _, c := range classes {
		have[strings.ToLower(c)] = true
	}
	for _, c := range nonPosixClasses {
		if !have[c] {
			return TypeUnrecognized
		}
		delete(have, c)
	}
	if len(have) == 0 {
		return TypeNonPosix
	}
	if !have["posixgroup"] {
		return TypeUnrecognized
	}
	for c := range have {
		if !posixExtra[c] {
			return TypeUnrecognized
		}
	}
	return TypePosix
}

// strs reads a list of strings; absent is nil.
func strs(e map[string]any, key string) ([]string, error) {
	v, present := e[key]
	if !present {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a list", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s holds a non-string value", key)
		}
		out = append(out, s)
	}
	return out, nil
}

func lowerList(e map[string]any, key string) ([]string, error) {
	list, err := strs(e, key)
	var out []string
	for _, s := range list {
		out = appendUnique(out, strings.ToLower(s))
	}
	sort.Strings(out)
	return out, err
}

// single reads a one-value list; absent is "" unless required.
func single(e map[string]any, key string, required bool) (string, error) {
	list, err := strs(e, key)
	if err != nil {
		return "", err
	}
	switch {
	case len(list) == 0 && required:
		return "", fmt.Errorf("%s is missing", key)
	case len(list) == 0:
		return "", nil
	case len(list) > 1:
		return "", fmt.Errorf("%s has %d values, want one", key, len(list))
	}
	return list[0], nil
}

// boolean reads a field user_find --all always carries as a JSON boolean.
func boolean(e map[string]any, key string) (bool, error) {
	b, ok := e[key].(bool)
	if !ok {
		return false, fmt.Errorf("%s is missing or not a boolean", key)
	}
	return b, nil
}

// datetime reads a [{"__datetime__": "YYYYMMDDHHMMSSZ"}] value; absent is "".
func datetime(e map[string]any, key string) (string, error) {
	v, present := e[key]
	if !present {
		return "", nil
	}
	list, ok := v.([]any)
	if !ok || len(list) != 1 {
		return "", fmt.Errorf("%s is not a one-value list", key)
	}
	m, ok := list[0].(map[string]any)
	if !ok {
		return "", fmt.Errorf("%s is not a datetime", key)
	}
	s, ok := m["__datetime__"].(string)
	if !ok || len(s) != len("YYYYMMDDHHMMSSZ") || !strings.HasSuffix(s, "Z") {
		return "", fmt.Errorf("%s is not a YYYYMMDDHHMMSSZ datetime", key)
	}
	return s, nil
}
