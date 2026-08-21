// roster_references.go implements the inbound-reference scanner spec.md
// §13 requires for `pilot roster remove-user`/`remove-group`: every roster
// location that names a user or group is enumerated here, classified as
// cascadeable (a list membership --cascade-references may prune) or
// blocked (a required scalar field — e.g. an NFS share's ownership.group —
// that must be reassigned by hand instead of ever being auto-removed).
package inventory

import (
	"fmt"
	"sort"
)

// RosterReferenceCascade classifies whether --cascade-references may
// remove a given RosterReference automatically.
type RosterReferenceCascade string

const (
	RosterReferenceCascadeRemovable RosterReferenceCascade = "removable"
	RosterReferenceCascadeBlocked   RosterReferenceCascade = "blocked"
)

// RosterReference is one inbound reference to the user/group a remove
// command was asked to hard-remove.
type RosterReference struct {
	Kind        string
	Path        string
	Cascade     RosterReferenceCascade
	Explanation string
}

// RosterUserReferences returns every inbound reference to username found
// anywhere in root (an already-parsed roster document — see
// readRosterAsMap). Every user reference is a list membership, so every
// result is RosterReferenceCascadeRemovable — see spec.md §13.1.
func RosterUserReferences(root map[string]any, username string) []RosterReference {
	var out []RosterReference

	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		if contains(stringListField(mapField(g, "membership"), "users"), username) {
			out = append(out, RosterReference{
				Kind:    "group membership",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("groups[%s].membership.users", stringField(g, "name")),
			})
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		r := asMap(raw)
		if contains(stringListField(mapField(r, "subjects"), "users"), username) {
			out = append(out, RosterReference{
				Kind:    "hbac subject",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("hbac.rules[%s].subjects.users", stringField(r, "name")),
			})
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		r := asMap(raw)
		if contains(stringListField(mapField(r, "subjects"), "users"), username) {
			out = append(out, RosterReference{
				Kind:    "sudo subject",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("sudo.rules[%s].subjects.users", stringField(r, "name")),
			})
		}
	}
	for _, raw := range listField(root, "netgroups") {
		ng := asMap(raw)
		if contains(stringListField(mapField(ng, "membership"), "users"), username) {
			out = append(out, RosterReference{
				Kind:    "netgroup membership",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("netgroups[%s].membership.users", stringField(ng, "name")),
			})
		}
	}

	sortRosterReferences(out)
	return out
}

// RosterGroupReferences is RosterUserReferences' group counterpart. Most
// group references are list memberships (cascadeable); an NFS share's
// ownership.group is a required scalar and is always
// RosterReferenceCascadeBlocked — see spec.md §13.2/§13.3.
func RosterGroupReferences(root map[string]any, groupname string) []RosterReference {
	var out []RosterReference

	for _, raw := range listField(root, "groups") {
		g := asMap(raw)
		if contains(stringListField(mapField(g, "membership"), "groups"), groupname) {
			out = append(out, RosterReference{
				Kind:    "group membership",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("groups[%s].membership.groups", stringField(g, "name")),
			})
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		r := asMap(raw)
		if contains(stringListField(mapField(r, "subjects"), "groups"), groupname) {
			out = append(out, RosterReference{
				Kind:    "hbac subject",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("hbac.rules[%s].subjects.groups", stringField(r, "name")),
			})
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		r := asMap(raw)
		label := stringField(r, "name")
		if contains(stringListField(mapField(r, "subjects"), "groups"), groupname) {
			out = append(out, RosterReference{
				Kind:    "sudo subject",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("sudo.rules[%s].subjects.groups", label),
			})
		}
		if contains(stringListField(mapField(r, "run_as"), "groups"), groupname) {
			out = append(out, RosterReference{
				Kind:    "sudo run_as",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("sudo.rules[%s].run_as.groups", label),
			})
		}
	}
	for _, raw := range listField(root, "netgroups") {
		ng := asMap(raw)
		if contains(stringListField(mapField(ng, "membership"), "groups"), groupname) {
			out = append(out, RosterReference{
				Kind:    "netgroup membership",
				Cascade: RosterReferenceCascadeRemovable,
				Path:    fmt.Sprintf("netgroups[%s].membership.groups", stringField(ng, "name")),
			})
		}
	}

	for _, rawServer := range listField(mapField(root, "nfs"), "servers") {
		server := asMap(rawServer)
		serverLabel := stringField(server, "host")
		for _, rawShare := range listField(server, "shares") {
			share := asMap(rawShare)
			shareLabel := labelOf(share)

			if stringField(mapField(share, "ownership"), "group") == groupname {
				out = append(out, RosterReference{
					Kind:        "nfs ownership",
					Cascade:     RosterReferenceCascadeBlocked,
					Path:        fmt.Sprintf("nfs.servers[%s].shares[%s].ownership.group", serverLabel, shareLabel),
					Explanation: "required scalar reference — reassign the owning group explicitly before removing this roster group",
				})
			}

			acl := mapField(share, "acl")
			for _, section := range []string{"access", "default"} {
				for _, rawNamedGroup := range listField(mapField(acl, section), "named_groups") {
					if stringField(asMap(rawNamedGroup), "name") == groupname {
						out = append(out, RosterReference{
							Kind:    "nfs acl named_group",
							Cascade: RosterReferenceCascadeRemovable,
							Path:    fmt.Sprintf("nfs.servers[%s].shares[%s].acl.%s.named_groups[%s]", serverLabel, shareLabel, section, groupname),
						})
					}
				}
			}
		}
	}

	sortRosterReferences(out)
	return out
}

func sortRosterReferences(refs []RosterReference) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].Path < refs[j].Path })
}
