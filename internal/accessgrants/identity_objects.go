package accessgrants

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// IdentityObject is the credential-free projection of an apply-normalized
// user/group or an observed FreeIPA object. Attributes use FreeIPA RPC names.
type IdentityObject struct {
	Name          string              `json:"name"`
	State         string              `json:"state,omitempty"`
	Enabled       bool                `json:"enabled"`
	Attributes    map[string][]string `json:"attributes"`
	KeyHashes     *[]string           `json:"key_hashes,omitempty"`
	Users         []string            `json:"users,omitempty"`
	Groups        []string            `json:"groups,omitempty"`
	Authoritative bool                `json:"authoritative"`
}

// IdentityObjects is a complete users/groups read paired with the same
// normalized desired objects apply consumes. It never contains credentials.
type IdentityObjects struct {
	SchemaVersion int              `json:"schema_version"`
	DesiredUsers  []IdentityObject `json:"desired_users"`
	DesiredGroups []IdentityObject `json:"desired_groups"`
	LiveUsers     []IdentityObject `json:"live_users"`
	LiveGroups    []IdentityObject `json:"live_groups"`
}

// ComputeIdentityObjectDrift describes only operations implemented by apply.
// It uses direct group members, never a user's transitive memberof_group.
func ComputeIdentityObjectDrift(snapshot IdentityObjects) ([]DriftItem, error) {
	if snapshot.SchemaVersion != 1 {
		return nil, fmt.Errorf("accessgrants: unsupported identity object snapshot")
	}
	if snapshot.DesiredUsers == nil || snapshot.DesiredGroups == nil || snapshot.LiveUsers == nil || snapshot.LiveGroups == nil {
		return nil, fmt.Errorf("accessgrants: incomplete identity object snapshot")
	}
	items := []DriftItem{}
	for _, kind := range []struct {
		name       string
		want, live []IdentityObject
	}{
		{"user", snapshot.DesiredUsers, snapshot.LiveUsers},
		{"group", snapshot.DesiredGroups, snapshot.LiveGroups},
	} {
		index := map[string]IdentityObject{}
		for _, object := range kind.live {
			name := strings.ToLower(object.Name)
			if name == "" {
				return nil, fmt.Errorf("accessgrants: unnamed live identity object")
			}
			if _, ok := index[name]; ok {
				return nil, fmt.Errorf("accessgrants: duplicate live identity object")
			}
			index[name] = object
		}
		managed := map[string]bool{}
		for _, want := range kind.want {
			name := strings.ToLower(want.Name)
			if name == "" || managed[name] {
				return nil, fmt.Errorf("accessgrants: invalid desired identity object")
			}
			managed[name] = true
			got, exists := index[name]
			add := func(category, action, detail string) {
				items = append(items, DriftItem{Category: kind.name + "_" + category, Name: name, Action: action, Detail: detail})
			}
			if want.State == "absent" {
				if exists {
					add("should_be_absent", "delete", "explicitly absent managed object exists live")
				}
				continue
			}
			if !exists {
				add("missing", "create", "managed object does not exist live")
				// Membership/attribute updates on the new object are included in create.
				continue
			}
			for field, values := range want.Attributes {
				if !slices.Contains([]string{"givenname", "sn", "displayname", "mail", "uidnumber", "gidnumber", "loginshell", "homedirectory", "description"}, field) {
					return nil, fmt.Errorf("accessgrants: unsupported identity attribute")
				}
				// Report the field name only: values may be user-controlled text.
				if !slices.Equal(sortedUnique(values, false), sortedUnique(got.Attributes[field], false)) {
					add("attribute", "update", "managed attribute differs: "+field)
				}
			}
			if kind.name == "user" {
				if want.Enabled != got.Enabled {
					add("enabled", "update", "account enabled state differs")
				}
				if want.KeyHashes != nil {
					if got.KeyHashes == nil {
						return nil, fmt.Errorf("accessgrants: missing live SSH key observation")
					}
					if !slices.Equal(sortedUnique(*want.KeyHashes, false), sortedUnique(*got.KeyHashes, false)) {
						add("ssh_keys", "update", fmt.Sprintf("SSH public key set differs (desired=%d, live=%d)", len(*want.KeyHashes), len(*got.KeyHashes)))
					}
				}
				continue
			}
			for _, members := range []struct {
				name      string
				want, got []string
			}{
				{"user", want.Users, got.Users}, {"group", want.Groups, got.Groups},
			} {
				w, g := sortedUnique(members.want, true), sortedUnique(members.got, true)
				for _, member := range w {
					if !slices.Contains(g, member) {
						add("member_missing", "add_member", members.name+":"+member)
					}
				}
				for _, member := range g {
					if !slices.Contains(w, member) {
						if want.Authoritative {
							add("member_extra", "remove_member", members.name+":"+member)
						} else {
							add("member_unmanaged", "report", members.name+":"+member)
						}
					}
				}
			}
		}
		for name := range index {
			if !managed[name] {
				items = append(items, DriftItem{Category: kind.name + "_unexpected", Name: name, Action: "report", Detail: "object outside the roster; apply will not delete it"})
			}
		}
	}
	sortDriftItems(items)
	return items, nil
}

func sortedUnique(values []string, fold bool) []string {
	result := append([]string{}, values...)
	if fold {
		for i := range result {
			result[i] = strings.ToLower(result[i])
		}
	}
	sort.Strings(result)
	return slices.Compact(result)
}

func sortDriftItems(items []DriftItem) {
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Action != b.Action {
			return a.Action < b.Action
		}
		return a.Detail < b.Detail
	})
}
