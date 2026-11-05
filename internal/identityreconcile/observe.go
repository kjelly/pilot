package identityreconcile

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// Finder runs one *_find command and returns every entry, failing on a
// truncated or incomplete answer (freeiparpc.Client.Find).
type Finder interface {
	Find(ctx context.Context, method string, args []any, opts map[string]any) ([]map[string]any, error)
}

// Observation is the live users and groups a plan is built from.
type Observation struct {
	Users  []LiveUser // active and preserved (LiveUser.Preserved)
	Groups []LiveGroup
}

// Observe reads every user, the preserved users and every group with
// all: true (spec §6.2), and checks that principal may read them fully:
// the reader must belong to admins (D7), since what other readers are
// shown has not been captured and a field a reader cannot see would look
// like an empty one.
func Observe(ctx context.Context, f Finder, principal string) (Observation, error) {
	var obs Observation
	raw, err := f.Find(ctx, "user_find", nil, map[string]any{"all": true})
	if err != nil {
		return obs, fmt.Errorf("read users: %w", err) // gate: observe-users-read
	}
	if obs.Users, err = ParseUsers(raw); err != nil {
		return obs, err // gate: observe-users-parse
	}
	reader := strings.ToLower(principal)
	i := slices.IndexFunc(obs.Users, func(u LiveUser) bool { return u.Name == reader })
	if i < 0 {
		return obs, fmt.Errorf("the login %q is not among the users FreeIPA returned; the Go engine needs an admins member to read the whole directory", principal) // gate: observe-reader-absent
	}
	if !slices.Contains(obs.Users[i].MemberOf, "admins") {
		return obs, fmt.Errorf("the login %q is not a member of admins; the Go engine reads with an admins member only, since what other readers see has not been verified", principal) // gate: observe-reader-not-admin
	}
	raw, err = f.Find(ctx, "user_find", nil, map[string]any{"all": true, "preserved": true})
	if err != nil {
		return obs, fmt.Errorf("read preserved users: %w", err) // gate: observe-preserved-read
	}
	preserved, err := ParseUsers(raw)
	if err != nil {
		return obs, err // gate: observe-preserved-parse
	}
	for _, p := range preserved {
		if !p.Preserved {
			continue
		}
		if j := slices.IndexFunc(obs.Users, func(u LiveUser) bool { return u.Name == p.Name }); j >= 0 {
			obs.Users[j].Preserved = true
			continue
		}
		obs.Users = append(obs.Users, p)
	}
	raw, err = f.Find(ctx, "group_find", nil, map[string]any{"all": true})
	if err != nil {
		return obs, fmt.Errorf("read groups: %w", err) // gate: observe-groups-read
	}
	if obs.Groups, err = ParseGroups(raw); err != nil {
		return obs, err // gate: observe-groups-parse
	}
	return obs, nil
}
