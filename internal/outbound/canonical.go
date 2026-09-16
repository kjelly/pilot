// canonical.go implements design spec §13: a deterministic canonical
// form for UserHostAccessSnapshotV1 and the sha256 snapshot ID derived
// from it. The hash input is semantic state only — no generated_at,
// event_id, workflow_id, delivery outcome, or webhook name — so the same
// declared state always hashes the same, regardless of which operation
// or webhook produced it.
package outbound

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

func sortedOrEmpty(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// CanonicalizeSnapshot returns a copy of in with every collection
// sorted and every non-omitempty nil slice replaced by an empty one, so
// two semantically-identical snapshots always marshal to byte-identical
// JSON (design spec §13.2). It never mutates in.
func CanonicalizeSnapshot(in UserHostAccessSnapshotV1) UserHostAccessSnapshotV1 {
	out := UserHostAccessSnapshotV1{
		Hosts:      make([]ProjectedHost, len(in.Hosts)),
		Users:      make([]ProjectedUser, len(in.Users)),
		Groups:     make([]ProjectedGroup, len(in.Groups)),
		Hostgroups: make([]ProjectedHostgroup, len(in.Hostgroups)),
	}
	for i, h := range in.Hosts {
		h.Roles = sortedOrEmpty(h.Roles)
		out.Hosts[i] = h
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].ID < out.Hosts[j].ID })

	for i, u := range in.Users {
		u.EffectiveGroups = sortedOrEmpty(u.EffectiveGroups)
		out.Users[i] = u
	}
	sort.Slice(out.Users, func(i, j int) bool { return out.Users[i].Name < out.Users[j].Name })

	for i, g := range in.Groups {
		g.Users = sortedOrEmpty(g.Users)
		g.Groups = sortedOrEmpty(g.Groups)
		out.Groups[i] = g
	}
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].Name < out.Groups[j].Name })

	for i, hg := range in.Hostgroups {
		hg.HostIDs = sortedOrEmpty(hg.HostIDs)
		hg.Hostgroups = sortedOrEmpty(hg.Hostgroups)
		hg.EffectiveHostIDs = sortedOrEmpty(hg.EffectiveHostIDs)
		out.Hostgroups[i] = hg
	}
	sort.Slice(out.Hostgroups, func(i, j int) bool { return out.Hostgroups[i].Name < out.Hostgroups[j].Name })

	out.Access.Login = make([]ProjectedLoginAccess, len(in.Access.Login))
	for i, a := range in.Access.Login {
		a.Users = sortedOrEmpty(a.Users)
		a.Services = sortedOrEmpty(a.Services)
		if !a.AllHosts {
			a.HostIDs = sortedOrEmpty(a.HostIDs)
		} else {
			a.HostIDs = nil
		}
		if a.ValidUntil != nil {
			utc := a.ValidUntil.UTC()
			a.ValidUntil = &utc
		}
		out.Access.Login[i] = a
	}
	sort.Slice(out.Access.Login, func(i, j int) bool { return out.Access.Login[i].ID < out.Access.Login[j].ID })

	out.Access.Sudo = make([]ProjectedSudoAccess, len(in.Access.Sudo))
	for i, a := range in.Access.Sudo {
		a.Users = sortedOrEmpty(a.Users)
		a.RunAsUsers = sortedOrEmpty(a.RunAsUsers)
		a.RunAsGroups = sortedOrEmpty(a.RunAsGroups)
		a.Options = sortedOrEmpty(a.Options)
		if !a.AllHosts {
			a.HostIDs = sortedOrEmpty(a.HostIDs)
		} else {
			a.HostIDs = nil
		}
		if !a.AllCommands {
			a.Commands = sortedOrEmpty(a.Commands)
		} else {
			a.Commands = nil
		}
		a.DeniedCommands = sortedOrEmpty(a.DeniedCommands)
		if a.ValidNotBefore != nil {
			utc := a.ValidNotBefore.UTC()
			a.ValidNotBefore = &utc
		}
		if a.ValidNotAfter != nil {
			utc := a.ValidNotAfter.UTC()
			a.ValidNotAfter = &utc
		}
		out.Access.Sudo[i] = a
	}
	sort.Slice(out.Access.Sudo, func(i, j int) bool { return out.Access.Sudo[i].ID < out.Access.Sudo[j].ID })

	return out
}

// SnapshotID returns the deterministic "sha256:<hex>" identifier for a
// snapshot's semantic state (design spec §13.1). Callers SHOULD pass an
// already-canonicalized snapshot; SnapshotID canonicalizes again
// internally so a caller can never forget the step and get a
// non-deterministic ID.
func SnapshotID(in UserHostAccessSnapshotV1) string {
	canon := CanonicalizeSnapshot(in)
	// encoding/json sorts map keys and preserves struct field declaration
	// order, both required for byte-identical output across runs.
	body, err := json.Marshal(canon)
	if err != nil {
		// canon contains only JSON-safe types (strings, bools, ints,
		// slices, maps, *time.Time) — Marshal cannot fail here.
		panic("outbound: snapshot canonicalization produced unmarshalable JSON: " + err.Error())
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}
