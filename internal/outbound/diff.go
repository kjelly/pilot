// diff.go implements design spec §14: the publication-state diff between
// a base authoritative snapshot and the current projection. Diff never
// compares local pre/post files (INV-5) — both arguments here are
// already-materialized UserHostAccessSnapshotV1 values; it is the
// caller's job (event.go/dispatcher.go, Phase 3-4) to supply the correct
// base (the last authoritative-ACKed publication snapshot, or the empty
// snapshot for a bootstrap diff).
package outbound

import (
	"reflect"
	"sort"
)

// Diff computes target's diff against base. When bootstrap is true, base
// is treated as conceptually absent: every target entity becomes an
// upsert, Delete is empty for every entity type, and BaseSnapshotID is
// left "" rather than the hash of whatever base happened to be passed
// (design spec §14.5) — callers should pass the zero
// UserHostAccessSnapshotV1{} for base in that case, though Diff does not
// require it.
func Diff(base, target UserHostAccessSnapshotV1, bootstrap bool) StateDiffV1 {
	baseCanon := CanonicalizeSnapshot(base)
	targetCanon := CanonicalizeSnapshot(target)

	d := StateDiffV1{
		TargetSnapshotID: SnapshotID(targetCanon),
		Bootstrap:        bootstrap,
	}
	if !bootstrap {
		d.BaseSnapshotID = SnapshotID(baseCanon)
	}

	if bootstrap {
		baseCanon = UserHostAccessSnapshotV1{}
	}

	d.Hosts = diffEntities(baseCanon.Hosts, targetCanon.Hosts, func(h ProjectedHost) string { return h.ID })
	d.Users = diffEntities(baseCanon.Users, targetCanon.Users, func(u ProjectedUser) string { return u.Name })
	d.Groups = diffEntities(baseCanon.Groups, targetCanon.Groups, func(g ProjectedGroup) string { return g.Name })
	d.Hostgroups = diffEntities(baseCanon.Hostgroups, targetCanon.Hostgroups, func(hg ProjectedHostgroup) string { return hg.Name })
	d.LoginAccess = diffEntities(baseCanon.Access.Login, targetCanon.Access.Login, func(l ProjectedLoginAccess) string { return l.ID })
	d.SudoAccess = diffEntities(baseCanon.Access.Sudo, targetCanon.Access.Sudo, func(s ProjectedSudoAccess) string { return s.ID })
	return d
}

// diffEntities compares base and target entity lists by a stable key,
// returning every target entity that is new or changed as an upsert
// (always the full entity, never a JSON Patch — design spec §14.3) and
// every base-only key as a delete. target is assumed already sorted by
// key (CanonicalizeSnapshot guarantees this), so Upsert order is
// deterministic without a second sort here.
func diffEntities[T any](base, target []T, key func(T) string) EntityDiff[T] {
	baseByKey := make(map[string]T, len(base))
	for _, b := range base {
		baseByKey[key(b)] = b
	}
	targetKeys := make(map[string]bool, len(target))

	upsert := []T{}
	for _, t := range target {
		k := key(t)
		targetKeys[k] = true
		if b, ok := baseByKey[k]; !ok || !reflect.DeepEqual(b, t) {
			upsert = append(upsert, t)
		}
	}

	del := []string{}
	for k := range baseByKey {
		if !targetKeys[k] {
			del = append(del, k)
		}
	}
	sort.Strings(del)

	return EntityDiff[T]{Upsert: upsert, Delete: del}
}
