package inventory

import "fmt"

// RosterDanglingHostReferenceWarnings returns one warning for each
// hostgroup/netgroup membership or HBAC/sudo rule target that names a
// host with no present roster hosts: entry — the same referential-
// integrity condition internal/outbound/projection.go's BuildProjection
// fails an entire outbound webhook snapshot closed over (design spec
// §11.4), surfaced here instead as a non-blocking lint warning so an
// operator sees it while editing the roster rather than discovering it
// only when a webhook silently stops carrying state. A host entry with
// state: absent does not count as present — a reference to a
// decommissioned host is exactly as dangling as a reference to a host
// that was never declared at all. Callers should only call this on a
// roster that has already passed ValidateRoster; it does not itself
// re-run structural validation.
func RosterDanglingHostReferenceWarnings(root map[string]any) []RosterWarning {
	present := map[string]bool{}
	for _, raw := range listField(root, "hosts") {
		h := asMap(raw)
		if stateOrDefault(h, "present") != "present" {
			continue
		}
		if name := stringField(h, "name"); name != "" {
			present[name] = true
		}
	}

	var out []RosterWarning
	check := func(location string, hosts []string) {
		for _, host := range hosts {
			if present[host] {
				continue
			}
			out = append(out, RosterWarning{
				Rule:   "dangling host reference",
				Detail: fmt.Sprintf("%s references %q, which has no present roster hosts: entry — outbound webhook snapshots will fail closed until it is added (or the reference removed)", location, host),
			})
		}
	}

	for _, raw := range listField(root, "hostgroups") {
		hg := asMap(raw)
		if m := mapField(hg, "membership"); m != nil {
			check(fmt.Sprintf("hostgroups[%s].membership.hosts", labelOf(hg)), stringListField(m, "hosts"))
		}
	}
	for _, raw := range listField(root, "netgroups") {
		ng := asMap(raw)
		if m := mapField(ng, "membership"); m != nil {
			check(fmt.Sprintf("netgroups[%s].membership.hosts", labelOf(ng)), stringListField(m, "hosts"))
		}
	}
	for _, raw := range listField(mapField(root, "hbac"), "rules") {
		r := asMap(raw)
		if t := mapField(r, "targets"); t != nil {
			check(fmt.Sprintf("hbac.rules[%s].targets.hosts", labelOf(r)), stringListField(t, "hosts"))
		}
	}
	for _, raw := range listField(mapField(root, "sudo"), "rules") {
		r := asMap(raw)
		if t := mapField(r, "targets"); t != nil {
			check(fmt.Sprintf("sudo.rules[%s].targets.hosts", labelOf(r)), stringListField(t, "hosts"))
		}
	}
	return out
}

// RosterDanglingHostReferenceWarningsFile is
// RosterDanglingHostReferenceWarnings' file-reading counterpart,
// mirroring RosterDeprecationWarningsFile's shape.
func RosterDanglingHostReferenceWarningsFile(path string) ([]RosterWarning, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return RosterDanglingHostReferenceWarnings(root), nil
}
