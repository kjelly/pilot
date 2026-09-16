// model.go defines the user_host_access_v1 wire shapes (design spec §11,
// §12, §14): the sanitized, versioned snapshot Pilot publishes, and the
// diff shape derived from two snapshots. These are pure data types; see
// projection.go/projection_roster.go for how they're built, canonical.go
// for deterministic ordering/hashing, and diff.go for the diff engine.
package outbound

import "time"

// UserHostAccessSnapshotV1 is the full sanitized projection of Pilot's
// declarative state (design spec §11.2). It is not raw hosts.yml or
// roster JSON — every field here is an explicit allowlist projection
// (design spec §37).
type UserHostAccessSnapshotV1 struct {
	Hosts      []ProjectedHost      `json:"hosts"`
	Users      []ProjectedUser      `json:"users"`
	Groups     []ProjectedGroup     `json:"groups"`
	Hostgroups []ProjectedHostgroup `json:"hostgroups"`
	Access     ProjectedAccess      `json:"access"`
}

// ProjectedHost is one host entity — either inventory-sourced or
// freeipa-roster-sourced (design spec §11.3). The two sources are never
// merged into one entity, even when their address matches (§11.4): V1
// keeps two distinct namespaced IDs.
type ProjectedHost struct {
	ID                     string            `json:"id"`
	Name                   string            `json:"name"`
	Source                 string            `json:"source"` // "inventory" | "freeipa_roster"
	FQDN                   string            `json:"fqdn,omitempty"`
	Address                string            `json:"address,omitempty"`
	Env                    string            `json:"env,omitempty"`
	Roles                  []string          `json:"roles"`
	DeploymentAvailability string            `json:"deployment_availability,omitempty"`
	Annotations            map[string]string `json:"annotations,omitempty"`
}

// ProjectedUser is one present/disabled roster user (design spec §11.2).
type ProjectedUser struct {
	Name            string   `json:"name"`
	DisplayName     string   `json:"display_name,omitempty"`
	Email           string   `json:"email,omitempty"`
	Enabled         bool     `json:"enabled"`
	UID             *int     `json:"uid,omitempty"`
	GID             *int     `json:"gid,omitempty"`
	EffectiveGroups []string `json:"effective_groups"`
}

// ProjectedGroup is one present roster group's direct membership.
type ProjectedGroup struct {
	Name        string   `json:"name"`
	Category    string   `json:"category,omitempty"`
	Type        string   `json:"type,omitempty"`
	Description string   `json:"description,omitempty"`
	Users       []string `json:"users"`
	Groups      []string `json:"groups"`
}

// ProjectedHostgroup is one present roster hostgroup, with both direct
// and transitively-expanded (EffectiveHostIDs) membership.
type ProjectedHostgroup struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	HostIDs          []string `json:"host_ids"`
	Hostgroups       []string `json:"hostgroups"`
	EffectiveHostIDs []string `json:"effective_host_ids"`
}

// ProjectedAccess groups the resolved login/sudo access entities.
type ProjectedAccess struct {
	Login []ProjectedLoginAccess `json:"login"`
	Sudo  []ProjectedSudoAccess  `json:"sudo"`
}

// ProjectedLoginAccess is one resolved login-access entity (design spec
// §12.2): a static HBAC rule, an active temporary_grant, or an active
// breakglass activation.
type ProjectedLoginAccess struct {
	ID         string     `json:"id"`
	Source     string     `json:"source"` // "static_hbac" | "temporary_grant" | "breakglass"
	Rule       string     `json:"rule"`
	Users      []string   `json:"users"`
	AllHosts   bool       `json:"all_hosts"`
	HostIDs    []string   `json:"host_ids,omitempty"`
	Services   []string   `json:"services"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

// ProjectedSudoAccess is one resolved sudo-access entity (design spec
// §12.3): a static sudo rule or an active sudo_grant.
type ProjectedSudoAccess struct {
	ID             string     `json:"id"`
	Source         string     `json:"source"` // "static_sudo" | "sudo_grant"
	Rule           string     `json:"rule"`
	Users          []string   `json:"users"`
	AllHosts       bool       `json:"all_hosts"`
	HostIDs        []string   `json:"host_ids,omitempty"`
	AllCommands    bool       `json:"all_commands"`
	Commands       []string   `json:"commands,omitempty"`
	DeniedCommands []string   `json:"denied_commands,omitempty"`
	RunAsUsers     []string   `json:"run_as_users"`
	RunAsGroups    []string   `json:"run_as_groups"`
	Options        []string   `json:"options"`
	ValidNotBefore *time.Time `json:"valid_not_before,omitempty"`
	ValidNotAfter  *time.Time `json:"valid_not_after,omitempty"`
}

// StateDiffV1 is the publication-state diff between a base authoritative
// snapshot and the current projection (design spec §14.3) — never a
// local pre/post file comparison (INV-5).
type StateDiffV1 struct {
	BaseSnapshotID   string `json:"base_snapshot_id,omitempty"`
	TargetSnapshotID string `json:"target_snapshot_id"`
	Bootstrap        bool   `json:"bootstrap"`

	Hosts       EntityDiff[ProjectedHost]        `json:"hosts"`
	Users       EntityDiff[ProjectedUser]        `json:"users"`
	Groups      EntityDiff[ProjectedGroup]       `json:"groups"`
	Hostgroups  EntityDiff[ProjectedHostgroup]   `json:"hostgroups"`
	LoginAccess EntityDiff[ProjectedLoginAccess] `json:"login_access"`
	SudoAccess  EntityDiff[ProjectedSudoAccess]  `json:"sudo_access"`
}

// EntityDiff is one entity type's upsert/delete set between two
// snapshots. Upsert always carries the full entity (never a JSON Patch)
// — design spec §14.3.
type EntityDiff[T any] struct {
	Upsert []T      `json:"upsert"`
	Delete []string `json:"delete"`
}
