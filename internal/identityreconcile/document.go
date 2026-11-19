package identityreconcile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// DocumentSchema names the plan JSON format (spec §7.5).
const DocumentSchema = "pilot.identity-plan/v1"

// EngineName is the --engine value that selects this engine.
const EngineName = "golang"

// Results of a preview that produced a plan.
const (
	ResultOK      = "ok"
	ResultBlocked = "blocked"
)

// Target is where the plan was observed.
type Target struct {
	InventoryHost string    `json:"inventory_host"`
	FQDN          string    `json:"fqdn"`
	SSH           SSHTarget `json:"ssh"`
	Destination   string    `json:"destination"`
}

// SSHTarget is the SSH connection the tunnel used.
type SSHTarget struct {
	Host string `json:"host"`
	Port int    `json:"port,omitempty"`
	User string `json:"user,omitempty"`
}

// Server is the FreeIPA server and API version ping reported.
type Server struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
}

// ObservationSummary identifies the live state a plan was built from.
type ObservationSummary struct {
	ObservedAt  string `json:"observed_at"`
	Fingerprint string `json:"fingerprint"`
	Users       int    `json:"users"`
	Groups      int    `json:"groups"`
}

// Stats counts what the preview sent.
type Stats struct {
	HTTPRequests int `json:"http_requests"`
	Reads        int `json:"reads"`
	Writes       int `json:"writes"`
	Relogins     int `json:"relogins"`
	ReadRetries  int `json:"read_retries"`
}

// Engine names the engine and the pilot build that planned.
type Engine struct {
	Name          string `json:"name"`
	PilotRevision string `json:"pilot_revision"`
}

// Document is the plan JSON: no password, cookie, vault content or SSH
// key body (spec §7.5).
type Document struct {
	Schema          string             `json:"schema"`
	Engine          Engine             `json:"engine"`
	Scope           string             `json:"scope"`
	Result          string             `json:"result"`
	Target          Target             `json:"target"`
	Server          Server             `json:"server"`
	DesiredRevision string             `json:"desired_revision"`
	Observation     ObservationSummary `json:"observation"`
	// HBAC is the HBAC plan of a mixed run (--scope full, spec 2026-11-19 phase 3a §7.2); absent
	// in the users-groups scope, whose document is what it was.
	HBAC *HBACPlanDoc `json:"hbac,omitempty"`
	Plan
	Stats Stats `json:"stats"`
}

// HBACObservationSummary identifies the live HBAC state a plan was built from.
type HBACObservationSummary struct {
	Fingerprint string `json:"fingerprint"`
	Rules       int    `json:"rules"`
	Services    int    `json:"services"`
	Hosts       int    `json:"hosts"`
	Hostgroups  int    `json:"hostgroups"`
	Domain      string `json:"domain"`
}

// HBACPlanDoc is the HBAC part of a plan document. It holds no secret: names and the fields the
// operations change, as the users and groups plan does.
type HBACPlanDoc struct {
	// Preview: the plan was made before the playbook phase, so the hosts, hostgroups and
	// services the roster declares were assumed to exist (spec D8).
	Preview     bool                   `json:"preview"`
	Observation HBACObservationSummary `json:"observation"`
	HBACPlan
}

// NewHBACPlanDoc wraps an HBAC plan with the observation it was built from.
func NewHBACPlanDoc(plan HBACPlan, obs HBACObservation, preview bool) *HBACPlanDoc {
	return &HBACPlanDoc{
		Preview: preview,
		Observation: HBACObservationSummary{
			Fingerprint: fingerprint(obs), Rules: len(obs.Rules), Services: len(obs.Services),
			Hosts: len(obs.Hosts), Hostgroups: len(obs.Hostgroups), Domain: obs.Domain,
		},
		HBACPlan: plan,
	}
}

// WithHBAC is the document of a mixed run: the users and groups plan with the HBAC plan next to it. The
// scope is then full, and a blocked HBAC plan makes the whole document blocked, as a blocked users and
// groups plan does. The document is returned as a copy.
func (d Document) WithHBAC(hbac *HBACPlanDoc) Document {
	if hbac == nil {
		return d
	}
	d.Scope = ScopeFull
	d.HBAC = hbac
	if len(hbac.Blocked) > 0 {
		d.Result = ResultBlocked
	}
	return d
}

// NewDocument wraps a plan with what it was built from.
func NewDocument(d Desired, obs Observation, plan Plan, target Target, server Server, revision string, observedAt time.Time, stats Stats) Document {
	result := ResultOK
	if len(plan.Blocked) > 0 {
		result = ResultBlocked
	}
	return Document{
		Schema:          DocumentSchema,
		Engine:          Engine{Name: EngineName, PilotRevision: revision},
		Scope:           ScopeUsersGroups,
		Result:          result,
		Target:          target,
		Server:          server,
		DesiredRevision: fingerprint(d),
		Observation: ObservationSummary{
			ObservedAt:  observedAt.UTC().Format(time.RFC3339),
			Fingerprint: fingerprint(obs),
			Users:       len(obs.Users),
			Groups:      len(obs.Groups),
		},
		Plan:  plan,
		Stats: stats,
	}
}

// fingerprint is the SHA-256 of v's JSON. Desired holds no password value
// and Observation no secret, so it reveals nothing to guess offline.
func fingerprint(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "unencodable"
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
