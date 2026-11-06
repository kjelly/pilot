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
	Plan
	Stats Stats `json:"stats"`
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
