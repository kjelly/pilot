// edit_workspace_ids.go generates the opaque identifiers the MCP plan/
// apply tools hand back to callers — a plan_id (referencing an audit
// directory) and a scenario_hash (so a caller can tell whether the
// scenario a plan_id refers to is the one they think it is).
package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// newPlanID returns a fresh, opaque, unique-enough identifier — 16
// random bytes, hex-encoded. Spec's examples show ULID-shaped IDs
// ("01K1...") but that's illustrative, not a mandated format: nothing
// depends on ID sortability here, since the audit directory name
// itself already carries an explicit timestamp prefix.
func newPlanID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate plan id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// computeScenarioHash hashes scenario's canonical JSON encoding, so a
// caller (or a later apply call) can confirm a plan_id still refers to
// the exact scenario they expect.
func computeScenarioHash(scenario editScenario) (string, error) {
	data, err := json.Marshal(scenario)
	if err != nil {
		return "", fmt.Errorf("marshal scenario: %w", err)
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
