package identityreconcile

import (
	"crypto/sha256"
	"encoding/hex"
)

// HistoryMarkerName is the FreeIPA group that records that a roster group
// was ever applied: playbooks/apply/tasks/freeipa-group-history-marker.yml
// hashes the roster name as written (Jinja hash('sha256')), not lower-cased.
func HistoryMarkerName(group string) string {
	sum := sha256.Sum256([]byte(group))
	return "pilot-internal-history-g-" + hex.EncodeToString(sum[:])
}

// HistoryMarkerDescription is the description that marker must carry.
func HistoryMarkerDescription(group string) string {
	return "pilot.group-history/v1 name=" + group
}
