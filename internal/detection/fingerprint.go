package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint computes a SignalEvent's identity per spec §21/§9.8. It
// deliberately excludes score, timestamp, category, severity, model, and
// provider — only the subject identity (id/kind/site) and the feature
// profile that evaluated it participate, so severity/category churn
// within one episode never changes its identity or creates a duplicate.
// subjectKind and site were added in Phase 4 (spec §9.8) so that, e.g., a
// managed host and an SNMP device that happened to share the same ID
// string could never collide on the same fingerprint/episode.
func Fingerprint(subjectID, subjectKind, site, featureProfileID string, featureProfileVersion int) string {
	payload := fmt.Sprintf("pilot-detection/v1\n%s\n%s\n%s\n%s\n%d", subjectID, subjectKind, site, featureProfileID, featureProfileVersion)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
