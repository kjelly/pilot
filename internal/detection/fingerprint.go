package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint computes a SignalEvent's identity per spec §21. It
// deliberately excludes score, timestamp, category, severity, model, and
// provider — only the subject (host) and the feature profile that
// evaluated it participate, so severity/category churn within one episode
// never changes its identity or creates a duplicate.
func Fingerprint(pilotHost, featureProfileID string, featureProfileVersion int) string {
	payload := fmt.Sprintf("pilot-detection/v1\n%s\n%s\n%d", pilotHost, featureProfileID, featureProfileVersion)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
