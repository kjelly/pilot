package inventory

import "regexp"

// secretLikeKeyPattern matches key names that look like they carry secret
// material (password, token, credential, ...) rather than descriptive
// metadata. Canonical home for this pattern — internal/decommission's
// persistence gate and this package's annotation validation both refuse to
// let a secret-shaped key name flow into effectively-permanent storage
// (FreeIPA userClass values are visible via `ipa host-show`; decommission
// plans are persisted to SQLite).
var secretLikeKeyPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|vault|credential)`)

// LooksSecretLike reports whether key looks like it names a secret value
// rather than descriptive metadata. Matches anywhere in key, not just as a
// whole-token match, so a dotted/nested key like "service.api_key" is still
// caught by its trailing token.
func LooksSecretLike(key string) bool {
	return secretLikeKeyPattern.MatchString(key)
}
