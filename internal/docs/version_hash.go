package docs

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// VersionHash computes a stable hash from a version string and a
// list of module names. The list is sorted internally so the order
// doesn't affect the result. Used to detect ansible-core version
// changes that would invalidate the index.
func VersionHash(ansibleVersion string, modules []string) string {
	sorted := make([]string, len(modules))
	copy(sorted, modules)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte(ansibleVersion))
	h.Write([]byte{0})
	for _, m := range sorted {
		h.Write([]byte(m))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
