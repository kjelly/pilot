package mcpwire

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
)

// ManifestName is the first tar entry of a snapshot.
const ManifestName = ".pilot-mcp-manifest.json"

// ChangesManifestName is the first tar entry of a changes export.
const ChangesManifestName = ".pilot-mcp-changes.json"

// Source is the client's claim about where a snapshot came from. The
// deploy node cannot verify it; it is recorded for audit only.
type Source struct {
	URL       string `json:"url"`
	Ref       string `json:"ref"`
	CommitSHA string `json:"commit_sha"`
	Subdir    string `json:"subdir"`
}

// FileEntry describes one snapshot file.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest is the snapshot's first tar entry. It is not itself listed in
// Files and is not part of ContentDigest.
type Manifest struct {
	Protocol      string      `json:"protocol"`
	Source        Source      `json:"source"`
	Env           string      `json:"env"`
	ClientVersion string      `json:"client_version"`
	ClientUser    string      `json:"client_user"`
	Files         []FileEntry `json:"files"`
	ContentDigest string      `json:"content_digest"`
}

// ContentDigest hashes the file list independent of order and metadata:
// for each file in path byte order, uint32 BE len(path), the path,
// uint64 BE size and the raw 32-byte SHA-256, all fed to one SHA-256.
func ContentDigest(files []FileEntry) (string, error) {
	sorted := append([]FileEntry(nil), files...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	var buf [8]byte
	for i, f := range sorted {
		if i > 0 && sorted[i-1].Path == f.Path {
			return "", fmt.Errorf("duplicate path %q", f.Path)
		}
		sum, err := hex.DecodeString(f.SHA256)
		if err != nil || len(sum) != sha256.Size {
			return "", fmt.Errorf("file %q has an invalid sha256", f.Path)
		}
		if f.Size < 0 {
			return "", fmt.Errorf("file %q has a negative size", f.Path)
		}
		binary.BigEndian.PutUint32(buf[:4], uint32(len(f.Path)))
		h.Write(buf[:4])
		h.Write([]byte(f.Path))
		binary.BigEndian.PutUint64(buf[:], uint64(f.Size))
		h.Write(buf[:])
		h.Write(sum)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Change operations in a changes export.
const (
	OpAdd    = "add"
	OpModify = "modify"
	OpDelete = "delete"
)

// Change is one path an edit session changed.
type Change struct {
	Path       string `json:"path"`
	Op         string `json:"op"`
	BaseSHA256 string `json:"base_sha256"`
	NewSHA256  string `json:"new_sha256"`
}

// ChangesManifest is the first tar entry of `pilot mcp remote changes`.
type ChangesManifest struct {
	Protocol      string   `json:"protocol"`
	SessionID     string   `json:"session_id"`
	Env           string   `json:"env"`
	BaseCommitSHA string   `json:"base_commit_sha"`
	Changes       []Change `json:"changes"`
}
