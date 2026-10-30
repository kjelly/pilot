package mcpclient

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/kjelly/pilot/internal/mcpwire"
)

const lfsPointerPrefix = "version https://git-lfs.github.com/spec/v1"

// Snapshot is the framed snapshot pilot-mcp sends: the header line plus
// the tar, ready to write to the remote's stdin.
type Snapshot struct {
	Manifest mcpwire.Manifest
	Framed   []byte
	Removed  []string // reserved paths left out, reported on stderr
}

// buildSnapshot reads subdir of commit from the cache and builds the
// normalized tar: manifest first, then regular files in path order with
// fixed mode and zero times (spec §6.1).
func buildSnapshot(ctx context.Context, repo *gitRepo, src SourceConfig, commit, env, clientVersion, clientUser string) (*Snapshot, error) {
	entries, err := repo.listTree(ctx, commit, src.Subdir)
	if err != nil {
		return nil, err
	}
	var keep []treeEntry
	var removed []string
	for _, e := range entries {
		if mcpwire.IsReserved(e.path) {
			removed = append(removed, e.path)
			continue
		}
		if e.kind != "blob" || (e.mode != "100644" && e.mode != "100755") {
			return nil, &Error{Code: CodeSnapshotInvalid, Msg: fmt.Sprintf("%s is a %s (mode %s); only regular files are allowed", e.path, e.kind, e.mode)}
		}
		if err := mcpwire.CheckSnapshotPath(e.path); err != nil {
			return nil, &Error{Code: CodeSnapshotInvalid, Msg: err.Error()}
		}
		keep = append(keep, e)
	}
	if len(keep) > mcpwire.MaxFiles {
		return nil, &Error{Code: CodeSnapshotTooLarge, Msg: fmt.Sprintf("%d files, more than %d", len(keep), mcpwire.MaxFiles)}
	}
	sort.Slice(keep, func(i, j int) bool { return keep[i].path < keep[j].path })
	objects := make([]string, len(keep))
	for i, e := range keep {
		objects[i] = e.object
	}
	blobs, err := repo.readBlobs(ctx, objects)
	if err != nil {
		return nil, err
	}

	m := mcpwire.Manifest{
		Protocol: mcpwire.Protocol,
		Source:   mcpwire.Source{URL: src.URL, Ref: src.Ref, CommitSHA: commit, Subdir: src.Subdir},
		Env:      env, ClientVersion: clientVersion, ClientUser: clientUser,
	}
	var total int64
	for i, e := range keep {
		data := blobs[i]
		if int64(len(data)) > mcpwire.MaxFileBytes {
			return nil, &Error{Code: CodeSnapshotTooLarge, Msg: fmt.Sprintf("%s is larger than %d bytes", e.path, mcpwire.MaxFileBytes)}
		}
		if bytes.HasPrefix(data, []byte(lfsPointerPrefix)) {
			return nil, &Error{Code: CodeSnapshotInvalid, Msg: fmt.Sprintf("%s is a Git LFS pointer; LFS files are not supported", e.path)}
		}
		total += int64(len(data))
		m.Files = append(m.Files, mcpwire.FileEntry{Path: e.path, Size: int64(len(data)), SHA256: mcpwire.SHA256Hex(data)})
	}
	if total > mcpwire.MaxTotalBytes {
		return nil, &Error{Code: CodeSnapshotTooLarge, Msg: fmt.Sprintf("files total %d bytes, more than %d", total, mcpwire.MaxTotalBytes)}
	}
	digest, err := mcpwire.ContentDigest(m.Files)
	if err != nil {
		return nil, &Error{Code: CodeSnapshotInvalid, Msg: err.Error()}
	}
	m.ContentDigest = digest

	manifest, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := writeTarFile(tw, mcpwire.ManifestName, manifest); err != nil {
		return nil, err
	}
	for i, e := range keep {
		if err := writeTarFile(tw, e.path, blobs[i]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	framed := append([]byte(mcpwire.SnapshotHeader(int64(buf.Len()))), buf.Bytes()...)
	return &Snapshot{Manifest: m, Framed: framed, Removed: removed}, nil
}

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err := io.Copy(tw, bytes.NewReader(data))
	return err
}
