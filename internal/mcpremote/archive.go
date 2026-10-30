package mcpremote

import (
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// readHeaderLine reads one line, newline included, without reading past
// it, failing once it grows beyond max bytes.
func readHeaderLine(br *bufio.Reader, max int) (string, error) {
	var line []byte
	for len(line) <= max {
		b, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		line = append(line, b)
		if b == '\n' {
			return string(line), nil
		}
	}
	return "", fmt.Errorf("header line longer than %d bytes", max)
}

// ReadSnapshot reads the snapshot header and exactly the announced number
// of tar bytes from br, writes the files under dest, and verifies them
// against the manifest. br is then positioned at the first MCP byte.
func ReadSnapshot(br *bufio.Reader, dest, wantEnv string) (*mcpwire.Manifest, error) {
	line, err := readHeaderLine(br, mcpwire.MaxHeaderLine)
	if err != nil {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "read snapshot header: %v", err)
	}
	n, err := mcpwire.ParseSnapshotHeader(line)
	if err != nil {
		if errors.Is(err, mcpwire.ErrStreamTooLarge) {
			return nil, errorf(mcpwire.CodeSnapshotTooLarge, "%v", err)
		}
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "%v", err)
	}
	lr := &io.LimitedReader{R: br, N: n}
	manifest, err := extractSnapshot(tar.NewReader(lr), dest, wantEnv)
	if err != nil {
		return nil, err
	}
	// Consume the rest of the announced bytes (tar padding), so br stops
	// exactly at the MCP stream.
	if _, err := io.Copy(io.Discard, lr); err != nil {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "read snapshot: %v", err)
	}
	if lr.N != 0 {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "snapshot truncated: %d of %d bytes missing", lr.N, n)
	}
	return manifest, nil
}

// checkFileSet applies the file-list rules of a snapshot (§6.2): each
// path's rules, no path twice (nor two spellings of one file or directory
// on a case-insensitive file system, mcpwire.FoldCollision), and the
// count and size limits. `changes` holds the next snapshot to the same
// rules (computeChanges).
func checkFileSet(files []mcpwire.FileEntry) error {
	if len(files) > mcpwire.MaxFiles {
		return errorf(mcpwire.CodeSnapshotTooLarge, "snapshot has %d files, more than %d", len(files), mcpwire.MaxFiles)
	}
	seen := make(map[string]bool, len(files))
	paths := make([]string, 0, len(files))
	var total int64
	for _, f := range files {
		if err := mcpwire.CheckSnapshotPath(f.Path); err != nil {
			return errorf(mcpwire.CodeSnapshotInvalid, "manifest: %v", err)
		}
		if seen[f.Path] {
			return errorf(mcpwire.CodeSnapshotInvalid, "manifest lists %q twice", f.Path)
		}
		seen[f.Path] = true
		paths = append(paths, f.Path)
		if f.Size < 0 || f.Size > mcpwire.MaxFileBytes {
			return errorf(mcpwire.CodeSnapshotTooLarge, "file %q is larger than %d bytes", f.Path, mcpwire.MaxFileBytes)
		}
		total += f.Size
	}
	if total > mcpwire.MaxTotalBytes {
		return errorf(mcpwire.CodeSnapshotTooLarge, "snapshot files total %d bytes, more than %d", total, mcpwire.MaxTotalBytes)
	}
	if a, b := mcpwire.FoldCollision(paths); a != "" {
		return errorf(mcpwire.CodeSnapshotInvalid, "manifest paths %q and %q differ only in case or ignorable characters", a, b)
	}
	return nil
}

func extractSnapshot(tr *tar.Reader, dest, wantEnv string) (*mcpwire.Manifest, error) {
	manifest, err := readManifest(tr, wantEnv)
	if err != nil {
		return nil, err
	}
	if err := checkFileSet(manifest.Files); err != nil {
		return nil, err
	}
	want := make(map[string]mcpwire.FileEntry, len(manifest.Files))
	for _, f := range manifest.Files {
		want[f.Path] = f
	}
	digest, err := mcpwire.ContentDigest(manifest.Files)
	if err != nil {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "manifest: %v", err)
	}
	if digest != manifest.ContentDigest {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "manifest content_digest does not match its file list")
	}

	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, errorf(mcpwire.CodeRuntimeError, "create %s: %v", dest, err)
	}
	seen := make(map[string]bool, len(want))
	entries := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errorf(mcpwire.CodeSnapshotInvalid, "read snapshot: %v", err)
		}
		entries++
		if entries > 2*mcpwire.MaxFiles {
			return nil, errorf(mcpwire.CodeSnapshotTooLarge, "snapshot has more than %d entries", 2*mcpwire.MaxFiles)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, errorf(mcpwire.CodeSnapshotInvalid, "entry %q is not a regular file", hdr.Name)
		}
		if err := mcpwire.CheckSnapshotPath(hdr.Name); err != nil {
			return nil, errorf(mcpwire.CodeSnapshotInvalid, "entry: %v", err)
		}
		entry, listed := want[hdr.Name]
		if !listed {
			return nil, errorf(mcpwire.CodeSnapshotInvalid, "entry %q is not in the manifest", hdr.Name)
		}
		if seen[hdr.Name] {
			return nil, errorf(mcpwire.CodeSnapshotInvalid, "entry %q appears twice", hdr.Name)
		}
		seen[hdr.Name] = true
		if hdr.Size != entry.Size {
			return nil, errorf(mcpwire.CodeSnapshotInvalid, "entry %q is %d bytes, manifest says %d", hdr.Name, hdr.Size, entry.Size)
		}
		if err := writeSnapshotFile(dest, hdr.Name, io.LimitReader(tr, hdr.Size), entry); err != nil {
			return nil, err
		}
	}
	if len(seen) != len(want) {
		for p := range want {
			if !seen[p] {
				return nil, errorf(mcpwire.CodeSnapshotInvalid, "manifest file %q is missing from the snapshot", p)
			}
		}
	}
	return manifest, nil
}

func readManifest(tr *tar.Reader, wantEnv string) (*mcpwire.Manifest, error) {
	hdr, err := tr.Next()
	if err != nil {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "read manifest: %v", err)
	}
	if hdr.Name != mcpwire.ManifestName || hdr.Typeflag != tar.TypeReg {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "first entry must be %s", mcpwire.ManifestName)
	}
	if hdr.Size > mcpwire.MaxManifestBytes {
		return nil, errorf(mcpwire.CodeSnapshotTooLarge, "manifest is larger than %d bytes", mcpwire.MaxManifestBytes)
	}
	data, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
	if err != nil {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "read manifest: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m mcpwire.Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, errorf(mcpwire.CodeSnapshotInvalid, "decode manifest: %v", err)
	}
	if m.Protocol != mcpwire.Protocol {
		return nil, errorf(mcpwire.CodeProtocolUnsupported, "manifest protocol %q", m.Protocol)
	}
	if m.Env != wantEnv {
		return nil, errorf(mcpwire.CodeEnvMismatch, "snapshot is for env %q, this session is %q", m.Env, wantEnv)
	}
	if len(m.Files) > mcpwire.MaxFiles {
		return nil, errorf(mcpwire.CodeSnapshotTooLarge, "snapshot lists %d files, more than %d", len(m.Files), mcpwire.MaxFiles)
	}
	return &m, nil
}

// writeSnapshotFile creates dest/name (never following or replacing an
// existing entry) and checks its size and SHA-256 against the manifest.
func writeSnapshotFile(dest, name string, r io.Reader, entry mcpwire.FileEntry) error {
	target := filepath.Join(dest, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return errorf(mcpwire.CodeRuntimeError, "create directory for %q: %v", name, err)
	}
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return errorf(mcpwire.CodeSnapshotInvalid, "create %q: %v", name, err)
	}
	h := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(f, h), r)
	closeErr := f.Close()
	if copyErr != nil {
		return errorf(mcpwire.CodeSnapshotInvalid, "read %q: %v", name, copyErr)
	}
	if closeErr != nil {
		return errorf(mcpwire.CodeRuntimeError, "write %q: %v", name, closeErr)
	}
	if written != entry.Size {
		return errorf(mcpwire.CodeSnapshotInvalid, "entry %q is truncated", name)
	}
	if hex.EncodeToString(h.Sum(nil)) != entry.SHA256 {
		return errorf(mcpwire.CodeSnapshotInvalid, "entry %q does not match its manifest sha256", name)
	}
	return nil
}
