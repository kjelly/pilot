package mcpremote

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/kjelly/pilot/internal/mcpwire"
)

// tarEntry is one raw tar entry a test writes, valid or hostile.
type tarEntry struct {
	hdr  tar.Header
	data []byte
}

func regular(name, content string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(content))}, data: []byte(content)}
}

func manifestFor(env string, files map[string]string) mcpwire.Manifest {
	m := mcpwire.Manifest{
		Protocol: mcpwire.Protocol,
		Source:   mcpwire.Source{URL: "https://example.invalid/org/config", Ref: "main", CommitSHA: "0123456789abcdef0123456789abcdef01234567", Subdir: "env"},
		Env:      env, ClientVersion: "test", ClientUser: "tester",
	}
	for p, c := range files {
		m.Files = append(m.Files, mcpwire.FileEntry{Path: p, Size: int64(len(c)), SHA256: mcpwire.SHA256Hex([]byte(c))})
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	d, err := mcpwire.ContentDigest(m.Files)
	if err != nil {
		panic(err)
	}
	m.ContentDigest = d
	return m
}

// rawSnapshot frames a manifest and entries as header line + tar.
func rawSnapshot(t testing.TB, m mcpwire.Manifest, entries []tarEntry) []byte {
	t.Helper()
	mdata, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var tbuf bytes.Buffer
	tw := tar.NewWriter(&tbuf)
	all := append([]tarEntry{regular(mcpwire.ManifestName, string(mdata))}, entries...)
	for _, e := range all {
		h := e.hdr
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return append([]byte(mcpwire.SnapshotHeader(int64(tbuf.Len()))), tbuf.Bytes()...)
}

// snapshot builds a valid snapshot of files for env.
func snapshot(t testing.TB, env string, files map[string]string) []byte {
	t.Helper()
	m := manifestFor(env, files)
	var entries []tarEntry
	for _, f := range m.Files {
		entries = append(entries, regular(f.Path, files[f.Path]))
	}
	return rawSnapshot(t, m, entries)
}

func hostsFor(env string) string {
	line := ""
	if env != "sandbox" {
		line = "    env: " + env + "\n"
	}
	return "vars:\n  ansible_ssh_private_key_file: \"/pilot/config/.vault/id_ed25519\"\nhosts:\n  web-1:\n    ansible_host: \"192.0.2.10\"\n    roles: [docker]\n" + line
}

// repoRoot is the pilot checkout, which has contracts/ and group_vars/
// like the image's /pilot.
func repoRoot(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
