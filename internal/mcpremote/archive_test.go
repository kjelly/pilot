package mcpremote

import (
	"archive/tar"
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/mcpwire"
)

func TestReadSnapshotStopsExactlyAtTheMCPStream(t *testing.T) {
	files := map[string]string{"hosts.yml": hostsFor("prod"), "group_vars/all.yml": "a: 1\n"}
	mcpBytes := `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
	br := bufio.NewReaderSize(bytes.NewReader(append(snapshot(t, "prod", files), mcpBytes...)), 64<<10)
	dest := t.TempDir()
	m, err := ReadSnapshot(br, dest, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Files) != 2 {
		t.Fatalf("manifest files = %d", len(m.Files))
	}
	rest, err := io.ReadAll(br)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != mcpBytes {
		t.Fatalf("bytes after the snapshot = %q, want the MCP request", rest)
	}
	got, err := os.ReadFile(filepath.Join(dest, "group_vars", "all.yml"))
	if err != nil || string(got) != "a: 1\n" {
		t.Fatalf("extracted file = %q, %v", got, err)
	}
	info, err := os.Stat(filepath.Join(dest, "hosts.yml"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("extracted mode = %v, %v", info.Mode(), err)
	}
}

func TestReadSnapshotRejectsHostileInput(t *testing.T) {
	good := map[string]string{"hosts.yml": hostsFor("prod")}
	m := manifestFor("prod", good)
	hostsEntry := regular("hosts.yml", good["hosts.yml"])
	withFiles := func(files map[string]string, entries ...tarEntry) []byte {
		return rawSnapshot(t, manifestFor("prod", files), entries)
	}
	cases := []struct {
		name string
		data []byte
		code string
	}{
		{"malformed header", []byte("PILOT-MCP-SNAPSHOT x\n"), mcpwire.CodeSnapshotInvalid},
		{"oversized header", []byte("PILOT-MCP-SNAPSHOT 99999999\n"), mcpwire.CodeSnapshotTooLarge},
		{"long header line", []byte(strings.Repeat("A", 200) + "\n"), mcpwire.CodeSnapshotInvalid},
		{"truncated", snapshot(t, "prod", good)[:60], mcpwire.CodeSnapshotInvalid},
		{"env mismatch", snapshot(t, "staging", good), mcpwire.CodeEnvMismatch},
		{"absolute path", withFiles(map[string]string{"/etc/x": "a"}, regular("/etc/x", "a")), mcpwire.CodeSnapshotInvalid},
		{"dot dot", withFiles(map[string]string{"a/../../x": "a"}, regular("a/../../x", "a")), mcpwire.CodeSnapshotInvalid},
		{"backslash", withFiles(map[string]string{`a\b`: "a"}, regular(`a\b`, "a")), mcpwire.CodeSnapshotInvalid},
		{"control char", withFiles(map[string]string{"a\x01b": "a"}, regular("a\x01b", "a")), mcpwire.CodeSnapshotInvalid},
		{"vault path", withFiles(map[string]string{".vault/main.yaml": "x"}, regular(".vault/main.yaml", "x")), mcpwire.CodeSnapshotInvalid},
		{"contracts path", withFiles(map[string]string{"contracts/x.yaml": "x"}, regular("contracts/x.yaml", "x")), mcpwire.CodeSnapshotInvalid},
		{"case collision", withFiles(map[string]string{"A.yml": "a", "a.yml": "b"}, regular("A.yml", "a"), regular("a.yml", "b")), mcpwire.CodeSnapshotInvalid},
		{"duplicate entry", rawSnapshot(t, m, []tarEntry{hostsEntry, hostsEntry}), mcpwire.CodeSnapshotInvalid},
		{"unlisted entry", rawSnapshot(t, m, []tarEntry{hostsEntry, regular("extra.yml", "x")}), mcpwire.CodeSnapshotInvalid},
		{"missing entry", rawSnapshot(t, m, nil), mcpwire.CodeSnapshotInvalid},
		{"size mismatch", rawSnapshot(t, m, []tarEntry{regular("hosts.yml", "short")}), mcpwire.CodeSnapshotInvalid},
		{"content mismatch", rawSnapshot(t, m, []tarEntry{regular("hosts.yml", strings.Repeat("x", len(good["hosts.yml"])))}), mcpwire.CodeSnapshotInvalid},
		{"symlink", rawSnapshot(t, m, []tarEntry{{hdr: tar.Header{Name: "hosts.yml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}}}), mcpwire.CodeSnapshotInvalid},
		{"hardlink", rawSnapshot(t, m, []tarEntry{{hdr: tar.Header{Name: "hosts.yml", Typeflag: tar.TypeLink, Linkname: "x"}}}), mcpwire.CodeSnapshotInvalid},
		{"fifo", rawSnapshot(t, m, []tarEntry{{hdr: tar.Header{Name: "hosts.yml", Typeflag: tar.TypeFifo}}}), mcpwire.CodeSnapshotInvalid},
		{"char device", rawSnapshot(t, m, []tarEntry{{hdr: tar.Header{Name: "hosts.yml", Typeflag: tar.TypeChar}}}), mcpwire.CodeSnapshotInvalid},
		// A name over 100 bytes travels in a PAX "path" record; the reader
		// rebuilds it and the escape must still be caught.
		{"pax path escape", rawSnapshot(t, manifestFor("prod", map[string]string{"x": "a"}), []tarEntry{{hdr: tar.Header{Name: strings.Repeat("d/", 60) + strings.Repeat("../", 61) + "x", Typeflag: tar.TypeReg, Size: 1, Format: tar.FormatPAX}, data: []byte("a")}}), mcpwire.CodeSnapshotInvalid},
	}
	badDigest := m
	badDigest.ContentDigest = strings.Repeat("0", 64)
	cases = append(cases, struct {
		name string
		data []byte
		code string
	}{"digest mismatch", rawSnapshot(t, badDigest, []tarEntry{hostsEntry}), mcpwire.CodeSnapshotInvalid})
	foreign := m
	foreign.Protocol = "other/v9"
	cases = append(cases, struct {
		name string
		data []byte
		code string
	}{"foreign protocol", rawSnapshot(t, foreign, []tarEntry{hostsEntry}), mcpwire.CodeProtocolUnsupported})
	huge := m
	huge.Files = []mcpwire.FileEntry{{Path: "big.yml", Size: mcpwire.MaxFileBytes + 1, SHA256: strings.Repeat("0", 64)}}
	cases = append(cases, struct {
		name string
		data []byte
		code string
	}{"oversized file", rawSnapshot(t, huge, nil), mcpwire.CodeSnapshotTooLarge})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dest := filepath.Join(root, "source")
			_, err := ReadSnapshot(bufio.NewReader(bytes.NewReader(tc.data)), dest, "prod")
			if err == nil {
				t.Fatal("hostile snapshot accepted")
			}
			if got := CodeOf(err); got != tc.code {
				t.Fatalf("code = %s, want %s (%v)", got, tc.code, err)
			}
			assertNothingOutside(t, root, dest)
		})
	}
}

// assertNothingOutside fails when anything was written under root other
// than inside dest.
func assertNothingOutside(t *testing.T, root, dest string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Join(root, e.Name()) != dest {
			t.Fatalf("snapshot wrote %s outside its destination", e.Name())
		}
	}
}

// FuzzRemoteArchive feeds arbitrary bytes after a valid header. Whatever
// they are, ReadSnapshot must not panic or write outside its destination,
// and an accepted snapshot's YAML must pass through CheckPathScope in
// bounded time (the seeds include alias bombs and a cyclic alias).
func FuzzRemoteArchive(f *testing.F) {
	bomb := "a: &a [x, x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\ne: [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]\n"
	cyclic := "a: &a\n  <<: *a\n"
	for _, files := range []map[string]string{
		{"hosts.yml": hostsFor("prod")},
		{"hosts.yml": hostsFor("prod"), "group_vars/bomb.yml": bomb},
		{"hosts.yml": hostsFor("prod"), "group_vars/cyclic.yml": cyclic},
	} {
		f.Add(snapshot(f, "prod", files))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		root := t.TempDir()
		dest := filepath.Join(root, "source")
		m, err := ReadSnapshot(bufio.NewReader(bytes.NewReader(data)), dest, "prod")
		assertNothingOutside(t, root, dest)
		if err != nil {
			return
		}
		paths := make([]string, 0, len(m.Files))
		for _, file := range m.Files {
			paths = append(paths, file.Path)
		}
		_ = CheckPathScope(dest, paths)
	})
}
