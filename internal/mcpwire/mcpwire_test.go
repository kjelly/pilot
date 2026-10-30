package mcpwire

import (
	"strings"
	"testing"
)

func entry(p, content string) FileEntry {
	return FileEntry{Path: p, Size: int64(len(content)), SHA256: SHA256Hex([]byte(content))}
}

func TestContentDigestIgnoresOrderButNotContentPathOrSize(t *testing.T) {
	a := []FileEntry{entry("hosts.yml", "x"), entry("group_vars/a.yml", "y")}
	b := []FileEntry{a[1], a[0]}
	da, err := ContentDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := ContentDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatal("digest depends on file order")
	}
	for name, changed := range map[string][]FileEntry{
		"content": {entry("hosts.yml", "z"), a[1]},
		"path":    {entry("hosts2.yml", "x"), a[1]},
		"size":    {{Path: "hosts.yml", Size: 2, SHA256: a[0].SHA256}, a[1]},
		"removed": {a[0]},
	} {
		dc, err := ContentDigest(changed)
		if err != nil {
			t.Fatal(err)
		}
		if dc == da {
			t.Errorf("digest unchanged after changing %s", name)
		}
	}
}

func TestContentDigestRejectsBadEntries(t *testing.T) {
	if _, err := ContentDigest([]FileEntry{entry("a", "x"), entry("a", "y")}); err == nil {
		t.Error("duplicate path accepted")
	}
	if _, err := ContentDigest([]FileEntry{{Path: "a", Size: 1, SHA256: "nothex"}}); err == nil {
		t.Error("invalid sha256 accepted")
	}
}

func TestSnapshotHeaderRoundTripAndLimits(t *testing.T) {
	n, err := ParseSnapshotHeader(SnapshotHeader(1234))
	if err != nil || n != 1234 {
		t.Fatalf("round trip = %d, %v", n, err)
	}
	for _, bad := range []string{
		"PILOT-MCP-SNAPSHOT 12",           // no newline
		"PILOT-MCP-SNAPSHOT  12\n",        // double space
		"PILOT-MCP-SNAPSHOT -1\n",         // sign
		"PILOT-MCP-SNAPSHOT 1234567890\n", // ten digits
		"PILOT-MCP-SNAPSHOT 99999999\n",   // over MaxStreamBytes
		"pilot-mcp-snapshot 12\n",
	} {
		if _, err := ParseSnapshotHeader(bad); err == nil {
			t.Errorf("header %q accepted", bad)
		}
	}
}

func TestReadyRoundTrip(t *testing.T) {
	line, err := FormatReady(Ready{Protocol: Protocol, SessionID: strings.Repeat("a", 32), Mode: ModeObserve, Env: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, ReadyPrefix) || !strings.HasSuffix(line, "\n") || strings.Count(line, "\n") != 1 {
		t.Fatalf("ready line %q is not one prefixed line", line)
	}
	got, err := ParseReady(line)
	if err != nil || got.Env != "prod" || got.Mode != ModeObserve {
		t.Fatalf("ParseReady = %+v, %v", got, err)
	}
	if _, err := ParseReady(`PILOT-MCP-READY {"protocol":"other"}`); err == nil {
		t.Error("foreign protocol accepted")
	}
}

func TestErrorLineRoundTripAndExitCodes(t *testing.T) {
	line := ErrorLine(CodeEnvMismatch, "host a has env prod\nnot staging")
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("error line %q spans lines", line)
	}
	code, msg, ok := ParseErrorLine("noise\n" + line + "\n")
	if !ok || code != CodeEnvMismatch || !strings.Contains(msg, "not staging") {
		t.Fatalf("ParseErrorLine = %q %q %v", code, msg, ok)
	}
	if _, _, ok := ParseErrorLine("panic: boom\ngoroutine 1"); ok {
		t.Error("panic text parsed as an error line")
	}
	cases := map[string]int{CodeCommandInvalid: 64, CodeProtocolUnsupported: 64, CodeEnvMismatch: 65, CodeChangesetInvalid: 65, CodeRuntimeError: 66}
	for c, want := range cases {
		if got := ExitCode(c); got != want {
			t.Errorf("ExitCode(%s) = %d, want %d", c, got, want)
		}
	}
}

func TestCheckSnapshotPath(t *testing.T) {
	for _, ok := range []string{"hosts.yml", "group_vars/all.yml", "monitoring/snmp/x.yaml", ".gitignore", "docs/readme.md", "contractsx/a", ".gitx/a", "Docs/verificationx/a",
		// Ignorable code points are fine in ordinary names (a ZWJ emoji).
		"docs/\U0001F469\u200d\U0001F4BB-onboarding.md", "a/\ufeffb", "x/contracts/a", "x/.vault"} {
		if err := CheckSnapshotPath(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/etc/passwd", "../x", "a/../b", "a//b", "./a", "a/", "a\\b", "a\x00b", "a\nb",
		".vault/main.yaml", ".pilot/x", ".pilot-data/x", "contracts/docker.yaml", "docs/verification/docker.md", ".git/config", ".vault",
		// A case-insensitive clone (macOS) resolves these to the reserved
		// directories, and HFS+ also drops the ignorable code points.
		".GIT/config", ".Git", ".VAULT/main.yaml", "Contracts/docker.yaml", "docs/Verification/docker.md",
		".g\u200cit/config", "contract\u017f/x",
		// Git refuses a .git component anywhere in a path.
		"x/.git/config", "a/b/.Git/HEAD", "x/.g\u200dit/config", "x/.git"} {
		if err := CheckSnapshotPath(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestFoldPath(t *testing.T) {
	for _, pair := range [][2]string{{"ALL.yml", "all.yml"}, {"contract\u017f", "contracts"}, {"a\u200cll.yml", "all.yml"}, {"\u212a", "k"}} {
		if FoldPath(pair[0]) != FoldPath(pair[1]) {
			t.Errorf("FoldPath(%q) != FoldPath(%q)", pair[0], pair[1])
		}
	}
	if FoldPath("a.yml") == FoldPath("b.yml") || FoldPath("a/b") == FoldPath("ab") {
		t.Error("FoldPath merges different names")
	}
}

func TestValidators(t *testing.T) {
	for _, e := range []string{"sandbox", "staging", "prod"} {
		if !ValidEnv(e) {
			t.Errorf("env %s rejected", e)
		}
	}
	if ValidEnv("production") || ValidEnv("") {
		t.Error("unknown env accepted")
	}
	if !ValidSessionID(strings.Repeat("0a", 16)) || ValidSessionID(strings.Repeat("A", 32)) || ValidSessionID("abc") {
		t.Error("session id validation wrong")
	}
}

func TestCheckTools(t *testing.T) {
	observe := map[string]bool{"pilot_edit_inspect": true, "pilot_edit_plan": true, "pilot_diagnose_sudo": true}
	if err := CheckTools(ModeObserve, observe); err != nil {
		t.Fatal(err)
	}
	if err := CheckTools(ModeEdit, observe); err == nil {
		t.Error("edit without pilot_edit_apply accepted")
	}
	withRepair := map[string]bool{"pilot_repair_plan": true}
	for k := range observe {
		withRepair[k] = true
	}
	if err := CheckTools(ModeObserve, withRepair); err == nil || !strings.Contains(err.Error(), "pilot_repair_plan") {
		t.Errorf("repair tool not reported: %v", err)
	}
	observe["pilot_edit_apply"] = true
	if err := CheckTools(ModeObserve, observe); err == nil {
		t.Error("observe with pilot_edit_apply accepted")
	}
}
