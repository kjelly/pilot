package identity

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// realProcStatus is the credential part of a real /proc/self/status,
// captured 2026-09-23 on the Ubuntu controller that runs the vm-target
// suite (AGENTS.md §5.6: parse real output, not a guess) — note the tab
// separators and the trailing space on Groups:.
const realProcStatus = "Name:\t2.1.280\n" +
	"Umask:\t0002\n" +
	"State:\tS (sleeping)\n" +
	"Uid:\t1000\t1000\t1000\t1000\n" +
	"Gid:\t1000\t1000\t1000\t1000\n" +
	"FDSize:\t256\n" +
	"Groups:\t4 24 27 30 46 100 114 126 983 984 1000 \n" +
	"NStgid:\t1588048\n"

func TestParseProcStatusCreds(t *testing.T) {
	c, err := parseProcStatusCreds([]byte(realProcStatus))
	if err != nil {
		t.Fatalf("parseProcStatusCreds: %v", err)
	}
	if len(c.UIDs) != 4 || c.UIDs[0] != 1000 || len(c.GIDs) != 4 || c.GIDs[1] != 1000 {
		t.Fatalf("creds = %+v", c)
	}
	if len(c.Groups) != 11 || c.Groups[0] != 4 || c.Groups[9] != 984 {
		t.Fatalf("groups = %v", c.Groups)
	}
	// A process with no supplementary groups prints an empty Groups: line.
	empty, err := parseProcStatusCreds([]byte("Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\n"))
	if err != nil || len(empty.Groups) != 0 {
		t.Fatalf("empty groups: %+v, %v", empty, err)
	}
	for name, bad := range map[string]string{
		"no Groups line": "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n",
		"short Uid":      "Uid:\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t\n",
		"non-numeric":    "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\tx\n",
	} {
		if _, err := parseProcStatusCreds([]byte(bad)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func selfPrimaryGroup(t *testing.T) (*user.User, *user.Group) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current unavailable: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Skipf("LookupGroupId unavailable: %v", err)
	}
	return u, g
}

// TestPeerInGroupSelfPrimaryGroup is the case the old member-list check
// could never see: a primary group is carried by the process's GID, not
// listed as a member, and the kernel (and SocketGroup=) honor it.
func TestPeerInGroupSelfPrimaryGroup(t *testing.T) {
	_, g := selfPrimaryGroup(t)
	ok, err := PeerInGroup(context.Background(), int32(os.Getpid()), uint32(os.Getuid()), g.Name)
	if err != nil || !ok {
		t.Fatalf("PeerInGroup(self, primary %s) = %v, %v; want true", g.Name, ok, err)
	}
}

func TestPeerInGroupSelfSupplementaryGroup(t *testing.T) {
	gids, err := os.Getgroups()
	if err != nil {
		t.Skipf("Getgroups: %v", err)
	}
	for _, gid := range gids {
		if gid == os.Getgid() {
			continue
		}
		g, err := user.LookupGroupId(strconv.Itoa(gid))
		if err != nil {
			continue
		}
		ok, err := PeerInGroup(context.Background(), int32(os.Getpid()), uint32(os.Getuid()), g.Name)
		if err != nil || !ok {
			t.Fatalf("PeerInGroup(self, supplementary %s) = %v, %v; want true", g.Name, ok, err)
		}
		return
	}
	t.Skip("test process has no resolvable supplementary group")
}

func TestPeerInGroupNotHeld(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: every group check is trivially about gid 0")
	}
	gids, _ := os.Getgroups()
	for _, gid := range append(gids, os.Getgid()) {
		if gid == 0 {
			t.Skip("test process holds gid 0")
		}
	}
	root, err := user.LookupGroupId("0")
	if err != nil {
		t.Skipf("no gid 0 group: %v", err)
	}
	ok, err := PeerInGroup(context.Background(), int32(os.Getpid()), uint32(os.Getuid()), root.Name)
	if err != nil || ok {
		t.Fatalf("PeerInGroup(self, %s) = %v, %v; want false", root.Name, ok, err)
	}
}

func TestPeerInGroupFailsClosed(t *testing.T) {
	_, g := selfPrimaryGroup(t)
	ctx := context.Background()
	if _, err := PeerInGroup(ctx, int32(os.Getpid()), uint32(os.Getuid()), "this-group-does-not-exist-12345"); err == nil {
		t.Errorf("unknown group: expected an error")
	}
	if _, err := PeerInGroup(ctx, int32(os.Getpid()), uint32(os.Getuid())+1, g.Name); err == nil {
		t.Errorf("uid mismatch (reused pid): expected an error")
	}
	// A pid that has exited.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skipf("cannot run true: %v", err)
	}
	if _, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(cmd.Process.Pid))); err == nil {
		t.Skip("pid was already reused")
	}
	if _, err := PeerInGroup(ctx, int32(cmd.Process.Pid), uint32(os.Getuid()), g.Name); err == nil {
		t.Errorf("exited pid: expected an error")
	}
}

func TestLookupGroupGID(t *testing.T) {
	_, g := selfPrimaryGroup(t)
	gid, err := LookupGroupGID(context.Background(), g.Name)
	if err != nil || strconv.FormatUint(uint64(gid), 10) != g.Gid {
		t.Fatalf("LookupGroupGID(%s) = %d, %v; want %s", g.Name, gid, err, g.Gid)
	}
}
