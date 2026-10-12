package decommission

import (
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// TestCanonicalInventoryHash_IncludesSSHRecording locks both halves of the
// per-host recording spec §5 decision: a host's ssh_recording policy is part
// of the inventory identity a plan was computed against, but hosts that never
// set it must hash exactly as they did before the field existed.
func TestCanonicalInventoryHash_IncludesSSHRecording(t *testing.T) {
	base := func() *inventory.HostsFile {
		return &inventory.HostsFile{
			Vars: map[string]string{"ansible_user": "root"},
			Hosts: []inventory.Host{{
				Name: "db-01", AnsibleHost: "10.0.0.31", Roles: []string{"linux-servers"},
				Extra: map[string]string{},
			}},
		}
	}

	// The pre-feature canonical shape, reproduced verbatim.
	type legacyHostCanon struct {
		Name                   string
		AnsibleHost            string
		AnsibleUser            string
		SSHKeyFile             string
		Roles                  []string
		Env                    string
		DeploymentAvailability string
		Extra                  map[string]string
	}
	legacy := jsonHash(struct {
		Vars  map[string]string
		Hosts []legacyHostCanon
	}{
		Vars: map[string]string{"ansible_user": "root"},
		Hosts: []legacyHostCanon{{
			Name: "db-01", AnsibleHost: "10.0.0.31", Roles: []string{"linux-servers"},
			Extra: map[string]string{},
		}},
	})

	unset := canonicalInventoryHash(base())
	if unset != legacy {
		t.Fatalf("hash of a host without ssh_recording changed: got %s, pre-feature %s", unset, legacy)
	}

	withPolicy := base()
	withPolicy.Hosts[0].SSHRecording = inventory.SSHRecordingTerminalOutput
	if got := canonicalInventoryHash(withPolicy); got == unset {
		t.Fatal("setting ssh_recording did not change the canonical inventory hash")
	}

	off := base()
	off.Hosts[0].SSHRecording = inventory.SSHRecordingOff
	if canonicalInventoryHash(off) == canonicalInventoryHash(withPolicy) {
		t.Fatal("off and terminal_output hash identically")
	}
}
