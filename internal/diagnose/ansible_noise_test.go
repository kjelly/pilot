package diagnose

import (
	"reflect"
	"testing"

	"github.com/kjelly/pilot/internal/networkcheck"
)

func TestAnsibleAutomationUsers_DedupsAcrossHostsAndSorts(t *testing.T) {
	resolved := networkcheck.ResolvedInventory{
		HostVars: map[string]map[string]any{
			"web1": {"ansible_user": "ubuntu"},
			"web2": {"ansible_user": "ansible"},
			"web3": {"ansible_user": "ubuntu"},
		},
	}
	got := AnsibleAutomationUsers(resolved)
	want := []string{"ansible", "ubuntu"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AnsibleAutomationUsers() = %v, want %v", got, want)
	}
}

func TestAnsibleAutomationUsers_MissingOrEmptyIgnored(t *testing.T) {
	resolved := networkcheck.ResolvedInventory{
		HostVars: map[string]map[string]any{
			"web1": {},
			"web2": {"ansible_user": ""},
			"web3": {"ansible_user": 123}, // wrong type — never a string in real ansible-inventory output
		},
	}
	if got := AnsibleAutomationUsers(resolved); got != nil {
		t.Fatalf("AnsibleAutomationUsers() = %v, want nil", got)
	}
}

func TestExcludeAnsibleNoise_AlwaysExcludesBecomeSuccessMarker(t *testing.T) {
	got := ExcludeAnsibleNoise(`{job="pilot-siem"}`, nil)
	want := `{job="pilot-siem"} !~ "BECOME-SUCCESS-"`
	if got != want {
		t.Fatalf("ExcludeAnsibleNoise() = %q, want %q", got, want)
	}
}

func TestExcludeAnsibleNoise_AppendsAnsibleUsersAsAlternation(t *testing.T) {
	got := ExcludeAnsibleNoise(`{job="pilot-siem"}`, []string{"ansible", "ubuntu"})
	want := `{job="pilot-siem"} !~ "BECOME-SUCCESS-" !~ "ansible|ubuntu"`
	if got != want {
		t.Fatalf("ExcludeAnsibleNoise() = %q, want %q", got, want)
	}
}

func TestExcludeAnsibleNoise_QuoteMetasEachUser(t *testing.T) {
	got := ExcludeAnsibleNoise(`{job="pilot-siem"}`, []string{"svc.deploy+1"})
	want := `{job="pilot-siem"} !~ "BECOME-SUCCESS-" !~ "svc\\.deploy\\+1"`
	if got != want {
		t.Fatalf("ExcludeAnsibleNoise() = %q, want %q — regex metacharacters in a username must be escaped", got, want)
	}
}
