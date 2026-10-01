package decommission

import (
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestStageScopeArgs(t *testing.T) {
	scope := func(auth StageAuthorization) *StageScope {
		return NewStageScope([]inventory.Host{
			{Name: "sbx", Roles: []string{"docker"}},
			{Name: "sbx2", Env: "sandbox", Roles: []string{"docker"}},
			{Name: "stg", Env: "staging", Roles: []string{"freeipa-client"}},
			{Name: "ipa", Env: "prod", Roles: []string{"freeipa-server"}},
			{Name: "ipa2", Env: "prod", Roles: []string{"freeipa-server"}},
		}, auth)
	}
	none := StageAuthorization{StagingAttestedWithinHours: -1}
	full := StageAuthorization{ConfirmStaging: true, ConfirmProd: true, StagingAttestedWithinHours: 24}
	sandbox := []string{"-e", "stage=sandbox"}
	cases := []struct {
		name  string
		auth  StageAuthorization
		hosts []string
		want  []string
		class ErrorClass
		msg   string
	}{
		{"sandbox needs no confirmation", none, []string{"sbx", "sbx2"}, sandbox, "", ""},
		{"no hosts", none, nil, sandbox, "", ""},
		{"host not in hosts.yml counts as sandbox", none, []string{"gone"}, sandbox, "", ""},
		{"staging without confirmation", none, []string{"stg"}, nil, ErrStageConfirmationRequired, "--confirm-staging"},
		{"staging confirmed", full, []string{"stg"}, []string{"-e", "stage=staging", "-e", "confirm_staging=true"}, "", ""},
		{"prod without confirmation", StageAuthorization{ConfirmStaging: true, StagingAttestedWithinHours: 24}, []string{"ipa"}, nil, ErrStageConfirmationRequired, "--confirm-prod"},
		{"prod confirmed without hours", StageAuthorization{ConfirmProd: true, StagingAttestedWithinHours: -1}, []string{"ipa"}, nil, ErrStageConfirmationRequired, "got none"},
		{"prod attestation older than a week", StageAuthorization{ConfirmProd: true, StagingAttestedWithinHours: 169}, []string{"ipa"}, nil, ErrStageConfirmationRequired, "got 169"},
		{"prod confirmed", full, []string{"ipa", "ipa2"}, []string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=24"}, "", ""},
		{"prod at the 168 h limit", StageAuthorization{ConfirmProd: true, StagingAttestedWithinHours: 168}, []string{"ipa"}, []string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=168"}, "", ""},
		{"hosts in different stages", full, []string{"stg", "ipa", "sbx"}, nil, ErrStageMixed, "prod: ipa; sandbox: sbx; staging: stg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scope(tc.auth).Args(tc.hosts)
			if tc.class != "" {
				if err == nil || ClassOf(err) != tc.class {
					t.Fatalf("Args() = %v, %v; want a %s error", got, err, tc.class)
				}
				if !strings.Contains(err.Error(), tc.msg) {
					t.Fatalf("error %q does not mention %q", err, tc.msg)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Fatalf("Args() = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

func TestStageScopeGroups(t *testing.T) {
	s := NewStageScope([]inventory.Host{
		{Name: "b", Roles: []string{"freeipa-server", "docker"}},
		{Name: "a", Roles: []string{"wazuh-manager"}},
	}, StageAuthorization{StagingAttestedWithinHours: -1})
	if got := s.RoleHosts("freeipa-server"); !slices.Equal(got, []string{"b"}) {
		t.Errorf("RoleHosts(freeipa-server) = %v", got)
	}
	if got := s.RoleHosts("nothing"); len(got) != 0 {
		t.Errorf("RoleHosts(nothing) = %v", got)
	}
	if got := s.AllHosts(); !slices.Equal(got, []string{"a", "b"}) {
		t.Errorf("AllHosts() = %v", got)
	}
	var nilScope *StageScope
	if args, err := nilScope.Args([]string{"b"}); args != nil || err != nil {
		t.Errorf("nil scope Args() = %v, %v; want nil, nil", args, err)
	}
}
