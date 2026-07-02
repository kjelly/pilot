package cmd

import (
	"strings"
	"testing"
)

// TestBuildApplyArgs pins the `vm-target test` apply-arg construction: extras
// forwarded verbatim, and -l dropped iff the extras carry a target_group
// (mirroring `vm-target run`).
func TestBuildApplyArgs(t *testing.T) {
	cases := []struct {
		name    string
		extras  []string
		want    string
		wantNoL bool // -l must be absent
	}{
		{
			name: "no extras keeps -l limit",
			want: "pb.yml -i inv.yaml -l alma-vm",
		},
		{
			name:   "plain -e vars keep -l limit",
			extras: []string{"-e", "ipa_server_ip=1.2.3.4", "-e", "@vault"},
			want:   "pb.yml -i inv.yaml -l alma-vm -e ipa_server_ip=1.2.3.4 -e @vault",
		},
		{
			name:    "target_group drops -l limit",
			extras:  []string{"-e", "target_group=all", "-e", "ipa_server_ip=1.2.3.4"},
			want:    "pb.yml -i inv.yaml -e target_group=all -e ipa_server_ip=1.2.3.4",
			wantNoL: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(buildApplyArgs("pb.yml", "inv.yaml", "alma-vm", tc.extras), " ")
			if got != tc.want {
				t.Errorf("buildApplyArgs = %q, want %q", got, tc.want)
			}
			if tc.wantNoL && strings.Contains(got, " -l ") {
				t.Errorf("expected no -l limit, got %q", got)
			}
		})
	}
}
