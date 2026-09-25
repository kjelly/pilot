package directoryapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/accessdirectory"
	"github.com/kjelly/pilot/internal/accessportal"
)

func TestToTargetJSON_RecordingStatus(t *testing.T) {
	cases := []struct {
		p    accessportal.SSHRecordingAccessPolicy
		want string
	}{
		{accessportal.SSHRecordingAccessPolicy{Known: true, Valid: true}, "inherit"},
		{accessportal.SSHRecordingAccessPolicy{Known: true, Valid: true, Override: "terminal_output"}, "terminal_output"},
		{accessportal.SSHRecordingAccessPolicy{Reason: "host_show_failed"}, "unknown"},
		{accessportal.SSHRecordingAccessPolicy{Known: true, Reason: "malformed"}, "invalid"},
	}
	for _, c := range cases {
		got := toTargetJSON(accessdirectory.DirectoryTarget{FQDN: "a.example", Recording: c.p})
		if got.Recording.Status != c.want {
			t.Errorf("Recording.Status = %q, want %q", got.Recording.Status, c.want)
		}
		b, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"recording":{"status":"`+c.want+`"}`) {
			t.Errorf("JSON %s lacks recording.status %q", b, c.want)
		}
		if strings.Contains(string(b), "effective") {
			t.Errorf("Directory JSON must not claim an effective mode: %s", b)
		}
	}
}
