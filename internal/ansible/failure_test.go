package ansible

import (
	"strings"
	"testing"
)

func TestFailureSummaryIncludesHostTaskAndMessage(t *testing.T) {
	out := `PLAY [deploy] ********
TASK [Install package] ********
fatal: [web-1]: FAILED! => {"changed": false, "msg": "No package nginx available"}
PLAY RECAP ********
web-1 : ok=1 changed=0 unreachable=0 failed=1 skipped=0
`
	got := FailureSummary(out)
	for _, want := range []string{"Ansible 失敗摘要", "host=web-1", "task=Install package", "msg=No package nginx available"} {
		if !strings.Contains(got, want) {
			t.Fatalf("FailureSummary() = %q, missing %q", got, want)
		}
	}
}

func TestFailureSummaryHandlesUnreachableAndNoisyMessage(t *testing.T) {
	out := "TASK [Connect] ********\nunreachable: [db-1]: UNREACHABLE! => {\"msg\": \"ssh: connect\\n refused\"}\n"
	got := FailureSummary(out)
	if !strings.Contains(got, "host=db-1 (unreachable)") || !strings.Contains(got, "ssh: connect refused") {
		t.Fatalf("FailureSummary() = %q", got)
	}
}

func TestFailureSummaryEmptyWhenNoFailure(t *testing.T) {
	if got := FailureSummary("TASK [ok] ********\nok: [web-1]\n"); got != "" {
		t.Fatalf("FailureSummary() = %q, want empty", got)
	}
}
