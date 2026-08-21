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

func TestFailureSummarySurfacesPerItemErrorsForLoopTask(t *testing.T) {
	out := `TASK [Refresh SSSD caches on enrolled FreeIPA clients] ********
fatal: [freeipa -> {{ item }}]: FAILED! => {"msg": "All items completed", "results": [` +
		`{"item": "client-1.example.com", "failed": true, "msg": "ssh: connect to host client-1.example.com port 22: Connection refused"}, ` +
		`{"item": "client-2.example.com", "failed": false, "msg": "cache refreshed"}` +
		`]}
`
	got := FailureSummary(out)
	if strings.Contains(got, "{{ item }}") {
		t.Fatalf("FailureSummary() = %q, should not leak unresolved {{ item }} template", got)
	}
	if !strings.Contains(got, "host=freeipa (fatal)") {
		t.Fatalf("FailureSummary() = %q, missing clean host= line", got)
	}
	if !strings.Contains(got, "item=client-1.example.com") {
		t.Fatalf("FailureSummary() = %q, missing failing item", got)
	}
	if !strings.Contains(got, "msg=ssh: connect to host client-1.example.com port 22: Connection refused") {
		t.Fatalf("FailureSummary() = %q, missing real per-item msg", got)
	}
	if strings.Contains(got, "client-2.example.com") {
		t.Fatalf("FailureSummary() = %q, should not report the item that succeeded", got)
	}
	if strings.Contains(got, "msg=All items completed") {
		t.Fatalf("FailureSummary() = %q, should not print the uninformative aggregate msg", got)
	}
}

func TestFailureSummaryKeepsResolvedDelegateHost(t *testing.T) {
	out := "TASK [Check] ********\nfatal: [ctrl -> node-3.example.com]: FAILED! => {\"msg\": \"boom\"}\n"
	got := FailureSummary(out)
	if !strings.Contains(got, "host=ctrl -> node-3.example.com") {
		t.Fatalf("FailureSummary() = %q, should keep a resolved delegate host", got)
	}
}
