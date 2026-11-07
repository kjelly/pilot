package identityreconcile

import (
	"fmt"
	"testing"
)

// The server log lines below are captured from the disposable FreeIPA server of the live runs (the
// remote address and the process ids are removed). They are the forms a write is logged in: the
// JSON-RPC client's commands inside a batch (the command line and the outer session line), a command
// the ipa CLI sent (with the version suffix "/1" on the commands that have versions), and the
// reads and the session lines that are not writes.
const logPrefix = "[Fri Nov 06 23:10:57.956456 2026] [wsgi:error] [pid 0:tid 0] [remote 0.0.0.0:0] ipa: INFO: "

var capturedLogLines = []struct {
	name  string
	line  string
	count string // the method it counts for, "" for none
}{
	{"a batched command", logPrefix + "admin@IPA.PILOT.INTERNAL: batch: user_add('p26-n17', givenname='P26', sn='n17', homedirectory='/home/p26-n17', loginshell='/bin/bash', version='2.257'): SUCCESS", "user_add"},
	{"the same batch's session line", logPrefix + "[jsonserver_session] admin@IPA.PILOT.INTERNAL: batch(user_add('p26-n17', givenname='P26', sn='n17', homedirectory='/home/p26-n17', loginshell='/bin/bash', version='2.257')): SUCCESS", ""},
	{"a password set by the ipa CLI", logPrefix + "[jsonserver_session] admin@IPA.PILOT.INTERNAL: passwd/1('p26-dan', '********', '********', version='2.257'): SUCCESS", "passwd"},
	{"a member added by the ipa CLI", logPrefix + "[jsonserver_kerb] admin@IPA.PILOT.INTERNAL: group_add_member/1('team-p26', version='2.257', user=('p26-eve',)): SUCCESS", "group_add_member"},
	{"a group read", logPrefix + "[jsonserver_session] admin@IPA.PILOT.INTERNAL: group_find(None, timelimit=0, sizelimit=0, all=True, version='2.257'): SUCCESS", ""},
	{"a user read that found nothing", logPrefix + "[jsonserver_kerb] admin@IPA.PILOT.INTERNAL: user_show/1('p26-n19e', version='2.257'): NotFound", ""},
	{"a session logout", logPrefix + "[jsonserver_session] admin@IPA.PILOT.INTERNAL: session_logout(version='2.257'): SUCCESS", ""},
}

// Every captured line counts for the method it is a write of, or for none; both the lines that must
// count and the lines that must not are the server's own. Without the version suffix in the matcher
// the CLI's writes were not counted (A19(a) expected the external passwd and saw 0), and without the
// batch rule a batched write counted twice (A17 saw two user_add for one).
func TestWriteLogLinesAreCountedOncePerCommand(t *testing.T) {
	for _, c := range capturedLogLines {
		got := countWriteLines([]string{c.line})
		want := map[string]int{}
		if c.count != "" {
			want[c.count] = 1
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s: counted %v, want %v", c.name, got, want)
		}
	}
	var all []string
	for _, c := range capturedLogLines {
		all = append(all, c.line)
	}
	if got, want := fmt.Sprint(countWriteLines(all)), "map[group_add_member:1 passwd:1 user_add:1]"; got != want {
		t.Errorf("all lines counted %s, want %s", got, want)
	}
}
