package evidence

import "testing"

// A real ansible-core 2.19 recap (three hosts) preceded by task output that
// prints the substring "changed=1" outside the recap.
const sampleOutput = `TASK [debug] ***
ok: [ipa] => {"msg": "changed=1 is only text here"}

PLAY RECAP *********************************************************************
el9                        : ok=162  changed=0    unreachable=0    failed=0    skipped=48   rescued=0    ignored=0
ipa                        : ok=331  changed=0    unreachable=0    failed=0    skipped=94   rescued=0    ignored=0
ubu                        : ok=180  changed=3    unreachable=0    failed=1    skipped=51   rescued=1    ignored=0

Wednesday 01 November 2026  05:48:00 +0000 (0:00:01.001)       0:17:21.201 ****
`

func TestParseRecapReadsOnlyTheRecapBlock(t *testing.T) {
	hosts, ok := ParseRecap(sampleOutput)
	if !ok {
		t.Fatal("recap not found")
	}
	if len(hosts) != 3 {
		t.Fatalf("hosts = %v", hosts)
	}
	if got := hosts["ubu"]; got != (HostRecap{Ok: 180, Changed: 3, Failed: 1, Skipped: 51, Rescued: 1}) {
		t.Fatalf("ubu = %+v", got)
	}
	if TotalChanged(hosts) != 3 {
		t.Fatalf("total changed = %d", TotalChanged(hosts))
	}
	if _, ok := ParseRecap("TASK [x] ***\nok: [h] => changed=1\n"); ok {
		t.Fatal("output without PLAY RECAP must not report a recap")
	}
}

func TestParseRecapLaterRunWins(t *testing.T) {
	two := sampleOutput + "\nPLAY RECAP ****\nubu : ok=1 changed=0 unreachable=0 failed=0 skipped=0 rescued=0 ignored=0\n"
	hosts, _ := ParseRecap(two)
	if hosts["ubu"].Changed != 0 || hosts["el9"].Ok != 162 {
		t.Fatalf("hosts = %v", hosts)
	}
}

func TestParseVerifyVerdict(t *testing.T) {
	out := "row C1 PASS\n\nverdict: **PASS**  (pass=24 fail=0 skip=0)\n"
	v, ok := ParseVerifyVerdict(out)
	if !ok || v != (VerifyVerdict{Verdict: "PASS", Pass: 24}) {
		t.Fatalf("verdict = %+v ok=%v", v, ok)
	}
	v, ok = ParseVerifyVerdict("verdict: **FAIL**  (pass=23 fail=1 skip=0)\nverdict: **PASS**  (pass=24 fail=0 skip=0)\n")
	if !ok || v.Verdict != "PASS" || v.Pass != 24 {
		t.Fatalf("last verdict should win: %+v", v)
	}
	if _, ok := ParseVerifyVerdict("no verdict here"); ok {
		t.Fatal("absent verdict must not parse")
	}
}
