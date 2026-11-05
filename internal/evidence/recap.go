package evidence

import (
	"regexp"
	"strconv"
	"strings"
)

// HostRecap is one host's line of an ansible PLAY RECAP.
type HostRecap struct {
	Ok          int `json:"ok"`
	Changed     int `json:"changed"`
	Unreachable int `json:"unreachable"`
	Failed      int `json:"failed"`
	Skipped     int `json:"skipped"`
	Rescued     int `json:"rescued"`
	Ignored     int `json:"ignored"`
}

var recapLineRe = regexp.MustCompile(
	`^(\S+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)(?:\s+skipped=(\d+))?(?:\s+rescued=(\d+))?(?:\s+ignored=(\d+))?`)

// ParseRecap reads ONLY the PLAY RECAP block(s) of ansible-playbook output
// and returns the per-host counts, keyed by host, and whether a recap was
// present at all. Scoping to the recap avoids task or debug lines that merely
// print the substring "changed=1". When the output holds several recaps (one
// ansible-playbook run after another), the later line for a host wins.
func ParseRecap(output string) (map[string]HostRecap, bool) {
	hosts := map[string]HostRecap{}
	found := false
	inRecap := false
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "PLAY RECAP") {
			inRecap, found = true, true
			continue
		}
		if !inRecap {
			continue
		}
		m := recapLineRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			if strings.TrimSpace(line) == "" {
				continue // ansible prints a blank line before the recap body
			}
			inRecap = false // first non-host line ends the block
			continue
		}
		atoi := func(s string) int {
			n, _ := strconv.Atoi(s)
			return n
		}
		hosts[m[1]] = HostRecap{Ok: atoi(m[2]), Changed: atoi(m[3]), Unreachable: atoi(m[4]), Failed: atoi(m[5]),
			Skipped: atoi(m[6]), Rescued: atoi(m[7]), Ignored: atoi(m[8])}
	}
	return hosts, found
}

// TotalChanged sums the changed count over every host of a recap.
func TotalChanged(recap map[string]HostRecap) int {
	total := 0
	for _, h := range recap {
		total += h.Changed
	}
	return total
}

// VerifyVerdict is the summary line `pilot verify` prints.
type VerifyVerdict struct {
	Verdict string `json:"verdict"`
	Pass    int    `json:"pass"`
	Fail    int    `json:"fail"`
	Skip    int    `json:"skip"`
}

var verifyVerdictRe = regexp.MustCompile(`verdict:\s+\*\*(PASS|FAIL)\*\*\s+\(pass=(\d+) fail=(\d+) skip=(\d+)\)`)

// ParseVerifyVerdict finds the last `verdict: **PASS**  (pass=N fail=N
// skip=N)` line of `pilot verify` output.
func ParseVerifyVerdict(output string) (VerifyVerdict, bool) {
	all := verifyVerdictRe.FindAllStringSubmatch(output, -1)
	if len(all) == 0 {
		return VerifyVerdict{}, false
	}
	m := all[len(all)-1]
	atoi := func(s string) int {
		n, _ := strconv.Atoi(s)
		return n
	}
	return VerifyVerdict{Verdict: m[1], Pass: atoi(m[2]), Fail: atoi(m[3]), Skip: atoi(m[4])}, true
}
