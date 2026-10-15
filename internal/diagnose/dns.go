package diagnose

import (
	"fmt"
	"net"
	"strings"
)

// DNSSteps returns the fixed, read-only ad-hoc commands used to diagnose
// DNS resolution problems: the always-run facts mirror
// docs/verification/core-infra.md §2 (resolv.conf, systemd-resolved) and
// docs/verification/dns.md (daemon installed/listening on :53), and are
// deliberately reported as facts rather than a hard-coded
// pass/fail — the two docs expect *opposite* resolv.conf values depending
// on whether the host is a DNS client or a DNS provider, so this check
// must not assume either role. When name is non-empty (already validated
// via inventory.ValidDNSRecordName) two more steps resolve it both via NSS
// and directly against the loopback resolver. These are independent paths:
// a client using a remote resolver need not have a loopback DNS service.
func DNSSteps(name string) []Step {
	steps := []Step{
		{ID: "resolv-nameserver", Description: "first nameserver in /etc/resolv.conf", Module: "command", Command: `awk '$1 == "nameserver" {print $2; exit}' /etc/resolv.conf`},
		{ID: "resolved-active", Description: "systemd-resolved service active", Module: "command", Command: "systemctl is-active systemd-resolved"},
		{ID: "daemon-listening", Description: "a non-stub DNS daemon is listening on :53", Module: "shell", Command: `ss -tulnH | grep ":53 " | grep -v "127.0.0.53" | head -n1`},
		{ID: "daemon-installed", Description: "a DNS daemon package (unbound/bind9/dnsmasq) is installed", Module: "shell", Command: `dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}"`},
	}
	if name != "" {
		steps = append(steps,
			Step{ID: "nss-resolve", Description: "resolves via NSS (getent hosts)", Module: "command", Command: fmt.Sprintf("getent hosts %s", name)},
			Step{ID: "direct-resolve", Description: "resolves via a direct A query against the loopback resolver", Module: "command", Command: fmt.Sprintf("dig +time=2 +tries=1 +noall +comments +answer %s @127.0.0.1 A", name)},
		)
	}
	return steps
}

// DNSOutput is the dns check's typed result: raw per-step evidence plus a
// synthesized verdict. See DNSSteps' doc comment for why resolv.conf's
// nameserver is reported as a bare fact rather than judged pass/fail.
type DNSOutput struct {
	Nameserver             string
	SystemdResolvedActive  bool
	LocalDaemonListening   bool
	DNSDaemonInstalled     bool
	NameQueried            bool
	ResolvesViaNSS         bool
	ResolvesViaDirectQuery bool
	Verdict                string
	Steps                  []StepResult
}

// BuildDNSOutput synthesizes DNSOutput from DNSSteps' results. results must
// be in the exact order DNSSteps(name) returned them.
func BuildDNSOutput(name string, results []StepResult) DNSOutput {
	find := func(id string) (StepResult, bool) {
		for _, r := range results {
			if r.Step.ID == id {
				return r, true
			}
		}
		return StepResult{}, false
	}

	out := DNSOutput{Steps: results, NameQueried: name != ""}

	succeeded := func(r StepResult) bool {
		return r.Result.RunErr == nil && !r.Result.Failed && !r.Result.Unreachable && r.Result.RC == 0
	}
	ns, nsFound := find("resolv-nameserver")
	if nsFound && succeeded(ns) {
		out.Nameserver = strings.TrimSpace(ns.Result.Stdout)
	}
	if r, ok := find("resolved-active"); ok {
		out.SystemdResolvedActive = succeeded(r)
	}
	if r, ok := find("daemon-listening"); ok && succeeded(r) {
		out.LocalDaemonListening = strings.TrimSpace(r.Result.Stdout) != ""
	}
	if r, ok := find("daemon-installed"); ok && succeeded(r) {
		out.DNSDaemonInstalled = strings.TrimSpace(r.Result.Stdout) == "1"
	}
	if out.NameQueried {
		if r, ok := find("nss-resolve"); ok && succeeded(r) {
			out.ResolvesViaNSS = strings.TrimSpace(r.Result.Stdout) != ""
		}
		if r, ok := find("direct-resolve"); ok && succeeded(r) {
			query := ParseDigComments("127.0.0.1", name, "A", r.Result.Stdout, r.Result.RC)
			if query.Error == "" && query.Status == "NOERROR" {
				for _, answer := range query.Answers {
					if ip := net.ParseIP(answer); ip != nil && ip.To4() != nil {
						out.ResolvesViaDirectQuery = true
						break
					}
				}
			}
		}
	}

	switch {
	case out.NameQueried && out.ResolvesViaNSS && out.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("%q resolves both via NSS and directly against the loopback resolver — DNS resolution is working for this name", name)
	case out.NameQueried && !out.ResolvesViaNSS && out.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("%q resolves via a direct query against 127.0.0.1; the NSS (getent) lookup did not succeed — compare NSS's configured resolution path with this loopback query", name)
	case out.NameQueried && out.ResolvesViaNSS && !out.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("%q resolves via NSS; the direct A query against 127.0.0.1 did not succeed — NSS may use a remote resolver, systemd-resolved's stub, or /etc/hosts; a loopback DNS service is not required", name)
	case out.NameQueried:
		out.Verdict = fmt.Sprintf("%q: neither the NSS lookup nor the direct A query against 127.0.0.1 succeeded — inspect each step's evidence and the configured nameserver; the loopback result alone does not establish remote resolver health", name)
	default:
		out.Verdict = "facts only — supply a name to test actual resolution via NSS and a direct loopback query"
	}
	if nsFound && succeeded(ns) && out.Nameserver == "" {
		out.Verdict += "; /etc/resolv.conf has no nameserver directive"
	}
	return out
}
