package diagnose

import (
	"fmt"
	"strings"
)

// DNSSteps returns the fixed, read-only ad-hoc commands used to diagnose
// DNS resolution problems: the always-run facts mirror
// docs/verification/core-infra.md §2 (resolv.conf, systemd-resolved) and
// docs/verification/core-infra-provider.md §2 (daemon installed/listening
// on :53), and are deliberately reported as facts rather than a hard-coded
// pass/fail — the two docs expect *opposite* resolv.conf values depending
// on whether the host is a DNS client or a DNS provider, so this check
// must not assume either role. When name is non-empty (already validated
// via inventory.ValidDNSRecordName) two more steps resolve it both via NSS
// and directly against the loopback resolver, since comparing those two is
// what actually localizes an nsswitch misconfiguration vs. an unreachable
// upstream.
func DNSSteps(name string) []Step {
	steps := []Step{
		{ID: "resolv-nameserver", Description: "first nameserver in /etc/resolv.conf", Module: "command", Command: `awk 'NR==1{print $2}' /etc/resolv.conf`},
		{ID: "resolved-active", Description: "systemd-resolved service active", Module: "command", Command: "systemctl is-active systemd-resolved"},
		{ID: "daemon-listening", Description: "a non-stub DNS daemon is listening on :53", Module: "shell", Command: `ss -tulnH | grep ":53 " | grep -v "127.0.0.53" | head -n1`},
		{ID: "daemon-installed", Description: "a DNS daemon package (unbound/bind9/dnsmasq) is installed", Module: "shell", Command: `dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}"`},
	}
	if name != "" {
		steps = append(steps,
			Step{ID: "nss-resolve", Description: "resolves via NSS (getent hosts)", Module: "command", Command: fmt.Sprintf("getent hosts %s", name)},
			Step{ID: "direct-resolve", Description: "resolves via a direct query against the loopback resolver", Module: "command", Command: fmt.Sprintf("dig +short %s @127.0.0.1", name)},
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

	if r, ok := find("resolv-nameserver"); ok && r.Result.RunErr == nil && r.Result.RC == 0 {
		out.Nameserver = strings.TrimSpace(r.Result.Stdout)
	}
	if r, ok := find("resolved-active"); ok && r.Result.RunErr == nil {
		out.SystemdResolvedActive = r.Result.RC == 0
	}
	if r, ok := find("daemon-listening"); ok && r.Result.RunErr == nil {
		out.LocalDaemonListening = strings.TrimSpace(r.Result.Stdout) != ""
	}
	if r, ok := find("daemon-installed"); ok && r.Result.RunErr == nil {
		out.DNSDaemonInstalled = strings.TrimSpace(r.Result.Stdout) == "1"
	}
	if out.NameQueried {
		if r, ok := find("nss-resolve"); ok && r.Result.RunErr == nil {
			out.ResolvesViaNSS = r.Result.RC == 0
		}
		if r, ok := find("direct-resolve"); ok && r.Result.RunErr == nil {
			out.ResolvesViaDirectQuery = strings.TrimSpace(r.Result.Stdout) != ""
		}
	}

	switch {
	case out.NameQueried && out.ResolvesViaNSS && out.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("%q resolves both via NSS and directly against the loopback resolver — DNS resolution is working for this name", name)
	case out.NameQueried && !out.ResolvesViaNSS && out.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("%q resolves via a direct query against 127.0.0.1 but not via NSS (getent) — nsswitch.conf's \"hosts\" line likely doesn't route through the local resolver", name)
	case out.NameQueried && out.ResolvesViaNSS && !out.ResolvesViaDirectQuery:
		out.Verdict = fmt.Sprintf("%q resolves via NSS but not via a direct query against 127.0.0.1 — NSS may be using a different resolution path (e.g. /etc/hosts) than the local DNS daemon", name)
	case out.NameQueried && !out.LocalDaemonListening && !out.SystemdResolvedActive:
		out.Verdict = fmt.Sprintf("%q does not resolve, and no local resolver (systemd-resolved or a DNS daemon) appears to be listening on this host", name)
	case out.NameQueried:
		out.Verdict = fmt.Sprintf("%q does not resolve via NSS or a direct query against 127.0.0.1, even though a local resolver appears to be running — check the resolver's own zone/upstream configuration", name)
	default:
		out.Verdict = "facts only — supply a name to test actual resolution via NSS and a direct loopback query"
	}
	return out
}
