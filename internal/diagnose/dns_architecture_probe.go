package diagnose

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// pilot_diagnose_dns_architecture's live probes. Each probe is one fixed
// POSIX sh script run through the `command` module as
// argv ["sh", "-c", <script>, "pilot-dnsarch", <validated args>...]: the
// script text is a code-defined literal, and every inventory- or
// operator-derived value reaches it only as a positional argument, never
// spliced into the script, so a value is never interpreted by a shell.
// The args are passed to Ansible as a JSON object, which Ansible still
// templates, so the scripts must not contain a Jinja delimiter
// (TestDNSArchScriptsHaveNoJinjaDelimiters).
//
// A script prints one delimited section per fact:
//
//	@@pilot-dnsarch <key> begin
//	<command output>
//	@@pilot-dnsarch <key> end rc=<exit code>
//
// so one step per host still reports each fact independently: a failed
// query never hides the next one.

const dnsArchMarker = "@@pilot-dnsarch "

// dnsArchProviderScript runs on a FreeIPA DNS provider. Args: domain,
// provider IP, internal probe name. Every query goes to the provider's own
// service address with RD=0, so an answer is FreeIPA's authoritative data,
// not something named resolved recursively.
const dnsArchProviderScript = `d=$1
ip=$2
iname=$3
q() {
  echo "@@pilot-dnsarch $1 begin"
  dig +norec +time=2 +tries=2 +noall +comments +answer "@$ip" "$2" "$3" 2>&1
  echo "@@pilot-dnsarch $1 end rc=$?"
}
echo "@@pilot-dnsarch whoami begin"
id -un 2>&1
echo "@@pilot-dnsarch whoami end rc=$?"
echo "@@pilot-dnsarch named begin"
systemctl is-active named 2>&1
echo "@@pilot-dnsarch named end rc=$?"
q soa "$d." SOA
q ns "$d." NS
q srv_ldap "_ldap._tcp.$d." SRV
q srv_kerberos "_kerberos._udp.$d." SRV
q internal "$iname" A
exit 0
`

// dnsArchAuthScript runs on one FreeIPA server with the operator-approved
// read-only principal. Args: principal, keytab path. The ticket lives in a
// private FILE ccache that is destroyed on exit (also on SIGHUP/INT/TERM);
// the host's default ccache, and any admin ticket in it, is never read.
// Nothing here can obtain an admin ticket: kinit only ever uses the given
// keytab.
const dnsArchAuthScript = `p=$1
kt=$2
echo "@@pilot-dnsarch whoami begin"
id -un 2>&1
echo "@@pilot-dnsarch whoami end rc=$?"
cc=$(mktemp /tmp/pilot-dnsarch-krb5cc.XXXXXX) || { echo "@@pilot-dnsarch kinit begin"; echo "mktemp failed"; echo "@@pilot-dnsarch kinit end rc=1"; exit 0; }
trap "kdestroy -q -c FILE:$cc >/dev/null 2>&1; rm -f $cc" EXIT
trap "exit 1" HUP INT TERM
KRB5CCNAME="FILE:$cc"
export KRB5CCNAME
echo "@@pilot-dnsarch kinit begin"
kinit -k -t "$kt" "$p" 2>&1
rc=$?
echo "@@pilot-dnsarch kinit end rc=$rc"
[ "$rc" -eq 0 ] || exit 0
echo "@@pilot-dnsarch dnsconfig begin"
ipa dnsconfig-show --all --rights 2>&1
echo "@@pilot-dnsarch dnsconfig end rc=$?"
echo "@@pilot-dnsarch dnsserver begin"
ipa dnsserver-find --all --sizelimit=20 2>&1
echo "@@pilot-dnsarch dnsserver end rc=$?"
echo "@@pilot-dnsarch forwardzones begin"
ipa dnsforwardzone-find --all --sizelimit=50 2>&1
echo "@@pilot-dnsarch forwardzones end rc=$?"
echo "@@pilot-dnsarch zones begin"
ipa dnszone-find --pkey-only --sizelimit=50 2>&1
echo "@@pilot-dnsarch zones end rc=$?"
exit 0
`

// dnsArchTierScript runs on one dns tier host. Args: internal probe name,
// external probe name ("." means the root NS set, the dns role's own G6/G8
// external check), FreeIPA domain ("-" when there is none), then every
// FreeIPA DNS server IP the tier stubs to. The last part repeats the dns
// role's G5 probe (+norec SOA must come back NOERROR with aa) from the tier
// itself, so a provider the tier cannot reach shows up here even when SSH
// to that provider works.
const dnsArchTierScript = `iname=$1
ename=$2
dom=$3
shift 3
sec() {
  key=$1
  shift
  echo "@@pilot-dnsarch $key begin"
  "$@" 2>&1
  echo "@@pilot-dnsarch $key end rc=$?"
}
sec whoami id -un
sec unbound systemctl is-active unbound
sec forwards unbound-control list_forwards
sec stubs unbound-control list_stubs
sec identity dig +time=2 +tries=1 +short @127.0.0.1 id.server CH TXT
if [ "$iname" != "-" ]; then
  sec internal dig +time=2 +tries=1 +noall +comments +answer @127.0.0.1 "$iname" A
fi
if [ "$ename" = "." ]; then
  sec external dig +time=2 +tries=1 +noall +comments +answer @127.0.0.1 . NS
else
  sec external dig +time=2 +tries=1 +noall +comments +answer @127.0.0.1 "$ename" A
fi
if [ "$dom" != "-" ]; then
  for ip in "$@"; do
    sec "authority@$ip" dig +norec +time=2 +tries=1 +noall +comments "@$ip" "$dom." SOA
  done
fi
exit 0
`

// dnsArchClientScript runs on the requested client host. Args: internal
// probe name. It reads the resolver the host actually uses and asks the
// first nameserver who it is: a dns tier host answers id.server CH TXT with
// "pilot-dns:<name>" (docs/verification/dns.md C18/C20).
const dnsArchClientScript = `iname=$1
sec() {
  key=$1
  shift
  echo "@@pilot-dnsarch $key begin"
  "$@" 2>&1
  echo "@@pilot-dnsarch $key end rc=$?"
}
sec whoami id -un
sec nameservers awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf
sec options awk '$1 == "options"' /etc/resolv.conf
sec resolved systemctl is-active systemd-resolved
sec resolvectl resolvectl dns
ns=$(awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)
if [ -n "$ns" ]; then
  sec first_hop dig +time=2 +tries=1 +short "@$ns" id.server CH TXT
fi
sec lookup getent hosts "$iname"
exit 0
`

// dnsArchStep builds one script step. The JSON form keeps every arg one
// argv element.
func dnsArchStep(id, description, script string, args ...string) Step {
	argv := append([]string{"sh", "-c", script, "pilot-dnsarch"}, args...)
	raw, err := json.Marshal(map[string]any{"argv": argv})
	if err != nil {
		// json.Marshal of a map of string slices cannot fail.
		panic(err)
	}
	return Step{ID: id, Description: description, Module: "command", Command: string(raw)}
}

// DNSArchProviderStep probes one FreeIPA DNS provider's authoritative data.
func DNSArchProviderStep(host, domain, ip, internalName string) Step {
	return dnsArchStep("provider-"+host, "FreeIPA DNS provider "+host+": named state and authoritative SOA/NS/SRV answers (+norec)", dnsArchProviderScript, domain, ip, internalName)
}

// DNSArchAuthStep reads FreeIPA's DNS configuration with the approved
// read-only principal.
func DNSArchAuthStep(host, principal, keytab string) Step {
	return dnsArchStep("freeipa-config-"+host, "FreeIPA DNS configuration via the approved read-only principal (private ccache, destroyed on exit)", dnsArchAuthScript, principal, keytab)
}

// DNSArchTierStep probes one dns tier host.
func DNSArchTierStep(host, internalName, externalName, domain string, providerIPs []string) Step {
	if domain == "" {
		domain = "-"
	}
	if internalName == "" {
		internalName = "-"
	}
	args := append([]string{internalName, externalName, domain}, providerIPs...)
	return dnsArchStep("tier-"+host, "dns tier host "+host+": unbound state, forward/stub zones, identity, resolution through the tier and its reach to FreeIPA", dnsArchTierScript, args...)
}

// DNSArchClientStep probes the requested client's resolver.
func DNSArchClientStep(host, internalName string) Step {
	return dnsArchStep("client-"+host, "client "+host+": resolv.conf, systemd-resolved, first hop identity and an NSS lookup", dnsArchClientScript, internalName)
}

// ---- section parsing ----------------------------------------------------------

// DNSArchSection is one delimited section of a probe's stdout.
type DNSArchSection struct {
	Output   string
	RC       int
	Complete bool
}

// ParseDNSArchSections splits a probe's stdout into its sections. A
// section without an end marker (the step timed out mid-way) is returned
// with Complete false.
func ParseDNSArchSections(stdout string) map[string]DNSArchSection {
	out := map[string]DNSArchSection{}
	var key string
	var body []string
	open := false
	for _, line := range strings.Split(stdout, "\n") {
		rest, isMarker := strings.CutPrefix(line, dnsArchMarker)
		if !isMarker {
			if open {
				body = append(body, line)
			}
			continue
		}
		fields := strings.Fields(rest)
		switch {
		case len(fields) == 2 && fields[1] == "begin":
			if open {
				out[key] = DNSArchSection{Output: strings.Join(body, "\n")}
			}
			key, body, open = fields[0], nil, true
		case len(fields) == 3 && fields[1] == "end" && open && fields[0] == key:
			rc, err := strconv.Atoi(strings.TrimPrefix(fields[2], "rc="))
			if err != nil {
				rc = -1
			}
			out[key] = DNSArchSection{Output: strings.TrimRight(strings.Join(body, "\n"), "\n"), RC: rc, Complete: err == nil}
			open = false
		}
	}
	if open {
		out[key] = DNSArchSection{Output: strings.Join(body, "\n")}
	}
	return out
}

// ---- dig ------------------------------------------------------------------------

// DNSQueryResult is one parsed dig answer.
type DNSQueryResult struct {
	Server        string   `json:"server,omitempty"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	Status        string   `json:"status,omitempty"`
	Flags         []string `json:"flags,omitempty"`
	Authoritative bool     `json:"authoritative"`
	Answers       []string `json:"answers,omitempty"`
	Error         string   `json:"error,omitempty"`
}

var (
	digStatusRe = regexp.MustCompile(`status: ([A-Z]+),`)
	digFlagsRe  = regexp.MustCompile(`^;; flags: ([^;]*);`)
)

// ParseDigComments parses `dig +noall +comments [+answer]` output for one
// query. dig exits 0 for every DNS rcode (NXDOMAIN, SERVFAIL, REFUSED), so
// the outcome is read from the header line, never from rc alone; a missing
// ";; Got answer:" header means no server answered, and the result carries
// dig's own diagnostic as Error instead of being mistaken for "no records"
// (AGENTS.md §5.6).
func ParseDigComments(server, name, qtype, output string, rc int) DNSQueryResult {
	res := DNSQueryResult{Server: server, Name: name, Type: qtype}
	got := false
	var diag []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case line == ";; Got answer:":
			got = true
		case strings.HasPrefix(line, ";; ->>HEADER<<-"):
			if m := digStatusRe.FindStringSubmatch(line); m != nil {
				res.Status = m[1]
			}
		case strings.HasPrefix(line, ";; flags:"):
			if m := digFlagsRe.FindStringSubmatch(line); m != nil {
				res.Flags = strings.Fields(m[1])
				for _, f := range res.Flags {
					if f == "aa" {
						res.Authoritative = true
					}
				}
			}
		case strings.HasPrefix(line, ";"):
			if !got {
				diag = append(diag, strings.TrimLeft(line, "; "))
			}
		default:
			fields := strings.Fields(line)
			if len(fields) >= 5 && strings.EqualFold(fields[3], qtype) {
				res.Answers = append(res.Answers, strings.Join(fields[4:], " "))
			}
		}
	}
	if !got || res.Status == "" {
		res.Error = strings.Join(diag, "; ")
		if res.Error == "" {
			res.Error = strings.TrimSpace(output)
		}
		if res.Error == "" {
			res.Error = fmt.Sprintf("dig exited %d without an answer", rc)
		}
		res.Status = ""
	}
	return res
}

// ---- unbound-control ------------------------------------------------------------

// DNSArchZoneServers is one zone and the servers a resolver sends it to.
type DNSArchZoneServers struct {
	Zone    string   `json:"zone"`
	Servers []string `json:"servers"`
}

// ParseUnboundZoneList parses `unbound-control list_forwards` or
// `list_stubs`: one zone per line, `<zone>. IN <forward|stub> [flags]
// <addr>...`, for example `ipa.pilot.internal. IN stub noprime +i
// 192.0.2.1 192.168.122.2` and `. IN forward 1.1.1.1 9.9.9.9`
// (docs/verification/dns.md §0.2, captured from unbound 1.19.2). Flag
// words (prime, noprime, +i, ...) are not servers.
func ParseUnboundZoneList(output, kind string) []DNSArchZoneServers {
	var out []DNSArchZoneServers
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "IN" || fields[2] != kind {
			continue
		}
		zone := DNSArchZoneServers{Zone: fields[0]}
		for _, f := range fields[3:] {
			if f == "prime" || f == "noprime" || strings.HasPrefix(f, "+") {
				continue
			}
			zone.Servers = append(zone.Servers, f)
		}
		out = append(out, zone)
	}
	return out
}

// ---- ipa CLI ----------------------------------------------------------------------

// ParseIPAAttributes parses the "  Label: value" lines `ipa <object>-show`
// and `-find --all` print into entries; a line starting "  <first label>:"
// again, or a "------" separator, starts a new entry. Multi-valued
// attributes are printed comma-separated on one line and returned as such.
func ParseIPAAttributes(output string) []map[string]string {
	var entries []map[string]string
	var cur map[string]string
	firstLabel := ""
	flush := func() {
		if len(cur) > 0 {
			entries = append(entries, cur)
		}
		cur = nil
	}
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "---") {
			if strings.HasPrefix(trimmed, "---") {
				flush()
			}
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			continue
		}
		label, value, ok := strings.Cut(trimmed, ": ")
		if !ok {
			label, ok = strings.CutSuffix(trimmed, ":")
			if !ok {
				continue
			}
			value = ""
		}
		if cur == nil {
			cur = map[string]string{}
			firstLabel = label
		} else if label == firstLabel {
			flush()
			cur = map[string]string{}
		}
		cur[label] = strings.TrimSpace(value)
	}
	flush()
	return entries
}

// firstIPAEntry returns the first entry of an ipa section, or an empty map.
func firstIPAEntry(s DNSArchSection) map[string]string {
	if entries := ParseIPAAttributes(s.Output); len(entries) > 0 {
		return entries[0]
	}
	return map[string]string{}
}

var ipaRightsRe = regexp.MustCompile(`'([A-Za-z0-9-]+)': '([a-z]*)'`)

// ParseIPARights parses the attributelevelrights value `--rights` prints,
// a Python dict repr such as {'idnsforwarders': 'r', 'cn': 'rsc'}, into
// attribute -> rights letters (r read, s search, c compare, w write).
func ParseIPARights(value string) map[string]string {
	out := map[string]string{}
	for _, m := range ipaRightsRe.FindAllStringSubmatch(value, -1) {
		out[strings.ToLower(m[1])] = m[2]
	}
	return out
}

// SplitIPAList splits a multi-valued ipa attribute ("a, b").
func SplitIPAList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// classifyIPAError maps the ipa CLI's failure text to a fact state.
func classifyIPAError(output string) (string, string) {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "insufficient access"):
		return FactPermissionDenied, firstLine(output)
	case strings.Contains(lower, "kerberos credentials"), strings.Contains(lower, "ticket expired"), strings.Contains(lower, "no credentials cache"):
		return FactAuthRequired, firstLine(output)
	case strings.Contains(lower, "command not found"), strings.Contains(lower, "not found") && strings.Contains(lower, "ipa:"):
		return FactUnknown, firstLine(output)
	}
	return FactError, firstLine(output)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
