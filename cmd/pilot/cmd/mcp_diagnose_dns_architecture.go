// mcp_diagnose_dns_architecture.go implements pilot_diagnose_dns_architecture
// (issue #62): one read-only call that answers "how is DNS wired here" —
// the dns tier, the FreeIPA DNS providers, their forwarding, and the client
// resolver path — in four separate layers: what the product supports, what
// the inventory declares, what the canonical playbook rules make of it, and
// what the live hosts show. Live probes are the fixed scripts in
// internal/diagnose/dns_architecture_probe.go; FreeIPA's own DNS
// configuration is read only with the read-only principal the operator
// approved when starting the server (--diagnose-freeipa-principal/-keytab),
// in a private ccache, never with a password and never with whatever ticket
// happens to sit in the host's default cache.
package cmd

import (
	"context"
	"fmt"
	"net"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/diagnose"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// diagnoseFreeIPAReader is the operator-approved read-only principal and the
// path of its keytab on the FreeIPA servers. Both empty means none.
type diagnoseFreeIPAReader struct {
	Principal string
	Keytab    string
}

var (
	// Every component starts with a letter or digit, so no value can be
	// read as a kinit option (-c/tmp@R would pick the ccache).
	freeIPAReaderPrincipalRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?@[A-Z0-9][A-Z0-9._-]*$`)
	freeIPAReaderKeytabRe    = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

// freeIPAPrivilegedPrincipals are principal names (the part before / or
// @, lower-cased) a diagnosis must never authenticate as: administrators,
// and the service principals FreeIPA itself and its servers run with
// (host/, HTTP/, ldap/ and DNS/ keytabs can change the directory or DNS
// data; krbtgt and kadmin are the KDC's own). The KDC's master key
// principal K/M is matched as a whole, not by its first component.
var freeIPAPrivilegedPrincipals = map[string]bool{
	"admin": true, "administrator": true, "root": true,
	"host": true, "http": true, "ldap": true, "dns": true, "dogtag": true, "cifs": true,
	"ipa-dnskeysyncd": true, "ipa-ods-exporter": true, "krbtgt": true, "kadmin": true,
}

// validateFreeIPAReader checks the operator's --diagnose-freeipa-* flags.
// The principal must be a dedicated reader: administrators and FreeIPA's
// own service principals are refused outright, since a diagnosis must
// never run with a ticket that can change anything. A reader whose
// rights on the global DNS configuration (cn=dns, the --rights of
// ipa dnsconfig-show) include write is refused when the call reads them
// (diagnose.KerberosRefusedPrivileged); rights on other entries are not
// inspected, so the reader's role must stay the runbook's read-only one.
func validateFreeIPAReader(r diagnoseFreeIPAReader) error {
	if r.Principal == "" && r.Keytab == "" {
		return nil
	}
	if r.Principal == "" || r.Keytab == "" {
		return fmt.Errorf("--diagnose-freeipa-principal and --diagnose-freeipa-keytab must be given together")
	}
	if !freeIPAReaderPrincipalRe.MatchString(r.Principal) {
		return fmt.Errorf("--diagnose-freeipa-principal %q is not a Kerberos principal of the form name[/host]@REALM", r.Principal)
	}
	name := strings.SplitN(r.Principal, "@", 2)[0]
	primary := strings.ToLower(strings.SplitN(name, "/", 2)[0])
	if freeIPAPrivilegedPrincipals[primary] || strings.EqualFold(name, "K/M") {
		return fmt.Errorf("--diagnose-freeipa-principal must be a dedicated read-only principal, not %s", r.Principal)
	}
	if !freeIPAReaderKeytabRe.MatchString(r.Keytab) || strings.Contains(r.Keytab, "/../") || strings.HasSuffix(r.Keytab, "/..") {
		return fmt.Errorf("--diagnose-freeipa-keytab %q must be an absolute path without spaces or '..'", r.Keytab)
	}
	return nil
}

// maxDNSArchProbeHosts bounds how many providers and tier hosts one call
// probes (each is one ad-hoc step).
const maxDNSArchProbeHosts = 5

// dnsArchComponentIDs are the components whose contracts describe the DNS
// architecture, in the order the report lists them.
var dnsArchComponentIDs = []string{"dns", "freeipa-server", "freeipa-server-replica", "freeipa-dns-client", "internal-endpoint", "freeipa-dns"}

type diagnoseDNSArchitectureInput struct {
	ClientHost   string `json:"client_host,omitempty" jsonschema:"optional exact inventory hostname whose live resolver (resolv.conf, systemd-resolved, first-hop identity) is compared with the resolver list pilot would write for it"`
	InternalName string `json:"internal_name,omitempty" jsonschema:"optional internal DNS name to resolve authoritatively on each FreeIPA DNS provider and through each dns tier host; default: the FreeIPA primary's FQDN"`
	ExternalName string `json:"external_name,omitempty" jsonschema:"optional external DNS name to resolve (A) through each dns tier host; default: the root NS set (.), the dns role's own external self-check"`
}

type dnsArchRun struct {
	RunID      string `json:"run_id"`
	Outcome    string `json:"outcome"`
	FinishedAt string `json:"finished_at,omitempty"`
}

type dnsArchComponent struct {
	ID       string      `json:"id"`
	Role     string      `json:"role,omitempty"`
	Contract string      `json:"contract,omitempty"`
	Product  bool        `json:"in_product"`
	Assigned bool        `json:"assigned"`
	Hosts    []string    `json:"hosts,omitempty"`
	OptIn    bool        `json:"opt_in"`
	LastRun  *dnsArchRun `json:"last_run,omitempty"`
	RunState string      `json:"run_state"`
	Note     string      `json:"note,omitempty"`
}

type dnsArchSupported struct {
	Components   []dnsArchComponent `json:"components"`
	TierModes    []string           `json:"tier_modes"`
	Capabilities []string           `json:"capabilities"`
	NotManaged   []string           `json:"not_managed_by_pilot"`
}

type dnsArchExecution struct {
	ControllerUser string                   `json:"controller_user,omitempty"`
	RemoteUsers    map[string]string        `json:"remote_users,omitempty"`
	Kerberos       diagnose.DNSArchKerberos `json:"kerberos"`
}

type diagnoseDNSArchitectureOutput struct {
	diagnoseAuditStatus
	Status         string                       `json:"status"`
	Findings       []string                     `json:"findings,omitempty"`
	Paths          []string                     `json:"paths"`
	Execution      dnsArchExecution             `json:"execution"`
	Supported      dnsArchSupported             `json:"supported"`
	Declared       []diagnose.DNSArchVar        `json:"declared"`
	Effective      diagnose.DNSArchModel        `json:"effective"`
	Observed       diagnose.DNSArchObserved     `json:"observed"`
	Differences    []diagnose.DNSArchDifference `json:"differences"`
	Steps          []diagnoseStepEvidence       `json:"steps"`
	AuditDirectory string                       `json:"audit_directory"`
}

func registerDiagnoseDNSArchitectureTool(server *mcp.Server, opts diagnoseMCPToolsOptions) {
	addRecoveredTool(server, &mcp.Tool{
		Name:        "pilot_diagnose_dns_architecture",
		Description: "read-only, one-call answer to \"how is DNS wired here\": the dns caching tier, the FreeIPA DNS providers (primary/replica, canonical FQDN, internal zones), FreeIPA forwarding (global forwarders, forward policy, per-server forwarders, forward zones) and each managed host's resolver path (tier first, FreeIPA fallback, explicit overrides). Four layers are kept apart: supported (component contracts), declared (inventory variables, with references), effective (what the canonical playbook rules compute from them) and observed (bounded live probes: authoritative SOA/NS/SRV on each provider, unbound forward/stub zones and internal/external resolution through each tier host, the optional client_host's resolver). Every declared/live difference carries evidence references; unknown and absent are separate states. External resolution through the tier is reported as such, never as proof that a particular forwarder answered. FreeIPA's DNS configuration is read only with the read-only principal the operator configured at server start (--diagnose-freeipa-principal/--diagnose-freeipa-keytab), in a private ccache; without one the call returns status auth_required with every other fact still filled in. Never accepts a password, never uses an admin ticket, refuses FreeIPA's own service principals at startup, and refuses a principal whose rights on the global DNS configuration (cn=dns) include write. Every failed or unknown fact is named in findings; complete means every fact was seen, not that DNS works.",
	}, diagnoseDNSArchitectureHandler(opts))
}

func diagnoseDNSArchitectureHandler(opts diagnoseMCPToolsOptions) mcp.ToolHandlerFor[diagnoseDNSArchitectureInput, diagnoseDNSArchitectureOutput] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in diagnoseDNSArchitectureInput) (*mcp.CallToolResult, diagnoseDNSArchitectureOutput, error) {
		fail := func(code, msg string) (*mcp.CallToolResult, diagnoseDNSArchitectureOutput, error) {
			return toolErrorResult(mcpToolError{Code: code, Message: msg}), diagnoseDNSArchitectureOutput{}, nil
		}
		in.InternalName = normalizeDNSArchName(in.InternalName)
		in.ExternalName = normalizeDNSArchName(in.ExternalName)
		if in.InternalName != "" && !validDNSArchName(in.InternalName) {
			return fail(mcpErrInvalidParam, fmt.Sprintf("internal_name %q is not a valid DNS name", in.InternalName))
		}
		if in.ExternalName != "" && !validDNSArchName(in.ExternalName) {
			return fail(mcpErrInvalidParam, fmt.Sprintf("external_name %q is not a valid DNS name", in.ExternalName))
		}
		if err := validateFreeIPAReader(opts.FreeIPAReader); err != nil {
			return fail(mcpErrInvalidParam, err.Error())
		}

		ctx = withDeployAnsibleRuntime(ctx, scopedDiagnoseAnsibleRuntime(opts.AnsibleRuntime))
		resolved, err := resolveDiagnoseInventoryReadOnly(ctx, opts)
		if err != nil {
			return fail(mcpErrInvalidParam, fmt.Sprintf("resolve inventory: %v", err))
		}
		if in.ClientHost != "" {
			if err := diagnose.ValidateHost(resolved, in.ClientHost); err != nil {
				return fail(mcpErrHostNotFound, err.Error())
			}
		}

		sessionID, err := newID()
		if err != nil {
			return fail(mcpErrRecordingFailed, err.Error())
		}
		start := time.Now()
		auditDir, err := prepareDiagnoseAuditDir(opts, "dns_architecture", sessionID, start)
		if err != nil {
			return fail(mcpErrRecordingFailed, err.Error())
		}
		runner := opts.AdHocRunner
		if runner == nil {
			runner = realDiagnoseAdHocRunner()
		}

		model := diagnose.BuildDNSArchitectureModel(resolved, in.ClientHost)
		var observed diagnose.DNSArchObserved
		// The internal name every provider and tier host resolves: the
		// operator's, or the primary's FQDN as a DNS name (lower case, no
		// trailing dot, AGENTS.md §5.13). Without one the core comparison
		// cannot be made, and the report says so.
		internalName := in.InternalName
		internalSkip := ""
		if internalName == "" && model.FreeIPAPresent && len(model.Providers) > 0 {
			if n := normalizeDNSArchName(model.Providers[0].FQDN); validDNSArchName(n) {
				internalName = n
			} else {
				internalSkip = fmt.Sprintf("the FreeIPA primary's FQDN %q is not a DNS name, so no internal name was resolved on the providers or through the tier; pass internal_name", model.Providers[0].FQDN)
				observed.Skipped = append(observed.Skipped, internalSkip)
			}
		}
		externalName := in.ExternalName
		if externalName == "" {
			externalName = "."
		}

		// Plan every independent probe first, run them concurrently, then
		// read them back in plan order so steps and evidence stay stable.
		domainOK := validDNSArchName(model.FreeIPADomain)
		var providerProbes, tierProbes []*dnsArchProbe
		var clientProbe *dnsArchProbe
		var overflow []string
		for _, p := range model.Providers {
			if !p.DNSProvider {
				continue
			}
			if len(providerProbes) >= maxDNSArchProbeHosts {
				overflow = append(overflow, p.InventoryHost)
				continue
			}
			probe := &dnsArchProbe{host: p.InventoryHost, provider: p, name: internalName}
			switch {
			case !domainOK:
				observed.Skipped = append(observed.Skipped, fmt.Sprintf("FreeIPA DNS provider %s: the FreeIPA domain %q is not a DNS name, so it was not probed", p.InventoryHost, model.FreeIPADomain))
			case !dnsArchProbeAddr(p.IP):
				observed.Skipped = append(observed.Skipped, fmt.Sprintf("FreeIPA DNS provider %s: its ansible_host %q is not an IP address or DNS name, so it was not probed", p.InventoryHost, p.IP))
			default:
				probeName := internalName
				if probeName == "" {
					probeName = "-"
				}
				probe.step = diagnose.DNSArchProviderStep(p.InventoryHost, model.FreeIPADomain, p.IP, probeName)
			}
			providerProbes = append(providerProbes, probe)
		}
		if len(overflow) > 0 {
			observed.Skipped = append(observed.Skipped, fmt.Sprintf("FreeIPA DNS providers beyond the first %d were not probed: %s", maxDNSArchProbeHosts, strings.Join(overflow, ", ")))
		}
		var validProviderIPs []string
		for _, ip := range model.DNSProviderIPs() {
			if dnsArchProbeAddr(ip) {
				validProviderIPs = append(validProviderIPs, ip)
			}
		}
		tierDomain := ""
		if domainOK && len(validProviderIPs) > 0 {
			tierDomain = model.FreeIPADomain
		}
		for i, t := range model.Tier {
			if i >= maxDNSArchProbeHosts {
				var rest []string
				for _, r := range model.Tier[i:] {
					rest = append(rest, r.Host)
				}
				observed.Skipped = append(observed.Skipped, fmt.Sprintf("dns tier hosts beyond the first %d were not probed: %s", maxDNSArchProbeHosts, strings.Join(rest, ", ")))
				break
			}
			tierProbes = append(tierProbes, &dnsArchProbe{host: t.Host, tier: t, step: diagnose.DNSArchTierStep(t.Host, internalName, externalName, tierDomain, validProviderIPs)})
		}
		if in.ClientHost != "" {
			probeName := internalName
			if probeName == "" {
				probeName = "localhost"
			}
			clientProbe = &dnsArchProbe{host: in.ClientHost, step: diagnose.DNSArchClientStep(in.ClientHost, probeName)}
		}
		all := append(append([]*dnsArchProbe(nil), providerProbes...), tierProbes...)
		if clientProbe != nil {
			all = append(all, clientProbe)
		}
		runDNSArchProbes(ctx, runner, opts, all)

		var allResults []diagnose.StepResult
		remoteUsers := map[string]string{}
		authHost := ""
		for _, probe := range providerProbes {
			if probe.step.ID == "" {
				observed.Providers = append(observed.Providers, unprobedProvider(probe.provider, "not probed: see skipped"))
				continue
			}
			allResults = append(allResults, probe.result)
			op := diagnose.BuildDNSArchObservedProvider(probe.provider, model.FreeIPADomain, probe.name, probe.result)
			if op.RemoteUser != "" {
				remoteUsers[probe.host] = op.RemoteUser
			}
			if authHost == "" && op.Reachable.State == diagnose.FactObserved {
				authHost = probe.host
			}
			observed.Providers = append(observed.Providers, op)
		}

		// A replica FreeIPA does not list as a DNS server is left out by
		// dns-apply.yml and the resolver task
		// (tasks/freeipa-dns-providers-live.yml); the model follows, from
		// the same live NS records.
		leftOut, registered := diagnose.DNSArchUnregisteredReplicas(model, observed.Providers)
		var leftOutIPs []string
		if len(leftOut) > 0 {
			model = diagnose.BuildDNSArchitectureModelLeavingOut(resolved, leftOut, in.ClientHost)
			for i, op := range observed.Providers {
				p, _ := model.Provider(op.Host)
				if p.LeftOut {
					observed.Providers[i].LeftOut = fmt.Sprintf("%s (%s) leaves freeipa_setup_dns unset, but it did not answer %s authoritatively and FreeIPA's NS records list only %s, so dns-apply.yml and the resolver task leave it out; promote it with freeipa-server-replica-apply.yml, set freeipa_replica_fqdn to the name FreeIPA knows it by, or start named on it (then re-run them), or set freeipa_setup_dns: false", op.Host, p.FQDN, model.FreeIPADomain, strings.Join(registered, ", "))
					leftOutIPs = append(leftOutIPs, p.IP)
				}
			}
		}

		// FreeIPA's own DNS configuration, only through the approved reader,
		// on the first provider that answered.
		observed.FreeIPA, observed.Kerberos = freeIPAConfigObservation(ctx, opts, runner, model, authHost, &allResults)
		if observed.Kerberos.State == "available" && observed.Kerberos.Host != "" {
			if u := lastRemoteUser(allResults); u != "" {
				remoteUsers[observed.Kerberos.Host] = u
			}
		}

		for _, probe := range tierProbes {
			allResults = append(allResults, probe.result)
			ot := diagnose.BuildDNSArchObservedTier(probe.tier, internalName, externalName, validProviderIPs, tierDomain, probe.result)
			// The tier's G5-style authority probe of a left-out replica is
			// expected to fail; dns-apply.yml no longer sends it queries.
			var kept []diagnose.DNSArchFact
			for i, a := range ot.ProviderAuthority {
				if i < len(validProviderIPs) && stringInList(leftOutIPs, validProviderIPs[i]) {
					continue
				}
				kept = append(kept, a)
			}
			ot.ProviderAuthority = kept
			if internalSkip != "" {
				ot.InternalResolution.Detail = internalSkip
			}
			if ot.RemoteUser != "" {
				remoteUsers[probe.host] = ot.RemoteUser
			}
			observed.Tier = append(observed.Tier, ot)
		}
		if clientProbe != nil {
			allResults = append(allResults, clientProbe.result)
			oc := diagnose.BuildDNSArchObservedClient(in.ClientHost, clientProbe.result, model.TierAddrs(in.ClientHost))
			if oc.RemoteUser != "" {
				remoteUsers[in.ClientHost] = oc.RemoteUser
			}
			observed.Client = &oc
		}

		diffs := diagnose.BuildDNSArchDifferences(model, observed)
		status, findings := diagnose.BuildDNSArchStatus(model, observed, diffs)
		out := diagnoseDNSArchitectureOutput{
			Status:   status,
			Findings: findings,
			Paths:    diagnose.BuildDNSArchPaths(model, observed),
			Execution: dnsArchExecution{
				ControllerUser: controllerUser(),
				RemoteUsers:    remoteUsers,
				Kerberos:       observed.Kerberos,
			},
			Supported:      dnsArchSupportedLayer(opts, resolved.OrderedGroupHosts),
			Declared:       model.Declared,
			Effective:      model,
			Observed:       observed,
			Differences:    diffs,
			Steps:          stepEvidenceList(allResults),
			AuditDirectory: auditDir,
		}
		if out.Declared == nil {
			out.Declared = []diagnose.DNSArchVar{}
		}

		params := map[string]string{"internal_name": internalName, "external_name": externalName}
		if in.ClientHost != "" {
			params["client_host"] = in.ClientHost
		}
		if opts.FreeIPAReader.Principal != "" {
			params["freeipa_reader_principal"] = opts.FreeIPAReader.Principal
		}
		rec := diagnoseAuditRecord{
			SessionID: sessionID, Check: "dns_architecture", PilotVersion: rootCmd.Version,
			GitRevision: gitRevision(filepath.Dir(opts.Inventory)), MCPClient: mcpClientString(req),
			Inventory: opts.Inventory, Host: in.ClientHost, Params: params,
			Start: start, Finish: time.Now(), Steps: stepAuditList(allResults),
		}
		out.diagnoseAuditStatus = auditStatusFor(writeDiagnoseAudit(auditDir, rec))
		return nil, out, nil
	}
}

// dnsArchProbe is one planned probe step and, after runDNSArchProbes, its
// result.
type dnsArchProbe struct {
	host     string
	step     diagnose.Step
	provider diagnose.DNSArchProvider
	tier     diagnose.DNSArchTierHost
	name     string
	result   diagnose.StepResult
}

// maxDNSArchConcurrentProbes bounds how many ansible processes one call runs
// at once. Probes target different hosts, and the call's ControlPath is
// already scoped per host (%C), so they do not share an SSH socket.
const maxDNSArchConcurrentProbes = 4

func runDNSArchProbes(ctx context.Context, runner diagnose.AdHocRunner, opts diagnoseMCPToolsOptions, probes []*dnsArchProbe) {
	var wg sync.WaitGroup
	slots := make(chan struct{}, maxDNSArchConcurrentProbes)
	for _, probe := range probes {
		if probe.step.ID == "" {
			continue
		}
		wg.Add(1)
		go func(p *dnsArchProbe) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			p.result = diagnose.RunSteps(ctx, runner, opts.Inventory, p.host, []diagnose.Step{p.step}, opts.StepTimeout)[0]
		}(probe)
	}
	wg.Wait()
}

// dnsArchProbeAddr accepts an inventory address for a probe argument: an
// IP address or a plain DNS name (ansible_host may be either).
func dnsArchProbeAddr(addr string) bool {
	return net.ParseIP(addr) != nil || validDNSArchName(normalizeDNSArchName(addr))
}

func stringInList(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// normalizeDNSArchName is a DNS name as the probes use it: lower case,
// without the trailing dot.
func normalizeDNSArchName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// validDNSArchName accepts a normalized host or domain name for a probe.
// ValidDNSRecordName also accepts "@", the zone apex in a manifest, which
// is not a name dig can resolve.
func validDNSArchName(s string) bool {
	return s != "@" && inventory.ValidDNSRecordName(s)
}

// unprobedProvider is a provider pilot planned but did not probe; the
// reason is in observed.skipped, which makes the report partial.
func unprobedProvider(p diagnose.DNSArchProvider, detail string) diagnose.DNSArchObservedProvider {
	f := diagnose.DNSArchFact{State: diagnose.FactNotApplicable, Detail: detail}
	return diagnose.DNSArchObservedProvider{Host: p.InventoryHost, IP: p.IP, Reachable: f, NamedActive: f, SOA: f, NS: f, LDAPSRV: f, KerberosSRV: f, Internal: f}
}

// freeIPAConfigObservation reads FreeIPA's DNS configuration on authHost
// with the approved reader, or says why it did not.
func freeIPAConfigObservation(ctx context.Context, opts diagnoseMCPToolsOptions, runner diagnose.AdHocRunner, model diagnose.DNSArchModel, authHost string, allResults *[]diagnose.StepResult) (diagnose.DNSArchObservedFreeIPA, diagnose.DNSArchKerberos) {
	gated := func(state, detail string) diagnose.DNSArchObservedFreeIPA {
		f := diagnose.DNSArchFact{State: state, Detail: detail}
		return diagnose.DNSArchObservedFreeIPA{GlobalForwarders: f, ForwardPolicy: f, ServerForwarders: f, ForwardZones: f, Zones: f}
	}
	reader := opts.FreeIPAReader
	switch {
	case !model.FreeIPAPresent || len(model.DNSProviderIPs()) == 0:
		detail := "the inventory has no FreeIPA DNS provider"
		return gated(diagnose.FactNotApplicable, detail), diagnose.DNSArchKerberos{State: diagnose.FactNotApplicable, Detail: detail}
	case reader.Principal == "":
		detail := "no approved read-only FreeIPA principal: start pilot mcp serve with --diagnose-freeipa-principal and --diagnose-freeipa-keytab (docs/runbooks/dns-architecture-diagnose.md)"
		return gated(diagnose.FactAuthRequired, detail), diagnose.DNSArchKerberos{State: "not_configured", Detail: detail}
	case authHost == "":
		detail := "no FreeIPA DNS provider was reachable to read the configuration from"
		return gated(diagnose.FactUnreachable, detail), diagnose.DNSArchKerberos{State: diagnose.FactUnreachable, Principal: reader.Principal, Keytab: reader.Keytab, Detail: detail}
	}
	results := diagnose.RunSteps(ctx, runner, opts.Inventory, authHost, []diagnose.Step{diagnose.DNSArchAuthStep(authHost, reader.Principal, reader.Keytab)}, opts.StepTimeout)
	*allResults = append(*allResults, results...)
	return diagnose.BuildDNSArchObservedFreeIPA(authHost, reader.Principal, reader.Keytab, results[0])
}

func lastRemoteUser(results []diagnose.StepResult) string {
	if len(results) == 0 {
		return ""
	}
	if s, ok := diagnose.ParseDNSArchSections(results[len(results)-1].Result.Stdout)["whoami"]; ok && s.Complete && s.RC == 0 {
		return strings.TrimSpace(s.Output)
	}
	return ""
}

func controllerUser() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

// dnsArchSupportedLayer reports what the product offers (contracts), what
// the inventory assigns, and the latest recorded delivery of each DNS
// component — so "the dns role exists but is not assigned / not deployed"
// is stated, not inferred.
func dnsArchSupportedLayer(opts diagnoseMCPToolsOptions, groupHosts func(string) []string) dnsArchSupported {
	s := dnsArchSupported{
		TierModes: []string{"freeipa-split (FreeIPA domain and dns_freeipa_zones stubbed to every FreeIPA DNS server, everything else forwarded to dns_upstream)", "forward-only (no FreeIPA DNS in the inventory)"},
		Capabilities: []string{
			"dns: unbound caching tier; split forwarding is derived from the inventory's FreeIPA DNS providers (playbooks/apply/dns-apply.yml)",
			"freeipa-server / freeipa-server-replica: native FreeIPA DNS (freeipa_setup_dns); global forwarders and each DNS server's own forwarders from freeipa_dns_forwarders via ipa dnsconfig-mod and ipa dnsserver-mod on every apply",
			"freeipa-dns-client and internal-endpoint's fleet-wide baseline: resolver list = explicit freeipa_dns_client_servers, else 127.0.0.1 plus the other providers on a provider, else up to 3 of (tier addresses, FreeIPA DNS providers), else the providers (playbooks/apply/tasks/freeipa-dns-client-resolver.yml)",
			"freeipa-dns: records in FreeIPA-managed zones from a manifest",
		},
		NotManaged: []string{
			"FreeIPA global forward policy (FreeIPA's default applies)",
			"FreeIPA forward zones (ipa dnsforwardzone-*)",
			"the resolver of a dns tier host itself (the dns role leaves it alone, docs/verification/dns.md B9)",
		},
	}
	root := diagnoseWorkspaceRoot(opts)
	var catalog contract.Catalog
	catalogLoaded := false
	if loader, err := contract.NewLoader(root); err == nil {
		if c, err := loader.LoadDefaultCatalog(); err == nil {
			catalog, catalogLoaded = c, true
		}
	}
	st, storeErr := openSpecStore()
	if storeErr == nil {
		defer st.Close()
	}
	for _, id := range dnsArchComponentIDs {
		comp := dnsArchComponent{ID: id, RunState: "unknown"}
		if catalogLoaded {
			if c, ok := catalog.Component(id); ok {
				comp.Product, comp.Role, comp.OptIn = true, c.Role, c.Site.OptIn
				comp.Contract = filepath.ToSlash(filepath.Join("contracts", id+".yaml"))
				comp.Hosts = groupHosts(c.Role)
				comp.Assigned = len(comp.Hosts) > 0
			}
		}
		if id == "internal-endpoint" || id == "freeipa-dns" {
			comp.Note = "day-2 opt-in component on the freeipa-server host; assignment follows freeipa-server, so only a recorded run shows it was applied"
		}
		switch {
		case storeErr != nil:
			comp.RunState = "unknown"
		default:
			runs, err := st.ListRuns(store.RunFilter{Component: id, Limit: 1})
			switch {
			case err != nil:
				comp.RunState = "unknown"
			case len(runs) == 0:
				comp.RunState = "no_recorded_run"
			default:
				r := runs[0]
				comp.LastRun = &dnsArchRun{RunID: r.RunID, Outcome: r.Outcome, FinishedAt: r.FinishedAt}
				comp.RunState = r.Outcome
			}
		}
		s.Components = append(s.Components, comp)
	}
	return s
}
