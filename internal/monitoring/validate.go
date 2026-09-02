package monitoring

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"time"
)

// targetNamePattern is spec.md §8.1's suggested identifier grammar.
var targetNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// subjectKindPattern is the required shape for a snmp profile's
// subjectKind (SNMP monitoring integration spec §7.4 rule 5) — the same
// grammar as a catalog module/auth ID (spec §6.4 rule 1).
var subjectKindPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// snmpAddressPattern allows an optional `transport://` prefix plus a bare
// host/IP or host:port, but rejects anything containing a path, query, or
// fragment (SNMP monitoring integration spec §7.4 rule 8) — deliberately
// more permissive than validateAddress (no port required, since upstream
// snmp_exporter's own target param accepts a bare host).
var snmpAddressPattern = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://)?[^/?#]+$`)

// Result is the outcome of Validate: Errors block a save/apply (spec.md §22,
// §32); Warnings are informational and never block anything (spec.md §40,
// §44).
type Result struct {
	Errors   []string
	Warnings []string
}

// OK reports whether r has no errors. A Result with only warnings is OK.
func (r Result) OK() bool {
	return len(r.Errors) == 0
}

func (r *Result) addf(format string, args ...any) {
	r.Errors = append(r.Errors, fmt.Sprintf(format, args...))
}

func (r *Result) warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Validate checks tf and pf against spec.md §7-18's schema rules, plus the
// SNMP monitoring integration spec §7.4's `kind: snmp` profile rules
// (cross-referenced against catalog, the already-loaded, already-parsed
// monitoring/snmp/catalog.yml — passing it in keeps this function pure:
// no filesystem/network access, so it runs identically in `pilot
// monitoring validate`, the TUI's save path, and this package's own
// tests). Reserved jobName/duplicate jobName/unknown profile are exactly
// the class of error spec.md §22 says must be caught before any Ansible
// apply — this function is the sole place that logic lives, so `pilot
// monitoring validate`, the TUI, and any future MCP structured action all
// get it for free.
func Validate(tf TargetFile, pf ProfileFile, catalog SNMPCatalog) Result {
	var r Result

	seenTargetNames := map[string]bool{}
	for _, t := range tf.Targets {
		switch {
		case t.Name == "":
			r.addf("target has an empty name")
			continue
		case !targetNamePattern.MatchString(t.Name):
			r.addf("target %q: name must match %s", t.Name, targetNamePattern.String())
		case seenTargetNames[t.Name]:
			r.addf("target %q: name is not unique", t.Name)
		}
		seenTargetNames[t.Name] = true

		profile, hasProfile := pf.Profiles[t.Profile]
		if t.Profile == "" {
			r.addf("target %q: profile is required", t.Name)
		} else if !hasProfile {
			r.addf("monitoring target %q references unknown scrape profile %q", t.Name, t.Profile)
		}

		if hasProfile && profile.IsSNMP() {
			switch {
			case t.Address == "":
				r.addf("target %q: address is required", t.Name)
			case !snmpAddressPattern.MatchString(t.Address):
				r.addf("target %q: address %q must not contain a path, query, or fragment (spec §7.4 rule 8)", t.Name, t.Address)
			}
			if t.IsEnabled() && t.Site == "" {
				r.addf("target %q: site is required for an enabled kind:snmp target (spec §7.4 rule 7)", t.Name)
			}
		} else if err := validateAddress(t.Address); err != nil {
			r.addf("target %q: %s", t.Name, err)
		}

		for _, reserved := range ReservedLabels {
			if _, ok := t.Labels[reserved]; ok {
				r.addf("target %q: label %q is reserved (set automatically by the target compiler)", t.Name, reserved)
			}
		}
		for label := range t.Labels {
			if strings.HasPrefix(label, "__") {
				r.addf("target %q: label %q uses the reserved __ prefix", t.Name, label)
			}
		}
	}

	seenJobNames := map[string]string{} // jobName -> first profile name that used it
	for name, p := range pf.Profiles {
		if p.JobName == "" {
			r.addf("profile %q: jobName is required", name)
			continue
		}
		if other, ok := seenJobNames[p.JobName]; ok {
			r.addf("profiles %q and %q: jobName %q must be unique (spec.md §18)", other, name, p.JobName)
		}
		seenJobNames[p.JobName] = name

		for _, reserved := range ReservedJobNames {
			if p.JobName == reserved {
				r.addf("profile %q: jobName %q is reserved (spec.md §63)", name, reserved)
			}
		}

		switch p.EffectiveKind() {
		case "prometheus":
			if p.SNMP != nil {
				r.addf("profile %q: kind prometheus must not set an snmp block (spec §7.4)", name)
			}
			validateHTTPProfile(&r, name, p)
		case "snmp":
			validateSNMPProfile(&r, name, p, catalog)
		default:
			r.addf("profile %q: kind must be prometheus or snmp, got %q", name, p.Kind)
		}
	}

	warnDuplicateEndpoints(&r, tf)

	sort.Strings(r.Errors)
	sort.Strings(r.Warnings)
	return r
}

// validateHTTPProfile checks the direct-Prometheus (kind:prometheus,
// including the empty-Kind default) subset of profile fields — unchanged
// from schema v1's rules.
func validateHTTPProfile(r *Result, name string, p Profile) {
	if p.Scheme != "" && p.Scheme != "http" && p.Scheme != "https" {
		r.addf("profile %q: scheme must be http or https, got %q", name, p.Scheme)
	}
	if p.ScrapeInterval != "" {
		if _, err := time.ParseDuration(p.ScrapeInterval); err != nil {
			r.addf("profile %q: invalid scrapeInterval %q", name, p.ScrapeInterval)
		}
	}
	if p.ScrapeTimeout != "" {
		if _, err := time.ParseDuration(p.ScrapeTimeout); err != nil {
			r.addf("profile %q: invalid scrapeTimeout %q", name, p.ScrapeTimeout)
		}
	}
	if p.TLS != nil && p.TLS.InsecureSkipVerify {
		r.warnf("profile %q disables TLS certificate verification (insecureSkipVerify: true)", name)
	}
}

// validateSNMPProfile checks a `kind: snmp` profile against SNMP
// monitoring integration spec §7.4's rules 1-9 (rule 10, strict secret-key
// rejection, is enforced earlier by LoadTargets/LoadProfiles' KnownFields
// decoding — an SNMPProfile struct has no field a secret could hide in).
func validateSNMPProfile(r *Result, name string, p Profile, catalog SNMPCatalog) {
	if p.Scheme != "" || p.MetricsPath != "" || p.AuthRef != "" || p.TLS != nil {
		r.addf("profile %q: kind snmp must not set scheme/metricsPath/authRef/tls (spec §7.4 rule 6)", name)
	}
	if !subjectKindPattern.MatchString(p.SubjectKind) {
		r.addf("profile %q: subjectKind is required and must match %s (spec §7.4 rule 5)", name, subjectKindPattern.String())
	}
	if p.ScrapeInterval != "" {
		if _, err := time.ParseDuration(p.ScrapeInterval); err != nil {
			r.addf("profile %q: invalid scrapeInterval %q", name, p.ScrapeInterval)
		}
	}
	if p.ScrapeTimeout != "" {
		if _, err := time.ParseDuration(p.ScrapeTimeout); err != nil {
			r.addf("profile %q: invalid scrapeTimeout %q", name, p.ScrapeTimeout)
		}
	}
	if p.ScrapeInterval != "" && p.ScrapeTimeout != "" {
		interval, ierr := time.ParseDuration(p.ScrapeInterval)
		timeout, terr := time.ParseDuration(p.ScrapeTimeout)
		if ierr == nil && terr == nil && timeout >= interval {
			r.addf("profile %q: scrapeTimeout (%s) must be less than scrapeInterval (%s) (spec §7.4 rule 9)", name, p.ScrapeTimeout, p.ScrapeInterval)
		}
	}

	if p.SNMP == nil {
		r.addf("profile %q: kind snmp requires an snmp block (spec §7.4 rule 1)", name)
		return
	}
	if len(p.SNMP.Modules) == 0 {
		r.addf("profile %q: snmp.modules must have at least one entry (spec §7.4 rule 2)", name)
	}
	seenModules := map[string]bool{}
	for _, m := range p.SNMP.Modules {
		if seenModules[m] {
			r.addf("profile %q: snmp.modules lists %q more than once (spec §7.4 rule 2)", name, m)
		}
		seenModules[m] = true
		if _, ok := catalog.Modules[m]; !ok {
			r.addf("profile %q: snmp.modules references unknown module %q (not in monitoring/snmp/catalog.yml)", name, m)
		}
	}
	if p.SNMP.AuthProfile == "" {
		r.addf("profile %q: snmp.authProfile is required (spec §7.4 rule 3)", name)
	} else if _, ok := catalog.AuthProfiles[p.SNMP.AuthProfile]; !ok {
		r.addf("profile %q: snmp.authProfile references unknown auth profile %q (not in monitoring/snmp/catalog.yml)", name, p.SNMP.AuthProfile)
	}
}

// validateAddress enforces spec.md §8.2/§43: host:port only (no scheme, no
// bare host), using net.SplitHostPort so IPv6 literals ("[::1]:9100") are
// handled correctly instead of a hand-rolled strings.Split(addr, ":") that
// would misparse on the extra colons. Direct-Prometheus (kind:prometheus)
// targets only — a kind:snmp target uses snmpAddressPattern instead (spec
// §7.4 rule 8 explicitly allows a bare host with no port).
func validateAddress(addr string) error {
	if addr == "" {
		return fmt.Errorf("address is required")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q must be host:port (%w)", addr, err)
	}
	if host == "" {
		return fmt.Errorf("address %q must include an explicit host", addr)
	}
	if port == "" {
		return fmt.Errorf("address %q must include an explicit port", addr)
	}
	return nil
}

// warnDuplicateEndpoints implements spec.md §40: an external target whose
// address coincides with one Pilot already manages via host-monitoring is
// allowed (different job/profile/auth is a legitimate reason) but worth a
// warning. This package has no inventory access, so it only flags
// duplicates WITHIN the target registry itself; the host-monitoring overlap
// warning lives in playbooks/apply/prometheus-apply.yml, which does have
// inventory access.
func warnDuplicateEndpoints(r *Result, tf TargetFile) {
	seen := map[string][]string{}
	for _, t := range tf.Targets {
		if !t.IsEnabled() || t.Address == "" {
			continue
		}
		seen[t.Address] = append(seen[t.Address], t.Name)
	}
	for addr, names := range seen {
		if len(names) > 1 {
			sort.Strings(names)
			r.warnf("address %q is used by more than one enabled target: %v", addr, names)
		}
	}
}

// ProfileInUse returns the names of targets that reference profileName —
// used to enforce spec.md §50 (a profile in use cannot be removed).
func ProfileInUse(tf TargetFile, profileName string) []string {
	var names []string
	for _, t := range tf.Targets {
		if t.Profile == profileName {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	return names
}
