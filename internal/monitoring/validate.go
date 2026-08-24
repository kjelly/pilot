package monitoring

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"time"
)

// targetNamePattern is spec.md §8.1's suggested identifier grammar.
var targetNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

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

// Validate checks tf and pf against spec.md §7-18's schema rules. It is pure
// (no filesystem/network access) so it runs identically in `pilot monitoring
// validate`, the TUI's save path, and this package's own tests. Reserved
// jobName/duplicate jobName/unknown profile are exactly the class of error
// spec.md §22 says must be caught before any Ansible apply — this function
// is the sole place that logic lives, so `pilot monitoring validate`, the
// TUI, and any future MCP structured action all get it for free.
func Validate(tf TargetFile, pf ProfileFile) Result {
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

		if err := validateAddress(t.Address); err != nil {
			r.addf("target %q: %s", t.Name, err)
		}

		if t.Profile == "" {
			r.addf("target %q: profile is required", t.Name)
		} else if _, ok := pf.Profiles[t.Profile]; !ok {
			r.addf("monitoring target %q references unknown scrape profile %q", t.Name, t.Profile)
		}

		for _, reserved := range ReservedLabels {
			if _, ok := t.Labels[reserved]; ok {
				r.addf("target %q: label %q is reserved (set automatically by the target compiler)", t.Name, reserved)
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

	warnDuplicateEndpoints(&r, tf)

	sort.Strings(r.Errors)
	sort.Strings(r.Warnings)
	return r
}

// validateAddress enforces spec.md §8.2/§43: host:port only (no scheme, no
// bare host), using net.SplitHostPort so IPv6 literals ("[::1]:9100") are
// handled correctly instead of a hand-rolled strings.Split(addr, ":") that
// would misparse on the extra colons.
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
