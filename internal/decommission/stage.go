// stage.go supplies the stage that each ansible-playbook run of a host
// decommission must carry.
//
// Every apply and decommission playbook gates on `stage` (AGENTS.md §4.3):
// staging needs confirm_staging, prod needs confirm_prod and
// staging_attested_within_hours <= 168, and an `always` cross-check refuses
// a stage that differs from the host's staging/prod inventory group. Host
// decommission used to pass no stage at all, so every run against a host in
// a staging or prod group failed that cross-check, already at the read-only
// inspect step (reproduced 2026-09-25 on a prod-grouped vm-target). A
// decommission also runs playbooks on other hosts: the FreeIPA identity
// reconcile on the freeipa-server hosts, the Wazuh deregistration on the
// wazuh-manager hosts. Each run therefore carries the stage of the hosts it
// targets, together with the operator's confirmation for that stage.
package decommission

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// StageAuthorization is the stage confirmation the operator gave for one
// apply or resume.
type StageAuthorization struct {
	ConfirmStaging bool
	ConfirmProd    bool
	// StagingAttestedWithinHours is how many hours ago staging was last
	// verified; prod accepts 0 through 168. A negative value means the
	// operator gave none.
	StagingAttestedWithinHours int
}

// StageScope maps the workspace's hosts to their environment and builds the
// stage arguments for the hosts one playbook run targets.
type StageScope struct {
	env   map[string]string
	roles map[string][]string
	all   []string
	auth  StageAuthorization
}

// NewStageScope builds a StageScope from the parsed hosts.yml. The generated
// inventory puts each host in its role groups and in the group named by its
// env, so these are the memberships the playbooks' cross-check sees.
func NewStageScope(hosts []inventory.Host, auth StageAuthorization) *StageScope {
	s := &StageScope{env: map[string]string{}, roles: map[string][]string{}, auth: auth}
	for _, h := range hosts {
		s.env[h.Name] = normalizeStage(h.Env)
		s.all = append(s.all, h.Name)
		for _, role := range h.Roles {
			s.roles[role] = append(s.roles[role], h.Name)
		}
	}
	sort.Strings(s.all)
	return s
}

// RoleHosts returns the hosts with role, which is the inventory group a
// playbook such as freeipa-identity-apply.yml targets by default.
func (s *StageScope) RoleHosts(role string) []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.roles[role]...)
}

// AllHosts returns every host in the workspace (the `all` group).
func (s *StageScope) AllHosts() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.all...)
}

// Stage returns the one stage shared by hosts: "sandbox", "staging" or
// "prod". It fails when hosts span more than one, because a playbook run
// takes a single stage and the cross-check would refuse every host outside
// it.
func (s *StageScope) Stage(hosts []string) (string, error) {
	if s == nil || len(hosts) == 0 {
		return "sandbox", nil
	}
	byStage := map[string][]string{}
	for _, h := range hosts {
		stage := s.env[h]
		if stage == "" {
			stage = "sandbox"
		}
		byStage[stage] = append(byStage[stage], h)
	}
	if len(byStage) == 1 {
		for stage := range byStage {
			return stage, nil
		}
	}
	var parts []string
	for stage, hs := range byStage {
		sort.Strings(hs)
		parts = append(parts, fmt.Sprintf("%s: %s", stage, strings.Join(hs, ", ")))
	}
	sort.Strings(parts)
	return "", newError(ErrStageMixed,
		"one playbook run would target hosts in different stages (%s); it can carry only one stage, and the cross-check refuses every host outside it",
		strings.Join(parts, "; "))
}

// Args returns the -e arguments for a playbook run that targets hosts:
// stage=<their stage>, plus confirm_staging, or confirm_prod and
// staging_attested_within_hours, from the operator's confirmation. It fails
// when hosts span stages or the confirmation for their stage is missing.
// A nil scope returns no arguments.
func (s *StageScope) Args(hosts []string) ([]string, error) {
	if s == nil {
		return nil, nil
	}
	stage, err := s.Stage(hosts)
	if err != nil {
		return nil, err
	}
	switch stage {
	case "staging":
		if !s.auth.ConfirmStaging {
			return nil, newError(ErrStageConfirmationRequired,
				"%s in staging: pass --confirm-staging (or confirm staging in the TUI)", hostList(hosts))
		}
		return []string{"-e", "stage=staging", "-e", "confirm_staging=true"}, nil
	case "prod":
		if !s.auth.ConfirmProd {
			return nil, newError(ErrStageConfirmationRequired,
				"%s in prod: pass --confirm-prod and --staging-attested-within-hours <0-168> (or confirm prod in the TUI)", hostList(hosts))
		}
		h := s.auth.StagingAttestedWithinHours
		if h < 0 || h > 168 {
			return nil, newError(ErrStageConfirmationRequired,
				"%s in prod: --staging-attested-within-hours must be 0 to 168 (hours since staging was last verified), got %s", hostList(hosts), attestedText(h))
		}
		return []string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=" + strconv.Itoa(h)}, nil
	default:
		return []string{"-e", "stage=sandbox"}, nil
	}
}

// ArgsFunc returns a closure for a provider config that computes Args for
// hosts when the provider runs its playbook.
func (s *StageScope) ArgsFunc(hosts []string) func() ([]string, error) {
	return func() ([]string, error) { return s.Args(hosts) }
}

func normalizeStage(env string) string {
	switch strings.TrimSpace(env) {
	case "staging":
		return "staging"
	case "prod":
		return "prod"
	default:
		return ""
	}
}

func hostList(hosts []string) string {
	sorted := append([]string(nil), hosts...)
	sort.Strings(sorted)
	if len(sorted) == 1 {
		return "host " + sorted[0] + " is"
	}
	return "hosts " + strings.Join(sorted, ", ") + " are"
}

func attestedText(h int) string {
	if h < 0 {
		return "none"
	}
	return strconv.Itoa(h)
}
