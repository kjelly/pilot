package identityreconcile

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/freeiparpc"
)

// LiveHBACRule is one FreeIPA HBAC rule as hbacrule_find --all reports it (captured:
// internal/freeiparpc/testdata/hbacrule-find-builtin.json, hbacrule-show-all-members.json;
// spec 2026-11-19 §1.3 K1).
type LiveHBACRule struct {
	Name     string // cn, as stored: FreeIPA keeps the spelling the rule was created with
	UniqueID string
	// Enabled is ipaenabledflag, a one-element list of a JSON boolean.
	Enabled bool
	// The categories are "" when the key is absent (K1: a rule without a category has
	// no key) and "all" otherwise.
	HostCategory, ServiceCategory, UserCategory string
	// The members, lower case and sorted; the hosts are the lower-case FQDNs FreeIPA
	// stores.
	Users, Groups, Hosts, Hostgroups, Services []string
}

// LiveHBACService is one HBAC service (hbacsvc_find).
type LiveHBACService struct{ Name string }

// HBACObservation is what the HBAC plan is built from.
type HBACObservation struct {
	Rules    []LiveHBACRule
	Services []LiveHBACService
	// Hosts and Hostgroups are the names FreeIPA has (host_find and hostgroup_find
	// with pkey_only): lower-case FQDNs and lower-case names.
	Hosts, Hostgroups []string
	// Domain is the domain FreeIPA completes a short host name with (env, K4), lower
	// case.
	Domain string
}

// ParseHBACRules decodes hbacrule_find --all entries. A value of an unexpected shape is
// an error: an unknown field is not an empty one.
func ParseHBACRules(entries []map[string]any) ([]LiveHBACRule, error) {
	out := make([]LiveHBACRule, 0, len(entries))
	for i, e := range entries {
		r, err := parseHBACRule(e)
		if err != nil {
			return nil, fmt.Errorf("hbacrule_find entry %d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func parseHBACRule(e map[string]any) (LiveHBACRule, error) {
	var r LiveHBACRule
	var err error
	if r.Name, err = single(e, "cn", true); err != nil {
		return r, err
	}
	if r.UniqueID, err = single(e, "ipauniqueid", false); err != nil {
		return r, fmt.Errorf("rule %s: %w", r.Name, err)
	}
	flag, ok := e["ipaenabledflag"].([]any)
	if !ok || len(flag) != 1 {
		return r, fmt.Errorf("rule %s: ipaenabledflag is missing or not a one-value list (find without all: true?)", r.Name)
	}
	if r.Enabled, ok = flag[0].(bool); !ok {
		return r, fmt.Errorf("rule %s: ipaenabledflag is not a boolean", r.Name)
	}
	for _, c := range []struct {
		key string
		dst *string
	}{
		{"hostcategory", &r.HostCategory}, {"servicecategory", &r.ServiceCategory}, {"usercategory", &r.UserCategory},
	} {
		if *c.dst, err = single(e, c.key, false); err != nil {
			return r, fmt.Errorf("rule %s: %w", r.Name, err)
		}
		if *c.dst != "" && !strings.EqualFold(*c.dst, "all") {
			return r, fmt.Errorf("rule %s: %s is %q, which this engine does not know (only all)", r.Name, c.key, *c.dst)
		}
		*c.dst = strings.ToLower(*c.dst)
	}
	for _, m := range []struct {
		key string
		dst *[]string
	}{
		{"memberuser_user", &r.Users}, {"memberuser_group", &r.Groups},
		{"memberhost_host", &r.Hosts}, {"memberhost_hostgroup", &r.Hostgroups},
		{"memberservice_hbacsvc", &r.Services},
	} {
		if *m.dst, err = lowerList(e, m.key); err != nil {
			return r, fmt.Errorf("rule %s: %w", r.Name, err)
		}
	}
	return r, nil
}

// ParseHBACServices decodes hbacsvc_find entries.
func ParseHBACServices(entries []map[string]any) ([]LiveHBACService, error) {
	out := make([]LiveHBACService, 0, len(entries))
	for i, e := range entries {
		name, err := single(e, "cn", true)
		if err != nil {
			return nil, fmt.Errorf("hbacsvc_find entry %d: %w", i, err)
		}
		out = append(out, LiveHBACService{Name: name})
	}
	return out, nil
}

// HBACReader is what ObserveHBAC reads with: the finds, and env.
type HBACReader interface {
	Finder
	Call(ctx context.Context, cmd freeiparpc.Command) (json.RawMessage, error)
}

// ParseEnvDomain reads the domain out of an env answer (captured: env-domain.json).
func ParseEnvDomain(raw json.RawMessage) (string, error) {
	var r struct {
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("decode env: %w", err)
	}
	d, ok := r.Result["domain"].(string)
	if !ok || strings.TrimSpace(d) == "" {
		return "", fmt.Errorf("env answered no domain")
	}
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), ".")), nil
}

// ObserveHBAC reads the HBAC rules and services, the host and hostgroup names the rules
// refer to, and the domain a short host name is completed with. Every read but the last is a find
// with no limit that fails on a truncated or incomplete answer (Finder), so the read
// count does not depend on the number of rules.
func ObserveHBAC(ctx context.Context, f HBACReader) (HBACObservation, error) {
	var obs HBACObservation
	raw, err := f.Find(ctx, "hbacrule_find", nil, map[string]any{"all": true})
	if err != nil {
		return obs, fmt.Errorf("read HBAC rules: %w", err)
	}
	if obs.Rules, err = ParseHBACRules(raw); err != nil {
		return obs, err
	}
	if raw, err = f.Find(ctx, "hbacsvc_find", nil, map[string]any{"all": true}); err != nil {
		return obs, fmt.Errorf("read HBAC services: %w", err)
	}
	if obs.Services, err = ParseHBACServices(raw); err != nil {
		return obs, err
	}
	if raw, err = f.Find(ctx, "host_find", nil, map[string]any{"pkey_only": true}); err != nil {
		return obs, fmt.Errorf("read hosts: %w", err)
	}
	if obs.Hosts, err = pkeyNames(raw, "fqdn"); err != nil {
		return obs, fmt.Errorf("host_find: %w", err)
	}
	if raw, err = f.Find(ctx, "hostgroup_find", nil, map[string]any{"pkey_only": true}); err != nil {
		return obs, fmt.Errorf("read hostgroups: %w", err)
	}
	if obs.Hostgroups, err = pkeyNames(raw, "cn"); err != nil {
		return obs, fmt.Errorf("hostgroup_find: %w", err)
	}
	env, err := f.Call(ctx, freeiparpc.Command{Method: "env", Args: []any{"domain"}})
	if err != nil {
		return obs, fmt.Errorf("read the server's domain: %w", err)
	}
	if obs.Domain, err = ParseEnvDomain(env); err != nil {
		return obs, err
	}
	return obs, nil
}

// pkeyNames is the lower-case, sorted primary keys a pkey_only find answers with.
func pkeyNames(entries []map[string]any, key string) ([]string, error) {
	var out []string
	for i, e := range entries {
		name, err := single(e, key, true)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		out = appendUnique(out, strings.ToLower(name))
	}
	sort.Strings(out)
	return out, nil
}
