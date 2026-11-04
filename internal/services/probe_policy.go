package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
)

// ProbePolicy is readonly data verification configuration, never stack identity.
type ProbePolicy map[Capability]DataProbe

func (p ProbePolicy) validate(required Requirements) error {
	normalized, e := NormalizeRequirements(required)
	if e != nil {
		return e
	}
	for _, c := range normalized {
		if descriptor, ok := p[c]; ok {
			if e := descriptor.Validate(c); e != nil {
				return fmt.Errorf("services: required %s probe policy: %w", c, e)
			}
		}
	}
	return nil
}

// ClientContract derives the canonical public endpoints without any filesystem,
// network, credential publication or service lifecycle effects.
func (p Profile) ClientContract(bindIP net.IP, caPEM string) (ClientConfig, error) {
	if bindIP == nil || bindIP.IsUnspecified() {
		return ClientConfig{}, errors.New("services: service bind IP is invalid")
	}
	fingerprint, e := p.Fingerprint()
	if e != nil {
		return ClientConfig{}, e
	}
	projects := make(map[string]string, len(p.OCI.Registries))
	for _, registry := range p.OCI.Registries {
		projects[registry.Name] = fmt.Sprintf("http://%s:%d/%s", serviceHostname, p.Harbor.HTTPPort, registry.ProxyProject)
	}
	repositories := make(map[string]string, len(p.RPM.Repos))
	for _, repo := range p.RPM.Repos {
		repositories[repo.Name] = fmt.Sprintf("http://%s:8080/pulp/content/%s/%s", serviceHostname, p.Name, repo.Name)
	}
	return ClientConfig{Profile: p.Name, Fingerprint: fingerprint, HostIP: bindIP.String(), Hostname: serviceHostname, AptProxyURL: fmt.Sprintf("http://%s:%d", serviceHostname, p.Apt.Port), RPMBaseURL: repositories[p.RPM.Repos[0].Name], RPMRepositories: repositories, RegistryMirrorURL: fmt.Sprintf("http://%s:%d", serviceHostname, p.Harbor.HTTPPort), RegistryProjects: projects, CAPEM: caPEM, DataProbes: p.ClientDataProbes()}, nil
}

func canonicalClient(client ClientConfig) ClientConfig { client.DataProbes = nil; return client }
func registeredClient(state ServiceState) ClientConfig {
	client := state.Client
	if client.HostIP == "" {
		client.HostIP = state.BindIP
	}
	return client
}

func validatePhysicalProfile(state ServiceState, profile Profile, bindIP net.IP) error {
	if e := validateConsumptionData(state); e != nil {
		return e
	}
	if bindIP == nil || bindIP.IsUnspecified() || bindIP.String() != state.BindIP {
		return errors.New("services: requested bind address differs from registered stack")
	}
	expected, e := profile.ClientContract(bindIP, state.Client.CAPEM)
	if e != nil {
		return e
	}
	expected.InstanceID, expected.Generation = state.InstanceID, state.Generation
	if state.Profile != profile.Name || state.Fingerprint != expected.Fingerprint {
		return errors.New("services: requested physical profile name or fingerprint differs from registered stack")
	}
	if !reflect.DeepEqual(canonicalClient(expected), canonicalClient(registeredClient(state))) {
		return errors.New("services: registered client endpoint contract differs from physical profile")
	}
	return nil
}

// compatibilityPolicy never guesses an arbitrary legacy profile from its name.
// Established explicit policy remains readable; only an exact built-in identity
// can supply defaults to a pre-policy client.
func compatibilityPolicy(state ServiceState) ProbePolicy {
	if state.Client.DataProbes != nil {
		return state.Client.DataProbes
	}
	profile := BuiltInDevLite()
	fingerprint, e := profile.Fingerprint()
	if e == nil && state.Profile == profile.Name && state.Fingerprint == fingerprint && validatePhysicalProfile(state, profile, net.ParseIP(state.BindIP)) == nil {
		return profile.ClientDataProbes()
	}
	return nil
}
func stateWithPolicy(state ServiceState, policy ProbePolicy) ServiceState {
	state.Client.DataProbes = policy
	return state
}

// ClientConfigForProfile checks physical identity before applying an explicit,
// readonly profile policy. No persisted client or profile fields are backfilled.
func (m *Manager) ClientConfigForProfile(ctx context.Context, profile Profile, bindIP net.IP, required Requirements) (ClientConfig, error) {
	if _, e := NormalizeRequirements(required); e != nil {
		return ClientConfig{}, e
	}
	unlock, e := m.operationContext(ctx)
	if e != nil {
		return ClientConfig{}, e
	}
	defer unlock()
	state, e := m.current()
	if e != nil {
		return ClientConfig{}, e
	}
	if e = validatePhysicalProfile(state, profile, bindIP); e != nil {
		return ClientConfig{}, e
	}
	return m.clientConfigWithPolicy(ctx, state, profile.ClientDataProbes(), required)
}
func (m *Manager) clientConfigWithPolicy(ctx context.Context, state ServiceState, policy ProbePolicy, required Requirements) (ClientConfig, error) {
	if policy == nil {
		return ClientConfig{}, errors.New("services: missing-descriptor: explicit validated physical profile and probe policy are required")
	}
	if e := policy.validate(required); e != nil {
		return ClientConfig{}, e
	}
	observed := m.observeCapabilities(ctx, stateWithPolicy(state, policy))
	if ctx.Err() != nil {
		return ClientConfig{}, ctx.Err()
	}
	if e := requireCapabilities(observed, required); e != nil {
		return ClientConfig{}, e
	}
	if e := ctx.Err(); e != nil {
		return ClientConfig{}, e
	}
	return registeredClient(state), nil
}
