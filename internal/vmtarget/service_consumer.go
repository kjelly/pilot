package vmtarget

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/kjelly/pilot/internal/services"
)

func (m *Manager) registerServiceConsumer(ctx context.Context, target *Target, bootstrap *ServiceBootstrap) error {
	if bootstrap == nil {
		return nil
	}
	if err := bootstrap.Validate(); err != nil {
		return err
	}
	if bootstrap.DiscoveryDirectory == "" || bootstrap.InstanceID == "" || bootstrap.Generation == 0 {
		return errors.New("vmtarget: services require shared discovery identity for durable guest protection")
	}
	manager, err := services.NewSharedManagerContext(ctx, services.DiscoveryOptions{Directory: bootstrap.DiscoveryDirectory, ConsumptionOnly: true}, nil)
	if err != nil {
		return err
	}
	stateDir, err := services.CanonicalDirectory(m.stateDir)
	if err != nil {
		return err
	}
	consumer := services.Consumer{Capabilities: services.RequirementKey(bootstrap.Requirements), ID: uuid.NewString(), Name: target.Name, StateDirectory: stateDir, DiscoveryDirectory: manager.Directory(), InstanceID: bootstrap.InstanceID, Generation: bootstrap.Generation}
	expected := services.ClientConfig{InstanceID: bootstrap.InstanceID, Generation: bootstrap.Generation, Profile: bootstrap.Profile, Fingerprint: bootstrap.Fingerprint, HostIP: bootstrap.HostIP, Hostname: bootstrap.Hostname, AptProxyURL: bootstrap.AptProxyURL, RPMBaseURL: bootstrap.RPMBaseURL, RPMRepositories: bootstrap.RPMRepositories, RegistryMirrorURL: bootstrap.RegistryMirrorURL, RegistryProjects: bootstrap.RegistryProjects, CAPEM: bootstrap.CAPEM, DataProbes: bootstrap.DataProbes}
	profile, err := bootstrap.physicalProfile()
	if err != nil {
		return err
	}
	if err := manager.RegisterConsumerWithPolicy(ctx, expected, consumer, bootstrap.Requirements, profile, bootstrap.DataProbes); err != nil {
		return err
	}
	target.ServiceConsumer = &consumer
	return nil
}

// serviceDomainPresent proves both UUID and name identity from successful probes.
func (m *Manager) serviceDomainPresent(ctx context.Context, target *Target) (bool, error) {
	consumer := target.ServiceConsumer
	stateDir, err := services.CanonicalDirectory(m.stateDir)
	if err != nil {
		return false, err
	}
	if consumer == nil || consumer.Name != target.Name || consumer.StateDirectory != stateDir || consumer.InstanceID == "" || consumer.Generation == 0 {
		return false, errors.New("vmtarget: service consumer ownership differs from target")
	}
	if _, err := uuid.Parse(consumer.ID); err != nil {
		return false, errors.New("vmtarget: service consumer domain UUID is invalid")
	}
	ids, err := m.virsh(ctx, "list", "--all", "--uuid")
	if err != nil {
		return false, err
	}
	if ids.ExitCode != 0 {
		return false, errors.New("vmtarget: cannot prove service consumer domain identity: UUID list failed")
	}
	names, err := m.virsh(ctx, "list", "--all", "--name")
	if err != nil {
		return false, err
	}
	if names.ExitCode != 0 {
		return false, errors.New("vmtarget: cannot prove service consumer domain identity: domain list failed")
	}
	hasID, hasName := false, false
	for _, id := range strings.Fields(ids.Stdout) {
		hasID = hasID || id == consumer.ID
	}
	for _, name := range strings.Fields(names.Stdout) {
		hasName = hasName || name == target.Name
	}
	if !hasID && !hasName {
		return false, nil
	}
	id, err := m.virsh(ctx, "domuuid", target.Name)
	if err != nil {
		return false, err
	}
	if !hasID || !hasName || id.ExitCode != 0 || strings.TrimSpace(id.Stdout) != consumer.ID {
		return false, errors.New("vmtarget: domain identity differs from durable service consumer; refusing teardown/release")
	}
	return true, nil
}

func (m *Manager) teardownServiceConsumer(ctx context.Context, target *Target) error {
	present, err := m.serviceDomainPresent(ctx, target)
	if err != nil {
		return err
	}
	if present {
		id := target.ServiceConsumer.ID
		state, err := m.virsh(ctx, "domstate", id)
		if err != nil {
			return err
		}
		if state.ExitCode != 0 {
			return errors.New("vmtarget: cannot inspect service consumer before teardown")
		}
		if strings.TrimSpace(state.Stdout) != "shut off" {
			result, err := m.virsh(ctx, "destroy", id)
			if err != nil {
				return err
			}
			if result.ExitCode != 0 {
				return errors.New("vmtarget: service consumer domain destroy failed; registration retained")
			}
		}
		result, err := m.virsh(ctx, "undefine", id, "--snapshots-metadata", "--managed-save", "--nvram")
		if err != nil {
			return err
		}
		if result.ExitCode != 0 {
			return errors.New("vmtarget: service consumer domain undefine failed; registration retained")
		}
	}
	if present, err := m.serviceDomainPresent(ctx, target); err != nil {
		return err
	} else if present {
		return errors.New("vmtarget: consumer domain still exists; registration retained")
	}
	m.cleanupTargetArtifacts(ctx, target)
	consumer := *target.ServiceConsumer
	manager, err := services.NewSharedManagerContext(ctx, services.DiscoveryOptions{Directory: consumer.DiscoveryDirectory}, nil)
	if err != nil {
		return err
	}
	if err := manager.ReleaseConsumer(ctx, consumer); err != nil {
		return fmt.Errorf("vmtarget: release verified consumer: %w", err)
	}
	return nil
}

func (bootstrap ServiceBootstrap) physicalProfile() (services.Profile, error) {
	if bootstrap.PhysicalProfile != nil {
		return *bootstrap.PhysicalProfile, nil
	}
	profile := services.BuiltInDevLite()
	fingerprint, e := profile.Fingerprint()
	if e == nil && bootstrap.Profile == profile.Name && bootstrap.Fingerprint == fingerprint {
		return profile, nil
	}
	return services.Profile{}, errors.New("vmtarget: explicit physical service profile is required")
}
