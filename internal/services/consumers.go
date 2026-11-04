package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"slices"
)

// LockConsumerDomain serializes provisioning/teardown of one host-global domain name.
// It is independent of repository, discovery directory and VM state directory.
func LockConsumerDomain(ctx context.Context, name string) (func(), error) {
	key := sha256.Sum256([]byte(name))
	file, err := lockOperationContext(ctx, fmt.Sprintf("/var/tmp/pilot-services-domain-%d-%x.lock", os.Getuid(), key))
	if err != nil {
		return nil, err
	}
	return func() { file.Close() }, nil
}

// Consumer is a durable claim for a VM that can outlive its provisioning process.
// ID is the guest domain UUID, never a PID or an expiring process lease.
type Consumer struct {
	Capabilities       string `json:"capabilities,omitempty"`
	ID                 string `json:"id"`
	Name               string `json:"name"`
	StateDirectory     string `json:"state_directory"`
	DiscoveryDirectory string `json:"discovery_directory"`
	InstanceID         string `json:"instance_id"`
	Generation         uint64 `json:"generation"`
}

// MaintenanceOptions acknowledges guests created before durable tracking existed.
// It never bypasses protection for registered consumers.
type MaintenanceOptions struct {
	AcknowledgeLegacyClients bool
}

func maintenanceAllowed(state ServiceState, options MaintenanceOptions) error {
	if len(state.Consumers) != 0 {
		return fmt.Errorf("services: maintenance refused: %d registered VM consumer(s); tear down their VMs or explicitly release one exact registration with interruption confirmation", len(state.Consumers))
	}
	if state.Fingerprint != "" && !state.ConsumerTracking && !options.AcknowledgeLegacyClients {
		return errors.New("services: maintenance requires --acknowledge-legacy-clients: unregistered legacy guests may be interrupted")
	}
	return nil
}

// Directory returns the canonical discovery directory for durable consumers.
func (m *Manager) Directory() string { return m.dataDir }

// RegisterConsumer atomically verifies a successful client contract and blocks maintenance.
func (m *Manager) RegisterConsumer(ctx context.Context, expected ClientConfig, consumer Consumer) error {
	return m.RegisterConsumerFor(ctx, expected, consumer, nil)
}

func (m *Manager) RegisterConsumerFor(ctx context.Context, expected ClientConfig, consumer Consumer, required Requirements) error {
	return m.registerConsumer(ctx, expected, consumer, required, nil, nil)
}

// RegisterConsumerWithPolicy carries explicit physical profile and readonly policy.
func (m *Manager) RegisterConsumerWithPolicy(ctx context.Context, expected ClientConfig, consumer Consumer, required Requirements, profile Profile, policy ProbePolicy) error {
	return m.registerConsumer(ctx, expected, consumer, required, &profile, policy)
}

func (m *Manager) registerConsumer(ctx context.Context, expected ClientConfig, consumer Consumer, required Requirements, profile *Profile, policy ProbePolicy) error {
	if _, err := NormalizeRequirements(required); err != nil {
		return err
	}
	if consumer.Capabilities != "" {
		declared, err := ParseRequirements(consumer.Capabilities)
		if err != nil || !slices.Equal(declared, mustNormalizeRequirements(required)) {
			return errors.New("services: consumer capability declaration differs from request")
		}
	} else if required != nil && !slices.Equal(mustNormalizeRequirements(required), Requirements{APT, RPM, OCI}) {
		return errors.New("services: consumer capability declaration is required")
	}

	unlock, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := m.current()
	if err != nil {
		return err
	}
	if !m.shared || consumer.ID == "" || consumer.Name == "" || consumer.StateDirectory == "" || consumer.DiscoveryDirectory != m.dataDir || consumer.InstanceID != state.InstanceID || consumer.Generation != state.Generation {
		return errors.New("services: consumer identity does not match shared discovery")
	}
	if profile != nil {
		if err := validatePhysicalProfile(state, *profile, net.ParseIP(expected.HostIP)); err != nil {
			return err
		}
	} else {
		if err := validateConsumptionData(state); err != nil {
			return err
		}
		policy = compatibilityPolicy(state)
	}
	actual := registeredClient(state)
	if !reflect.DeepEqual(canonicalClient(expected), canonicalClient(actual)) {
		return errors.New("services: consumer client contract is stale or stack is stopped")
	}
	if policy == nil {
		return errors.New("services: missing-descriptor: explicit validated physical profile and probe policy are required")
	}
	if err := policy.validate(required); err != nil {
		return err
	}
	observed := m.observeCapabilities(ctx, stateWithPolicy(state, policy))
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err := requireCapabilities(observed, required); err != nil {
		return err
	}
	return m.store.MutateContext(ctx, func(states []ServiceState) ([]ServiceState, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(states) != 1 {
			return nil, errors.New("services: missing consumer discovery state")
		}
		for _, existing := range states[0].Consumers {
			if existing.ID == consumer.ID {
				if existing != consumer {
					return nil, errors.New("services: conflicting consumer identity")
				}
				return states, nil
			}
		}
		states[0].Consumers = append(states[0].Consumers, consumer)
		return states, nil
	})
}

// Consumers lists persistent registrations, including pending or crashed VM provisioning.
func (m *Manager) Consumers(ctx context.Context) ([]Consumer, error) {
	unlock, err := m.operationContext(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	state, err := m.current()
	return slices.Clone(state.Consumers), err
}

// ReleaseConsumer removes one exact registration after the VM manager verified teardown.
func (m *Manager) ReleaseConsumer(ctx context.Context, consumer Consumer) error {
	return m.releaseConsumer(ctx, consumer.ID, &consumer)
}

// ForgetConsumer explicitly accepts interruption risk for one abandoned registration.
func (m *Manager) ForgetConsumer(ctx context.Context, id string, confirmed bool) error {
	if !confirmed {
		return errors.New("services: releasing a consumer requires --confirm-interruption; its VM may still need the cache")
	}
	return m.releaseConsumer(ctx, id, nil)
}

func (m *Manager) releaseConsumer(ctx context.Context, id string, expected *Consumer) error {
	if id == "" {
		return errors.New("services: exact consumer ID is required")
	}
	unlock, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	return m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		if len(states) != 1 {
			return nil, errors.New("services: consumer discovery state unavailable")
		}
		if expected != nil && (states[0].InstanceID != expected.InstanceID || states[0].Generation != expected.Generation || expected.DiscoveryDirectory != m.dataDir) {
			return nil, errors.New("services: consumer generation or discovery ownership differs from target record")
		}
		for i, consumer := range states[0].Consumers {
			if consumer.ID != id {
				continue
			}
			if expected != nil && consumer != *expected {
				return nil, errors.New("services: consumer ownership differs from target record")
			}
			states[0].Consumers = slices.Delete(states[0].Consumers, i, i+1)
			return states, nil
		}
		if expected != nil {
			return states, nil
		}
		return nil, errors.New("services: consumer ID is not registered")
	})
}
