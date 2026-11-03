package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
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
	actual := state.Client
	if actual.HostIP == "" {
		actual.HostIP = state.BindIP
	}
	if !state.Running || !reflect.DeepEqual(expected, actual) {
		return errors.New("services: consumer client contract is stale or stack is stopped")
	}
	if err := m.probeEndpoints(ctx, state); err != nil {
		return err
	}
	return m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
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
