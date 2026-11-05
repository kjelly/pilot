package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/services"
	"github.com/kjelly/pilot/internal/statefile"
)

func TestServicesCLIConstructorHonorsCommandCancellation(t *testing.T) {
	t.Setenv("PILOT_SERVICES_DIR", t.TempDir())
	file, err := os.OpenFile(fmt.Sprintf("/tmp/pilot-services-compose-%d.lock", os.Getuid()), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	oldContext := rootCmd.Context()
	oldOut, oldErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"services", "consumers"})
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(oldContext)
		rootCmd.SetOut(oldOut)
		rootCmd.SetErr(oldErr)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := rootCmd.ExecuteContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CLI ignored canceled constructor: %v", err)
	}
}

func TestServicesCLIExactReleaseRequiresInterruptionConfirmation(t *testing.T) {
	t.Setenv("PILOT_SERVICES_DIR", t.TempDir())
	oldID, oldConfirm := svcConsumerID, svcConfirmInterruption
	oldOut, oldErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	t.Cleanup(func() {
		svcConsumerID, svcConfirmInterruption = oldID, oldConfirm
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(oldOut)
		rootCmd.SetErr(oldErr)
	})
	rootCmd.SetArgs([]string{"services", "release-consumer", "--id", "one-exact-synthetic-domain"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "confirm-interruption") {
		t.Fatalf("CLI released consumer without interruption confirmation: %v", err)
	}
}

func TestServicesCommandRegistered(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "services" {
			return
		}
	}
	t.Fatal("services command is not registered")
}

func TestServicesSubcommandsRegistered(t *testing.T) {
	want := map[string]bool{"up": true, "status": true, "down": true, "purge": true, "repair": true, "consumers": true, "release-consumer": true}
	for _, c := range servicesCmd.Commands() {
		delete(want, c.Name())
	}
	if len(want) != 0 {
		t.Fatalf("missing services subcommands: %v", want)
	}
}

func TestServicesPurgeRequiresConfirmFlag(t *testing.T) {
	t.Setenv("PILOT_SERVICES_DIR", t.TempDir())
	rootCmd.SetArgs([]string{"services", "purge", "--data-dir", t.TempDir()})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	defer rootCmd.SetArgs(nil)
	t.Cleanup(func() { dataDir = "" })
	svcConfirm = false
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("want confirmation error, got %v", err)
	}
}

func TestDiscoverLibvirtNetworkAddress(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "virsh")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\nprintf '%s' \"<network><ip address='192.168.122.1' netmask='255.255.255.0'/></network>\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_VIRSH_BIN", shim)
	ip, err := discoverLibvirtNetworkAddress(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	if want := net.ParseIP("192.168.122.1"); !ip.Equal(want) {
		t.Fatalf("got %s, want %s", ip, want)
	}
}

func TestDiscoverLibvirtNetworkAddressErrorsWithoutGateway(t *testing.T) {
	dir := t.TempDir()
	shim := filepath.Join(dir, "virsh")
	if err := os.WriteFile(shim, []byte("#!/bin/sh\necho '<network></network>'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_VIRSH_BIN", shim)
	if _, err := discoverLibvirtNetworkAddress(context.Background(), "default"); err == nil {
		t.Fatal("missing gateway must fail")
	}
}

func TestServicesConsumerCLIWithoutManagementMaterial(t *testing.T) {
	for _, missing := range []string{"harbor/secrets/admin-password", "ca/ca-key.pem", "pulp/settings/secret-key"} {
		t.Run(missing, func(t *testing.T) {
			legacy, discovery := t.TempDir(), t.TempDir()
			bundle, err := services.RenderBundle(services.BuiltInDevLite(), services.DataRoot(legacy), net.ParseIP("127.0.0.1"))
			if err != nil {
				t.Fatal(err)
			}
			store, err := statefile.New[services.ServiceState](legacy, "services.json", 1, "services")
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Mutate(func([]services.ServiceState) ([]services.ServiceState, error) {
				return []services.ServiceState{{Profile: bundle.Client.Profile, Fingerprint: bundle.Client.Fingerprint, Root: bundle.Root, ComposePath: bundle.ComposePath, Client: bundle.Client, BindIP: "127.0.0.1", Running: true, ConsumerTracking: true}}, nil
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := services.NewSharedManager(services.DiscoveryOptions{Directory: discovery, AdoptFrom: legacy}, nil); err != nil {
				t.Fatal(err)
			}
			// Model two already registered VMs; bookkeeping must never probe or
			// start the native services to list/release these durable records.
			store, err = statefile.New[services.ServiceState](discovery, "services.json", 1, "services")
			if err != nil {
				t.Fatal(err)
			}
			var wanted []services.Consumer
			if err := store.Mutate(func(states []services.ServiceState) ([]services.ServiceState, error) {
				for _, id := range []string{"exact-consumer-one", "exact-consumer-two"} {
					wanted = append(wanted, services.Consumer{ID: id, Name: id, StateDirectory: legacy, DiscoveryDirectory: discovery, InstanceID: states[0].InstanceID, Generation: states[0].Generation})
				}
				states[0].Consumers = wanted
				return states, nil
			}); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(bundle.Root, missing)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PILOT_SERVICES_DIR", discovery)
			oldDir, oldAdopt, oldCfg := servicesDir, servicesAdoptFrom, cfgFile
			oldID, oldConfirm := svcConsumerID, svcConfirmInterruption
			oldCtx, oldOut, oldErr := rootCmd.Context(), rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
			oldListCtx, oldReleaseCtx := servicesConsumersCmd.Context(), servicesReleaseConsumerCmd.Context()
			servicesDir, servicesAdoptFrom, cfgFile = "", "", ""
			var stdout, stderr bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stderr)
			t.Cleanup(func() {
				servicesDir, servicesAdoptFrom, cfgFile = oldDir, oldAdopt, oldCfg
				svcConsumerID, svcConfirmInterruption = oldID, oldConfirm
				rootCmd.SetArgs(nil)
				rootCmd.SetContext(oldCtx)
				servicesConsumersCmd.SetContext(oldListCtx)
				servicesReleaseConsumerCmd.SetContext(oldReleaseCtx)
				rootCmd.SetOut(oldOut)
				rootCmd.SetErr(oldErr)
			})
			execute := func(args ...string) error {
				stdout.Reset()
				stderr.Reset()
				rootCmd.SetArgs(args)
				// Cobra retains child contexts across repeated executions in tests.
				// Earlier cancellation tests must not supply this command's context.
				servicesConsumersCmd.SetContext(context.Background())
				servicesReleaseConsumerCmd.SetContext(context.Background())
				return rootCmd.ExecuteContext(context.Background())
			}
			list := func() []services.Consumer {
				t.Helper()
				if err := execute("services", "consumers"); err != nil {
					t.Fatalf("listing consumers requires unavailable management material: %v", err)
				}
				var got []services.Consumer
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
				return got
			}
			if got := list(); len(got) != 2 || got[0] != wanted[0] || got[1] != wanted[1] {
				t.Fatalf("listing lost durable identities: %+v", got)
			}
			if err := execute("services", "release-consumer", "--id", wanted[0].ID, "--confirm-interruption=false"); err == nil || !strings.Contains(err.Error(), "confirm-interruption") {
				t.Errorf("release did not enforce interruption confirmation: %v", err)
			}
			if got := list(); len(got) != 2 {
				t.Fatal("unconfirmed release changed registrations")
			}
			if err := execute("services", "release-consumer", "--id", wanted[0].ID, "--confirm-interruption"); err != nil {
				t.Fatalf("exact confirmed release requires unavailable management material: %v", err)
			}
			if got := list(); len(got) != 1 || got[0] != wanted[1] {
				t.Fatalf("exact release changed another consumer: %+v", got)
			}
			if _, err := newServiceManagerContext(context.Background()); err == nil {
				t.Fatal("bookkeeping weakened management discovery prerequisites")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("bookkeeping recreated management material")
			}
		})
	}
}
