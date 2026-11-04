package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
