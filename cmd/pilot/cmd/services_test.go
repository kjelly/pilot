package cmd

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServicesCommandRegistered(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Name() == "services" {
			return
		}
	}
	t.Fatal("services command is not registered")
}

func TestServicesSubcommandsRegistered(t *testing.T) {
	want := map[string]bool{"up": true, "status": true, "down": true, "purge": true}
	for _, c := range servicesCmd.Commands() {
		delete(want, c.Name())
	}
	if len(want) != 0 {
		t.Fatalf("missing services subcommands: %v", want)
	}
}

func TestServicesPurgeRequiresConfirmFlag(t *testing.T) {
	rootCmd.SetArgs([]string{"services", "purge", "--data-dir", t.TempDir()})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
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
