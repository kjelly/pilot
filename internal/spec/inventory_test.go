package spec

import (
	"strings"
	"testing"
)

const sampleTargetSpec = `# Verification Spec — inventory-demo

> 版本：v1.0
> 對齊規範：none
> 維護者：sre

## 1. 目標系統

| Hostname | Group | Address | User | Port | IdentityFile |
|----------|-------|---------|------|------|--------------|
| bastion-01 | all | 10.0.0.1 | ubuntu | 22 | ~/.ssh/id_ed25519 |
| web-01     | web  | 10.0.1.1 | deploy |   |                |
| db-01      | db   | 10.0.2.1 |        | 2222 |               |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file    | x     | present  | test -f /etc/os-release |
`

func TestParse_TargetsTable(t *testing.T) {
	s, err := ParseReader(strings.NewReader(sampleTargetSpec))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(s.Hosts))
	}
	want := []struct {
		Hostname, Group, Address, User, Port, IdentityFile string
	}{
		{"bastion-01", "all", "10.0.0.1", "ubuntu", "22", "~/.ssh/id_ed25519"},
		{"web-01", "web", "10.0.1.1", "deploy", "", ""},
		{"db-01", "db", "10.0.2.1", "", "2222", ""},
	}
	for i, w := range want {
		h := s.Hosts[i]
		if h.Hostname != w.Hostname || h.Group != w.Group || h.Address != w.Address ||
			h.User != w.User || h.Port != w.Port || h.IdentityFile != w.IdentityFile {
			t.Errorf("Hosts[%d] = %+v, want %+v", i, h, w)
		}
	}
}

func TestGenerateInventory_Simple(t *testing.T) {
	s, err := ParseReader(strings.NewReader(sampleTargetSpec))
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.GenerateInventory(GenerateInventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "all:\n  hosts:\n    \"bastion-01\":") {
		t.Errorf("missing 'all/bastion-01' entry:\n%s", out)
	}
	if !strings.Contains(out, "web:\n  hosts:\n    \"web-01\":") {
		t.Errorf("missing 'web/web-01' entry:\n%s", out)
	}
	if !strings.Contains(out, "ansible_host: \"10.0.1.1\"") {
		t.Errorf("missing ansible_host for web-01:\n%s", out)
	}
}

func TestGenerateInventory_NoTargetsIsEmpty(t *testing.T) {
	body := `# Verification Spec — notargets

> 版本：v1.0
> 對齊規範：none
> 維護者：sre

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | x | present | test -f /etc/os-release |
`
	s, err := ParseReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if s.HasTargets() {
		t.Fatal("expected HasTargets=false")
	}
	out, err := s.GenerateInventory(GenerateInventoryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out != "" {
		t.Errorf("GenerateInventory on a targets-less spec must return empty, got %q", out)
	}
}

func TestRegression_EmptyHostnameRejected(t *testing.T) {
	// Regression: an empty Hostname row in the Targets table must
	// fail at parse time, not silently produce an "all:" block with
	// no entries.
	body := `# Verification Spec — bad

> 版本：v1.0
> 對齊規範：none
> 維護者：sre

## 1. 目標系統

| Hostname | Group | Address |
|----------|-------|---------|
|          | all   | 10.0.0.1 |
| web-01   | web   | 10.0.1.1 |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | x | present | test -f /etc/os-release |
`
	_, err := ParseReader(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected parse error for empty Hostname row, got nil")
	}
	if !strings.Contains(err.Error(), "Hostname is empty") {
		t.Errorf("error must mention 'Hostname is empty'; got %v", err)
	}
}
