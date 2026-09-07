// Package workspaceintegrity reports filesystem-backed reference closure.
package workspaceintegrity

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/monitoring"
	"gopkg.in/yaml.v3"
)

type Reference struct {
	From   string `json:"from"`
	Field  string `json:"field"`
	To     string `json:"to"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type Report struct {
	Scope      string      `json:"scope"`
	Verdict    string      `json:"verdict"`
	References []Reference `json:"references"`
}

// Monitoring evaluates registry, profile, diagnostic-profile and SNMP module
// references without changing monitoring.Load*'s intentionally lenient CLI
// semantics.
func Monitoring(root string) Report {
	report := Report{Scope: "monitoring", Verdict: "complete"}
	add := func(ref Reference) {
		report.References = append(report.References, ref)
		if ref.Status != "ok" {
			report.Verdict = "incomplete"
		}
	}
	profilesPath := filepath.Join(root, "monitoring", "scrape-profiles.yml")
	targetsPath := filepath.Join(root, "monitoring", "targets.yml")
	var targets monitoring.TargetFile
	var profiles monitoring.ProfileFile
	if err := decodeStrict(targetsPath, &targets); err != nil {
		add(Reference{From: "monitoring/targets.yml", Field: "source", To: "monitoring/targets.yml", Status: statusFor(err), Error: err.Error()})
		return report
	}
	if err := decodeStrict(profilesPath, &profiles); err != nil {
		add(Reference{From: "monitoring/scrape-profiles.yml", Field: "source", To: "monitoring/scrape-profiles.yml", Status: statusFor(err), Error: err.Error()})
		// Keep the graph useful even when the profile document itself is
		// broken: each registry edge still records which target could not
		// resolve its named profile.
		for _, target := range targets.Targets {
			add(Reference{From: "monitoring/targets.yml#" + target.Name, Field: "profile", To: "monitoring/scrape-profiles.yml#" + target.Profile, Status: statusFor(err), Error: err.Error()})
		}
		return report
	}
	catalogPath := filepath.Join(root, "monitoring", "snmp", "catalog.yml")
	catalog, catalogErr := monitoring.LoadSNMPCatalog(catalogPath)
	for _, target := range targets.Targets {
		profile, ok := profiles.Profiles[target.Profile]
		if !ok {
			add(Reference{From: "monitoring/targets.yml#" + target.Name, Field: "profile", To: "monitoring/scrape-profiles.yml#" + target.Profile, Status: "missing"})
			continue
		}
		if profile.DiagnosticProfile != "" {
			rel := filepath.Join("monitoring", "snmp", "diagnostic-profiles", profile.DiagnosticProfile+".yaml")
			add(pathReference(root, "monitoring/scrape-profiles.yml#"+target.Profile, "diagnosticProfile", rel))
		}
		if !profile.IsSNMP() {
			continue
		}
		if profile.SNMP == nil {
			add(Reference{From: "monitoring/scrape-profiles.yml#" + target.Profile, Field: "snmp", To: "monitoring/scrape-profiles.yml#" + target.Profile, Status: "missing"})
			continue
		}
		if catalogErr != nil {
			add(Reference{From: "monitoring/scrape-profiles.yml#" + target.Profile, Field: "snmp", To: "monitoring/snmp/catalog.yml", Status: statusFor(catalogErr), Error: catalogErr.Error()})
			continue
		}
		if strings.TrimSpace(profile.SNMP.AuthProfile) == "" {
			add(Reference{From: "monitoring/scrape-profiles.yml#" + target.Profile, Field: "snmp.authProfile", To: "monitoring/snmp/catalog.yml#<empty>", Status: "missing"})
		} else if _, exists := catalog.AuthProfiles[profile.SNMP.AuthProfile]; !exists {
			add(Reference{From: "monitoring/scrape-profiles.yml#" + target.Profile, Field: "snmp.authProfile", To: "monitoring/snmp/catalog.yml#" + profile.SNMP.AuthProfile, Status: "missing"})
		}
		for _, module := range profile.SNMP.Modules {
			entry, exists := catalog.Modules[module]
			if !exists {
				add(Reference{From: "monitoring/scrape-profiles.yml#" + target.Profile, Field: "snmp.modules", To: "monitoring/snmp/catalog.yml#" + module, Status: "missing"})
				continue
			}
			if err := monitoring.ValidateSNMPModuleFilePath(entry.File); err != nil {
				add(Reference{From: "monitoring/snmp/catalog.yml#" + module, Field: "file", To: entry.File, Status: "parse_error", Error: err.Error()})
				continue
			}
			add(pathReference(root, "monitoring/snmp/catalog.yml#"+module, "file", filepath.Join("monitoring", "snmp", entry.File)))
		}
	}
	sort.Slice(report.References, func(i, j int) bool {
		return report.References[i].From+report.References[i].Field < report.References[j].From+report.References[j].Field
	})
	return report
}

func decodeStrict(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return fmt.Errorf("%s is empty", path)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	return decoder.Decode(out)
}

func statusFor(err error) string {
	if errors.Is(err, os.ErrNotExist) {
		return "missing"
	}
	if strings.Contains(err.Error(), " is empty") {
		return "empty"
	}
	return "parse_error"
}

func pathReference(root, from, field, rel string) Reference {
	if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
		return Reference{From: from, Field: field, To: rel, Status: "ok"}
	}
	return Reference{From: from, Field: field, To: rel, Status: "missing"}
}
