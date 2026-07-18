// Command eval runs deterministic, model-independent delivery-bundle gates.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type gate struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Duration string `json:"duration"`
	Detail   string `json:"detail,omitempty"`
}

type scorecard struct {
	SchemaVersion int    `json:"schemaVersion"`
	GeneratedAt   string `json:"generatedAt"`
	Root          string `json:"root"`
	Status        string `json:"status"`
	Score         int    `json:"score"`
	Gates         []gate `json:"gates"`
}

func main() {
	root := flag.String("root", ".", "repository root containing the candidate bundle")
	output := flag.String("output", "tmp/eval-scorecard.json", "scorecard output path")
	target := flag.String("target-test", os.Getenv("PILOT_EVAL_TARGET_TEST"), "authorized disposable target-test command")
	requireTarget := flag.Bool("require-target", false, "fail unless a target/idempotency test is executed")
	flag.Parse()

	absRoot, err := filepath.Abs(*root)
	if err != nil {
		fatal(err)
	}
	card := scorecard{SchemaVersion: 1, GeneratedAt: time.Now().UTC().Format(time.RFC3339), Root: absRoot}
	card.Gates = append(card.Gates,
		run(absRoot, "contract-lint", "go", "run", "./cmd/pilot", "contract", "lint"),
		run(absRoot, "tag-coverage", "go", "test", "-count=1", "-run", "TestSpecPlaybookTagAlignment", "./cmd/pilot/cmd"),
		run(absRoot, "shell-syntax", "go", "test", "-count=1", "-run", "TestShellSyntax", "./internal/spec"),
		scanBundle(absRoot),
	)
	if strings.TrimSpace(*target) == "" {
		status := "not_run"
		if *requireTarget {
			status = "fail"
		}
		card.Gates = append(card.Gates, gate{Name: "target-and-idempotency", Status: status, Detail: "set PILOT_EVAL_TARGET_TEST or --target-test to an authorized disposable target test"})
	} else {
		card.Gates = append(card.Gates, run(absRoot, "target-and-idempotency", "bash", "-lc", *target))
	}
	card.Status, card.Score = summarize(card.Gates)
	if err := writeScorecard(absRoot, *output, card); err != nil {
		fatal(err)
	}
	if card.Status == "fail" {
		os.Exit(1)
	}
}

func run(root, name, binary string, args ...string) gate {
	started := time.Now()
	command := exec.Command(binary, args...)
	command.Dir = root
	command.Env = append(os.Environ(), "GOCACHE="+envDefault("GOCACHE", "/tmp/pilot-eval-go-build"))
	output, err := command.CombinedOutput()
	result := gate{Name: name, Status: "pass", Duration: time.Since(started).Round(time.Millisecond).String()}
	if err != nil {
		result.Status = "fail"
		result.Detail = truncate(strings.TrimSpace(string(output)), 4000)
	}
	return result
}

func scanBundle(root string) gate {
	started := time.Now()
	secret := regexp.MustCompile(`(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{8,}`)
	ip := regexp.MustCompile(`(?m)(ansible_host|[a-z_]+_host)\s*:\s*["']?([0-9]{1,3}\.){3}[0-9]{1,3}`)
	findings := make([]string, 0)
	for _, base := range []string{"contracts", "playbooks/apply"} {
		_ = filepath.WalkDir(filepath.Join(root, base), func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			ext := filepath.Ext(path)
			if ext != ".yml" && ext != ".yaml" {
				return nil
			}
			if strings.Contains(entry.Name(), ".example.") {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if secret.Match(data) {
				findings = append(findings, filepath.ToSlash(path)+": possible inline secret")
			}
			if ip.Match(data) {
				findings = append(findings, filepath.ToSlash(path)+": host-specific IPv4 literal")
			}
			return nil
		})
	}
	sort.Strings(findings)
	result := gate{Name: "secret-and-host-literal-scan", Status: "pass", Duration: time.Since(started).Round(time.Millisecond).String()}
	if len(findings) > 0 {
		result.Status = "fail"
		result.Detail = strings.Join(findings, "\n")
	}
	return result
}

func summarize(gates []gate) (string, int) {
	passed := 0
	status := "pass"
	for _, item := range gates {
		switch item.Status {
		case "pass":
			passed++
		case "fail":
			status = "fail"
		case "not_run":
			if status != "fail" {
				status = "incomplete"
			}
		}
	}
	return status, passed * 100 / len(gates)
}

func writeScorecard(root, output string, card scorecard) error {
	path := output
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(card, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("authoring eval: %s (score=%d) → %s\n", card.Status, card.Score, path)
	return nil
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n…truncated"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
