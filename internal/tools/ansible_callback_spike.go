package tools

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type callbackProbeStatus string

const (
	callbackStatusOK          callbackProbeStatus = "ok"
	callbackStatusTimeout     callbackProbeStatus = "timeout"
	callbackStatusUnreachable callbackProbeStatus = "unreachable"
	callbackStatusModuleError callbackProbeStatus = "module_error"
	callbackStatusRunnerError callbackProbeStatus = "runner_error"
	callbackStatusMissing     callbackProbeStatus = "missing"
)

type callbackProbeResult struct {
	Host       string
	Stdout     string
	Stderr     string
	ExitCode   int
	Status     callbackProbeStatus
	Message    string
	StartedAt  string
	FinishedAt string
}

type callbackDocument struct {
	Plays []struct {
		Tasks []struct {
			Hosts map[string]callbackHostPayload `json:"hosts"`
		} `json:"tasks"`
	} `json:"plays"`
}

type callbackHostPayload struct {
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	ModuleStderr string `json:"module_stderr"`
	Message      string `json:"msg"`
	Start        string `json:"start"`
	End          string `json:"end"`
	RC           *int   `json:"rc"`
	Failed       bool   `json:"failed"`
	Unreachable  bool   `json:"unreachable"`
}

// decodeAnsibleCallbackSpike decodes the complete ansible.posix.json document
// emitted by one isolated ad-hoc task. Its historical name is retained so the
// M0.2 fixture tests remain traceable; it is now the production per-host
// callback decoder.
func decodeAnsibleCallbackSpike(raw []byte, expectedHosts []string) ([]callbackProbeResult, error) {
	var doc callbackDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("decode ansible callback JSON: %w", err)
	}

	observed := make(map[string]callbackHostPayload)
	for _, play := range doc.Plays {
		for _, task := range play.Tasks {
			for host, payload := range task.Hosts {
				if _, duplicate := observed[host]; duplicate {
					return nil, fmt.Errorf("ansible callback contains duplicate host result %q", host)
				}
				observed[host] = payload
			}
		}
	}

	expected := make(map[string]struct{}, len(expectedHosts))
	for _, host := range expectedHosts {
		if host == "" {
			return nil, fmt.Errorf("expected host set contains an empty host")
		}
		if _, duplicate := expected[host]; duplicate {
			return nil, fmt.Errorf("expected host set contains duplicate %q", host)
		}
		expected[host] = struct{}{}
	}
	if len(expected) == 0 {
		return nil, fmt.Errorf("expected host set is empty")
	}

	var unexpected []string
	for host := range observed {
		if _, ok := expected[host]; !ok {
			unexpected = append(unexpected, host)
		}
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		return nil, fmt.Errorf("callback returned unexpected hosts: %s", strings.Join(unexpected, ", "))
	}

	results := make([]callbackProbeResult, 0, len(expectedHosts))
	for _, host := range expectedHosts {
		payload, ok := observed[host]
		if !ok {
			results = append(results, callbackProbeResult{
				Host:     host,
				ExitCode: -1,
				Status:   callbackStatusMissing,
				Message:  "host absent from complete callback document",
			})
			continue
		}

		result := callbackProbeResult{
			Host:       host,
			Stdout:     normalizeCallbackText(payload.Stdout),
			Stderr:     normalizeCallbackText(firstNonEmpty(payload.Stderr, payload.ModuleStderr)),
			ExitCode:   -1,
			Status:     callbackStatusOK,
			Message:    payload.Message,
			StartedAt:  payload.Start,
			FinishedAt: payload.End,
		}
		if payload.RC != nil {
			result.ExitCode = *payload.RC
		}
		switch {
		case payload.Unreachable:
			result.Status = callbackStatusUnreachable
		case payload.Failed || (payload.RC != nil && *payload.RC != 0):
			result.Status = callbackStatusModuleError
		}
		results = append(results, result)
	}
	return results, nil
}

func callbackRunnerErrorResults(expectedHosts []string, cause error) []callbackProbeResult {
	results := make([]callbackProbeResult, 0, len(expectedHosts))
	for _, host := range expectedHosts {
		results = append(results, callbackProbeResult{
			Host:     host,
			ExitCode: -1,
			Status:   callbackStatusRunnerError,
			Message:  cause.Error(),
		})
	}
	return results
}

func normalizeCallbackText(value string) string {
	return strings.ReplaceAll(value, "\r\n", "\n")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
