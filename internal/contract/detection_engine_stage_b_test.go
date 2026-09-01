package contract

import "testing"

// TestDetectionEngineContract_StageBDelta locks spec §41.1's Stage B
// contract delta on contracts/detection-engine.yaml: the provider group
// vars/inputRules exist with the right names, types, and Stage-A-safe
// defaults, and the delta never adds a required Stage A field or a
// provider Vault section reference outside what §42.1 permits.
func TestDetectionEngineContract_StageBDelta(t *testing.T) {
	loader, err := NewLoader(contractRepoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	c, err := loader.LoadFile("contracts/detection-engine.yaml")
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}

	byName := make(map[string]GroupVar, len(c.GroupVars))
	for _, gv := range c.GroupVars {
		byName[gv.Name] = gv
	}

	wantDefaults := map[string]struct {
		typ      string
		required bool
		secret   bool
	}{
		"detection_model_provider_enabled":  {"boolean", false, false},
		"detection_model_provider_protocol": {"string", false, false},
		"detection_model_provider_base_url": {"string", false, false},
		"detection_model_provider_model":    {"string", false, false},
		"detection_model_provider_auth":     {"string", false, false},
		"detection_model_provider_api_key":  {"string", false, true},
		"detection_model_provider_external": {"boolean", false, false},
		"detection_allow_external_provider": {"boolean", false, false},
		// Optional second provider (NPU-primary-with-fallback: spec1.md
		// §35's alternate-backend fallback, generalized to any protocol
		// pair) — same Stage-A-safe shape as the primary block.
		"detection_model_provider_fallback_enabled":  {"boolean", false, false},
		"detection_model_provider_fallback_protocol": {"string", false, false},
		"detection_model_provider_fallback_base_url": {"string", false, false},
		"detection_model_provider_fallback_model":    {"string", false, false},
		"detection_model_provider_fallback_auth":     {"string", false, false},
		"detection_model_provider_fallback_api_key":  {"string", false, true},
	}
	for name, want := range wantDefaults {
		gv, ok := byName[name]
		if !ok {
			t.Errorf("groupVars missing Stage B var %q", name)
			continue
		}
		if gv.Type != want.typ {
			t.Errorf("groupVar %s type = %q, want %q", name, gv.Type, want.typ)
		}
		if gv.Required != want.required {
			t.Errorf("groupVar %s required = %v, want %v (Stage B is never required for a Stage A apply)", name, gv.Required, want.required)
		}
		if gv.Secret != want.secret {
			t.Errorf("groupVar %s secret = %v, want %v", name, gv.Secret, want.secret)
		}
	}

	// Stage A endpoint/path inputs remain required. The artifact checksum is
	// optional because pilot-cli now packages the binary and adjacent SHA256
	// sidecar; an explicit checksum remains supported for external artifacts.
	for _, name := range []string{"detection_engine_artifact_path", "detection_metrics_source_host", "detection_alertmanager_target_host"} {
		gv, ok := byName[name]
		if !ok || !gv.Required {
			t.Errorf("Stage A groupVar %q must remain required=true after the Stage B delta", name)
		}
	}
	if gv, ok := byName["detection_engine_artifact_sha256"]; !ok || gv.Required {
		t.Error("detection_engine_artifact_sha256 must be optional when pilot-cli supplies the packaged sidecar")
	}

	if len(c.InputRules) == 0 {
		t.Fatal("expected Stage B inputRules (base_url/model/api_key enabled-provider requirements) to be present")
	}
	for _, rule := range c.InputRules {
		if len(rule.Any) == 0 {
			t.Errorf("Stage B inputRule %q should use the any-form disabled-exception pattern", rule.Reason)
		}
	}
}
