package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestVerifySpec_AdHoc_StageEnvIgnoresUnsetEnv ensures stageVerifyEnv
// is a no-op when KEYCLOAK_ISSUER is unset (no spurious ansible call).
func TestVerifySpec_AdHoc_StageEnvIgnoresUnsetEnv(t *testing.T) {
	t.Setenv("KEYCLOAK_ISSUER", "")
	stageVerifyEnv("/dev/null")
}

// TestVerifySpec_AdHoc_StageEnvIgnoresEmptyInv ensures stageVerifyEnv
// is a no-op when there's no inventory.
func TestVerifySpec_AdHoc_StageEnvIgnoresEmptyInv(t *testing.T) {
	t.Setenv("KEYCLOAK_ISSUER", "http://idp.infra.internal:8080/realms/master")
	stageVerifyEnv("")
}

// TestVerifySpec_AdHoc_LocalModeStillPassesWithEnvSet makes sure
// having KEYCLOAK_ISSUER set does not break local mode.
func TestVerifySpec_AdHoc_LocalModeStillPassesWithEnvSet(t *testing.T) {
	tmp := t.TempDir()
	specPath := filepath.Join(tmp, "x.md")
	body := "# Verification Spec — verify-test\n\n## 2. Checklist\n\n| ID | Category | Check | Expected | Command |\n|----|----------|-------|----------|---------|\n| C1 | file | a | present | `test -d /tmp` |\n"
	if err := os.WriteFile(specPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYCLOAK_ISSUER", "http://idp.infra.internal:8080/realms/master")
	tool := &VerifySpecTool{LocalOnly: true}
	res, err := tool.Execute(context.Background(), json.RawMessage(`{"spec_path":"`+specPath+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("result.IsError=true content=%q", res.Content)
	}
}
