package cmd

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestValidateDeployStageFlags(t *testing.T) {
	for _, tt := range []struct {
		stage, hours string
		wantErr      string
	}{
		{stage: "", hours: ""},
		{stage: "sandbox", hours: ""},
		{stage: "staging", hours: ""},
		{stage: "prod", hours: "72"},
		{stage: "prod", hours: "0"},
		{stage: "prod", hours: "168"},
		{stage: "production", wantErr: "--stage 只能是"},
		{stage: "prod", hours: "", wantErr: "需要 --staging-attested-within-hours"},
		{stage: "prod", hours: "169", wantErr: "0-168"},
		{stage: "prod", hours: "soon", wantErr: "請輸入數字"},
		{stage: "staging", hours: "24", wantErr: "只能搭配 --stage prod"},
		{stage: "", hours: "24", wantErr: "只能搭配 --stage prod"},
	} {
		err := validateDeployStageFlags(tt.stage, tt.hours)
		if tt.wantErr == "" {
			if err != nil {
				t.Errorf("validateDeployStageFlags(%q, %q) = %v, want nil", tt.stage, tt.hours, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("validateDeployStageFlags(%q, %q) = %v, want %q", tt.stage, tt.hours, err, tt.wantErr)
		}
	}
}

// TestPromptStageDecisionUsesStageFlag runs under a driver with no answers,
// so any stage, confirm or attestation prompt that still fired would fail.
func TestPromptStageDecisionUsesStageFlag(t *testing.T) {
	prevStage, prevHours, prevPrompt := deployStageFlag, deployStagingAttestedHoursFlag, activePromptAutomation
	t.Cleanup(func() {
		deployStageFlag, deployStagingAttestedHoursFlag, activePromptAutomation = prevStage, prevHours, prevPrompt
	})
	for _, tt := range []struct {
		stage, hours string
		want         stageDecision
	}{
		{stage: "sandbox", want: stageDecision{Stage: "sandbox"}},
		{stage: "staging", want: stageDecision{Stage: "staging", ConfirmVars: []string{"confirm_staging=true"}}},
		{stage: "prod", hours: "72", want: stageDecision{Stage: "prod", ConfirmVars: []string{"confirm_prod=true", "staging_attested_within_hours=72"}}},
	} {
		driver := &promptAutomation{action: "deploy"}
		activePromptAutomation = driver
		deployStageFlag, deployStagingAttestedHoursFlag = tt.stage, tt.hours

		got, err := promptStageDecision(&bytes.Buffer{}, "site.yml")
		if err != nil || driver.err != nil {
			t.Fatalf("--stage %s: promptStageDecision() error = %v, driver error = %v; want no prompt", tt.stage, err, driver.err)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Fatalf("--stage %s: decision = %#v, want %#v", tt.stage, got, tt.want)
		}
	}
}

func TestDeployRejectsStageFlagMisuse(t *testing.T) {
	prevStage, prevHours, prevActions := deployStageFlag, deployStagingAttestedHoursFlag, deployActionsPath
	t.Cleanup(func() {
		deployStageFlag, deployStagingAttestedHoursFlag, deployActionsPath = prevStage, prevHours, prevActions
	})

	deployStageFlag, deployStagingAttestedHoursFlag, deployActionsPath = "staging", "", filepath.Join(t.TempDir(), "scenario.json")
	if err := runDeploy(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "--stage 不能與 --actions") {
		t.Fatalf("--stage --actions: error = %v", err)
	}
	deployStageFlag, deployActionsPath = "prod", ""
	if err := runDeploy(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "--staging-attested-within-hours") {
		t.Fatalf("--stage prod without hours: error = %v", err)
	}
}
