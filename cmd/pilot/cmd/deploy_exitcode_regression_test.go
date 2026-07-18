package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
)

func TestExecuteDeployment_NonZeroAnsibleExitIsError(t *testing.T) {
	tests := []struct {
		name        string
		answers     []bool
		wantMessage string
	}{
		{
			name:        "preview",
			answers:     []bool{true, true},
			wantMessage: "預覽失敗(結束碼 2)",
		},
		{
			name:        "apply",
			answers:     []bool{false, true},
			wantMessage: "套用失敗(結束碼 2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner := ansible.NewRunner()
			runner.Binary = writeExitFixture(t, 2)
			runner.Timeout = 5 * time.Second

			restore := stubDeploymentConfirm(t, tt.answers...)
			defer restore()

			var out bytes.Buffer
			err := executeDeployment(
				context.Background(),
				runner,
				&out,
				"playbooks/apply/docker-apply.yml",
				"inventory.yml",
				"",
				"",
				nil,
				vaultInput{},
			)
			if err == nil {
				t.Fatal("executeDeployment() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Fatalf("executeDeployment() error = %q, want substring %q", err, tt.wantMessage)
			}
		})
	}
}

func TestExecuteDeployment_MissingBinaryIsError(t *testing.T) {
	runner := ansible.NewRunner()
	runner.Binary = filepath.Join(t.TempDir(), "missing-ansible-playbook")
	runner.Timeout = 5 * time.Second

	restore := stubDeploymentConfirm(t, false, true)
	defer restore()

	err := executeDeployment(
		context.Background(),
		runner,
		&bytes.Buffer{},
		"playbooks/apply/docker-apply.yml",
		"inventory.yml",
		"",
		"",
		nil,
		vaultInput{},
	)
	if err == nil {
		t.Fatal("executeDeployment() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "ansible run failed") {
		t.Fatalf("executeDeployment() error = %q, want original runner error", err)
	}
}

func TestExecuteDeployment_CancelBeforeRunIsCleanExit(t *testing.T) {
	runner := ansible.NewRunner()
	runner.Binary = writeExitFixture(t, 0)

	restore := stubDeploymentConfirm(t, false, false)
	defer restore()

	err := executeDeployment(
		context.Background(),
		runner,
		&bytes.Buffer{},
		"playbooks/apply/docker-apply.yml",
		"inventory.yml",
		"",
		"",
		nil,
		vaultInput{},
	)
	if !errors.Is(err, errDeployAborted) {
		t.Fatalf("executeDeployment() error = %v, want errDeployAborted", err)
	}
	if got := abortOrErr(err); got != nil {
		t.Fatalf("abortOrErr(errDeployAborted) = %v, want nil", got)
	}
}

func TestAbortOrErr_PreflightRejectedIsFailure(t *testing.T) {
	if got := abortOrErr(errPreflightRejected); !errors.Is(got, errPreflightRejected) {
		t.Fatalf("abortOrErr(errPreflightRejected) = %v, want original error", got)
	}
}

func stubDeploymentConfirm(t *testing.T, answers ...bool) func() {
	t.Helper()
	original := confirmDeployment
	next := 0
	confirmDeployment = func(string, bool) bool {
		if next >= len(answers) {
			t.Fatalf("confirmDeployment called %d times, only %d answers provided", next+1, len(answers))
		}
		answer := answers[next]
		next++
		return answer
	}
	return func() {
		confirmDeployment = original
	}
}

func writeExitFixture(t *testing.T, exitCode int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible-playbook")
	script := []byte("#!/bin/sh\nexit " + strconv.Itoa(exitCode) + "\n")
	if err := os.WriteFile(path, script, 0o755); err != nil {
		t.Fatalf("write ansible fixture: %v", err)
	}
	return path
}
