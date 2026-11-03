package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/statefile"
	"github.com/kjelly/pilot/internal/vmtarget"
)

// Run the real main/Execute path: calling Cobra directly would miss a signal
// handler installed around the root command, which caused R236-1.
func TestServicesCLISignalCancellationKeepsUnrelatedTermination(t *testing.T) {
	binary := buildPilotBinary(t)
	for _, signal := range []os.Signal{syscall.SIGTERM, os.Interrupt} {
		t.Run(signal.String(), func(t *testing.T) {
			for _, mode := range []string{"services-wait", "remote-exec"} {
				t.Run(mode, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					dir := t.TempDir()
					outputPath := filepath.Join(dir, "output")
					output, err := os.Create(outputPath)
					if err != nil {
						t.Fatal(err)
					}
					defer output.Close()
					var command *exec.Cmd
					var ready func() bool
					if mode == "services-wait" {
						lockPath := filepath.Join(dir, ".services-operation.lock")
						lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
						if err != nil {
							t.Fatal(err)
						}
						defer lock.Close()
						if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
							t.Fatal(err)
						}
						command = exec.CommandContext(ctx, binary, "--services-dir", dir, "services", "consumers")
						ready = func() bool {
							fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", command.Process.Pid))
							if err != nil {
								return false
							}
							for _, fd := range fds {
								path, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", command.Process.Pid, fd.Name()))
								if path == lockPath {
									return true
								}
							}
							return false
						}
					} else {
						stateDir := filepath.Join(dir, "state")
						store, err := statefile.New[vmtarget.Target](stateDir, "vm-targets.json", 1, "vmtarget")
						if err != nil {
							t.Fatal(err)
						}
						if err := store.Mutate(func([]vmtarget.Target) ([]vmtarget.Target, error) {
							return []vmtarget.Target{{Name: "signal-guest", Status: vmtarget.StatusRunning, IP: "192.0.2.1", SSHUser: "root", SSHPort: 22, KeyPath: filepath.Join(dir, "key")}}, nil
						}); err != nil {
							t.Fatal(err)
						}
						virsh, ssh := filepath.Join(dir, "virsh"), filepath.Join(dir, "ssh")
						if err := os.WriteFile(virsh, []byte("#!/bin/sh\necho running\n"), 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.WriteFile(ssh, []byte("#!/bin/sh\nprintf ready > \"$PILOT_SIGNAL_READY\"\nexec sleep 30\n"), 0700); err != nil {
							t.Fatal(err)
						}
						marker := filepath.Join(dir, "ssh-ready")
						command = exec.CommandContext(ctx, binary, "--data-dir", stateDir, "vm-target", "exec", "--name", "signal-guest", "--", "sleep", "30")
						command.Env = append(os.Environ(), "PILOT_VIRSH_BIN="+virsh, "PILOT_SSH_BIN="+ssh, "PILOT_SIGNAL_READY="+marker)
						ready = func() bool { _, err := os.Stat(marker); return err == nil }
					}
					command.Stdout, command.Stderr = output, output
					command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
					if err := command.Start(); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL) })
					done := make(chan error, 1)
					go func() { done <- command.Wait() }()
					deadline := time.After(5 * time.Second)
					for !ready() {
						select {
						case err := <-done:
							contents, _ := os.ReadFile(outputPath)
							t.Fatalf("CLI exited before the signal checkpoint: %v %s", err, contents)
						case <-deadline:
							t.Fatal("CLI did not reach the signal checkpoint")
						case <-time.After(10 * time.Millisecond):
						}
					}
					if err := command.Process.Signal(signal); err != nil {
						t.Fatal(err)
					}
					select {
					case err := <-done:
						if err == nil {
							t.Fatal("interrupted CLI reported success")
						}
						if mode == "services-wait" {
							contents, _ := os.ReadFile(outputPath)
							if !strings.Contains(string(contents), "context canceled") {
								t.Fatalf("services did not cancel lock wait: %v %s", err, contents)
							}
						} else {
							status, ok := command.ProcessState.Sys().(syscall.WaitStatus)
							if !ok || !status.Signaled() || status.Signal() != signal {
								t.Fatalf("unrelated CLI lost normal signal termination: %v", err)
							}
						}
					case <-time.After(2 * time.Second):
						t.Fatal("CLI swallowed its first termination signal")
					}
				})
			}
		})
	}
}
