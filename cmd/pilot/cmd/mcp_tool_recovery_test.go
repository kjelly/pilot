//go:build linux || darwin || freebsd

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestAddRecoveredTool_PanicDoesNotKillOtherConcurrentCalls is the
// regression test for the bug fixed by mcp_tool_recovery.go: previously,
// a panic in one tool handler crashed the whole `pilot mcp serve`
// process, taking down every other concurrent (and future) call on the
// same session. This spawns a minimal server registered the same way
// runMCPServe wires real tools — through addRecoveredTool — with one
// tool that panics and one that doesn't, fires both concurrently, and
// asserts the panicking call gets a normal internal_error result while
// every concurrently-running "fine" call succeeds, and the session is
// still alive afterward.
const recoveryDemoChildEnv = "PILOT_MCP_RECOVERY_DEMO_CHILD"

func TestAddRecoveredTool_PanicDoesNotKillOtherConcurrentCalls(t *testing.T) {
	if os.Getenv(recoveryDemoChildEnv) == "1" {
		runRecoveryDemoMCPServer()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.Command(os.Args[0], "-test.run", "^TestAddRecoveredTool_PanicDoesNotKillOtherConcurrentCalls$")
	cmd.Env = append(os.Environ(), recoveryDemoChildEnv+"=1")

	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-recovery-demo", Version: "0.0.1"}, nil)
	transport := &mcp.CommandTransport{Command: cmd}
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	defer session.Close()

	const fineCallers = 10
	const itersPerCaller = 20
	var wg sync.WaitGroup
	var fineErrs, panicResultErrs int32

	wg.Add(1)
	go func() {
		defer wg.Done()
		res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo_panic", Arguments: map[string]any{}})
		if err != nil {
			t.Errorf("demo_panic call returned a transport-level error (want a normal IsError result instead): %v", err)
			return
		}
		if !res.IsError {
			t.Errorf("demo_panic result = %+v, want IsError=true", res)
			return
		}
		if len(res.Content) != 1 {
			atomic.AddInt32(&panicResultErrs, 1)
			return
		}
		tc, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			atomic.AddInt32(&panicResultErrs, 1)
			return
		}
		var toolErr mcpToolError
		if jsonErr := json.Unmarshal([]byte(tc.Text), &toolErr); jsonErr != nil {
			atomic.AddInt32(&panicResultErrs, 1)
			return
		}
		if toolErr.Code != mcpErrInternal || !strings.Contains(toolErr.Message, "demo_panic") {
			t.Errorf("panic error = %+v, want code=%s and message mentioning the tool name", toolErr, mcpErrInternal)
		}
	}()
	for i := 0; i < fineCallers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < itersPerCaller; j++ {
				if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "demo_fine", Arguments: map[string]any{}}); err != nil {
					atomic.AddInt32(&fineErrs, 1)
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if panicResultErrs > 0 {
		t.Fatalf("panic call's result shape was unexpected %d times", panicResultErrs)
	}
	if fineErrs > 0 {
		t.Fatalf("%d concurrently-running, non-panicking calls failed as collateral damage from the other call's panic — the fix did not stop the blast radius", fineErrs)
	}

	// The session must still be alive: a fresh call after the storm must
	// succeed, proving the process didn't crash.
	postCtx, postCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer postCancel()
	if _, err := session.CallTool(postCtx, &mcp.CallToolParams{Name: "demo_fine", Arguments: map[string]any{}}); err != nil {
		t.Fatalf("post-storm call failed — server did not survive the panic: %v", err)
	}
}

// runRecoveryDemoMCPServer is the child-process entry point: a minimal
// MCP server registering its tools through addRecoveredTool exactly like
// registerEditTools/registerDiagnoseTools do, with demo_fine (always
// succeeds) and demo_panic (panics unconditionally, simulating a bug in a
// real tool handler).
func runRecoveryDemoMCPServer() {
	server := mcp.NewServer(&mcp.Implementation{Name: "pilot-mcp-recovery-demo", Version: "test"}, nil)
	addRecoveredTool(server, &mcp.Tool{Name: "demo_fine", Description: "always succeeds"},
		func(ctx context.Context, req *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{}, map[string]any{"ok": true}, nil
		})
	addRecoveredTool(server, &mcp.Tool{Name: "demo_panic", Description: "panics unconditionally (simulated bug)"},
		func(ctx context.Context, req *mcp.CallToolRequest, in map[string]any) (*mcp.CallToolResult, any, error) {
			panic(fmt.Sprintf("simulated tool handler bug at %v", time.Now()))
		})
	_ = server.Run(context.Background(), &mcp.StdioTransport{})
}
