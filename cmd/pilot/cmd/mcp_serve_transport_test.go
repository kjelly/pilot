package cmd

import (
	"context"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// serveMCPToolNames runs serveMCP over an in-memory transport — the path
// `pilot mcp remote` uses instead of StdioTransport — and returns the
// tool names a client sees.
func serveMCPToolNames(t *testing.T, opts mcpServeOptions) map[string]bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	served := make(chan error, 1)
	go func() { served <- serveMCP(ctx, opts, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "serve-transport-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client.Connect() error = %v", err)
	}
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools() error = %v", err)
	}
	names := map[string]bool{}
	for _, tool := range result.Tools {
		names[tool.Name] = true
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session.Close() error = %v", err)
	}
	select {
	case <-served:
	case <-ctx.Done():
		t.Fatal("serveMCP did not return after the client closed the session")
	}
	return names
}

func TestServeMCPOverAnyTransportKeepsTheWriteGate(t *testing.T) {
	readOnly := serveMCPToolNames(t, mcpServeOptions{Dir: t.TempDir(), AuditDir: t.TempDir()})
	if !readOnly["pilot_edit_inspect"] || !readOnly["pilot_edit_plan"] {
		t.Fatalf("read-only tools missing: %v", readOnly)
	}
	if readOnly["pilot_edit_apply"] {
		t.Fatal("pilot_edit_apply registered without AllowWrite")
	}

	writable := serveMCPToolNames(t, mcpServeOptions{Dir: t.TempDir(), AuditDir: t.TempDir(), AllowWrite: true})
	if !writable["pilot_edit_apply"] {
		t.Fatalf("pilot_edit_apply missing with AllowWrite: %v", writable)
	}
}
