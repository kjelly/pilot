package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

func TestMcpServer_Initialize(t *testing.T) {
	s := &Server{}
	
	r, w, _ := os.Pipe()
	s.stdout = w

	req := Request{
		JSONRPC: "2.0",
		Method:  "initialize",
		ID:      123,
	}
	s.handleInitialize(req)
	w.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	r.Close()

	var resp Response
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal initialize response: %v", err)
	}

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got: %s", resp.JSONRPC)
	}
	
	resMap, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatal("expected result map")
	}
	if resMap["protocolVersion"] != "2024-11-05" {
		t.Errorf("expected protocol version 2024-11-05, got: %v", resMap["protocolVersion"])
	}
}

func TestMcpServer_ToolsList(t *testing.T) {
	s := &Server{}
	r, w, _ := os.Pipe()
	s.stdout = w

	req := Request{
		JSONRPC: "2.0",
		Method:  "tools/list",
		ID:      456,
	}
	s.handleToolsList(req)
	w.Close()

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	r.Close()

	var resp Response
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.ID.(float64) != 456 {
		t.Errorf("expected ID 456, got: %v", resp.ID)
	}
}
