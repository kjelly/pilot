package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/anomalyco/pilot/internal/tools"
)

type Server struct {
	registry *tools.Registry
	stdout   io.Writer
}

func NewServer(registry *tools.Registry) *Server {
	originalStdout := os.Stdout
	// Redirect global os.Stdout to os.Stderr so standard prints don't corrupt JSON-RPC stdio stream
	os.Stdout = os.Stderr
	return &Server{
		registry: registry,
		stdout:   originalStdout,
	}
}

type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      any             `json:"id,omitempty"`
}

type Response struct {
	JSONRPC string `json:"jsonrpc"`
	Result  any    `json:"result,omitempty"`
	Error   *Error `json:"error,omitempty"`
	ID      any    `json:"id"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) Start(ctx context.Context) error {
	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			line, err := reader.ReadBytes('\n')
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			if len(line) == 0 {
				continue
			}
			go s.handleLine(ctx, line)
		}
	}
}

func (s *Server) handleLine(ctx context.Context, line []byte) {
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		s.sendError(nil, -32700, "Parse error: "+err.Error())
		return
	}

	if req.JSONRPC != "2.0" {
		s.sendError(req.ID, -32600, "Invalid Request: expected jsonrpc 2.0")
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		// No-op
	case "tools/list":
		s.handleToolsList(req)
	case "tools/call":
		s.handleToolsCall(ctx, req)
	default:
		if req.ID != nil {
			s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
		}
	}
}

func (s *Server) sendError(id any, code int, message string) {
	resp := Response{
		JSONRPC: "2.0",
		Error: &Error{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	s.writeResponse(resp)
}

func (s *Server) writeResponse(resp Response) {
	data, err := json.Marshal(resp)
	if err == nil {
		_, _ = s.stdout.Write(data)
		_, _ = s.stdout.Write([]byte("\n"))
	}
}

type InitializeResult struct {
	ProtocolVersion string            `json:"protocolVersion"`
	Capabilities    map[string]any    `json:"capabilities"`
	ServerInfo      map[string]string `json:"serverInfo"`
}

func (s *Server) handleInitialize(req Request) {
	res := InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities: map[string]any{
			"tools": map[string]any{},
		},
		ServerInfo: map[string]string{
			"name":    "pilot-mcp-server",
			"version": "1.0.0",
		},
	}
	s.writeResponse(Response{
		JSONRPC: "2.0",
		Result:  res,
		ID:      req.ID,
	})
}

type MCPTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type ToolsListResult struct {
	Tools []MCPTool `json:"tools"`
}

func (s *Server) handleToolsList(req Request) {
	var list []MCPTool
	if s.registry != nil {
		for _, name := range s.registry.List() {
			spec, ok := s.registry.Get(name)
			if !ok {
				continue
			}
			list = append(list, MCPTool{
				Name:        spec.Name,
				Description: spec.Description,
				InputSchema: spec.Parameters,
			})
		}
	}
	s.writeResponse(Response{
		JSONRPC: "2.0",
		Result:  ToolsListResult{Tools: list},
		ID:      req.ID,
	})
}

type ToolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type TextContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type ToolsCallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError"`
}

func (s *Server) handleToolsCall(ctx context.Context, req Request) {
	var params ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.sendError(req.ID, -32602, "Invalid params: "+err.Error())
		return
	}

	spec, ok := s.registry.Get(params.Name)
	if !ok {
		s.sendError(req.ID, -32602, fmt.Sprintf("Tool not found: %s", params.Name))
		return
	}

	// Run the tool's Interceptor first, matching the agent loop's contract:
	// a non-nil Result short-circuits the call; a non-nil error is a hard
	// failure; (nil, nil) means proceed. Without this, an interceptor-gated
	// tool would execute unguarded over MCP (the interceptor is the single
	// place per-tool policy lives). MCP is a "live" path — it sets no
	// dry-run context — so dry-run interceptors are correctly inert here.
	args := params.Arguments
	if spec.Interceptor != nil {
		interceptRes, ierr := spec.Interceptor(ctx, args)
		if ierr != nil {
			s.writeResponse(Response{
				JSONRPC: "2.0",
				Result: ToolsCallResult{
					Content: []TextContent{{Type: "text", Text: "Error: " + ierr.Error()}},
					IsError: true,
				},
				ID: req.ID,
			})
			return
		}
		if interceptRes != nil {
			s.writeResponse(Response{
				JSONRPC: "2.0",
				Result: ToolsCallResult{
					Content: []TextContent{{Type: "text", Text: interceptRes.Content}},
					IsError: interceptRes.IsError,
				},
				ID: req.ID,
			})
			return
		}
	}

	res, err := spec.Execute(ctx, args)
	if err != nil {
		s.writeResponse(Response{
			JSONRPC: "2.0",
			Result: ToolsCallResult{
				Content: []TextContent{{Type: "text", Text: "Error: " + err.Error()}},
				IsError: true,
			},
			ID: req.ID,
		})
		return
	}

	isErr := false
	content := ""
	if res != nil {
		isErr = res.IsError
		content = res.Content
	}

	s.writeResponse(Response{
		JSONRPC: "2.0",
		Result: ToolsCallResult{
			Content: []TextContent{{Type: "text", Text: content}},
			IsError: isErr,
		},
		ID: req.ID,
	})
}
