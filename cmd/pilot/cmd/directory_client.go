package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/kjelly/pilot/internal/directoryapi"
)

// directoryClient is `pilot directory`'s only allowed dependency (spec.md
// docs/tmp/now/spec.md §13): it talks to pilot-access-directory over its
// Unix socket and nothing else — no roster, no inventory, no FreeIPA
// credential of its own. Mirrors portalClient's shape exactly.
type directoryClient struct {
	httpClient *http.Client
}

func newDirectoryClient(socketPath string) *directoryClient {
	return &directoryClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

func (c *directoryClient) do(req *http.Request, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pilot-access-directory unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read pilot-access-directory response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp directoryapi.ErrorResponse
		_ = json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", errResp.Error, resp.StatusCode)
		}
		return fmt.Errorf("pilot-access-directory returned HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode pilot-access-directory response: %w", err)
	}
	return nil
}

func (c *directoryClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *directoryClient) postJSON(ctx context.Context, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

// Identity is GET /v1/identity.
func (c *directoryClient) Identity(ctx context.Context) (directoryapi.IdentityResponse, error) {
	var resp directoryapi.IdentityResponse
	err := c.get(ctx, "/v1/identity", &resp)
	return resp, err
}

// Access is GET /v1/access.
func (c *directoryClient) Access(ctx context.Context) (directoryapi.AccessResponse, error) {
	var resp directoryapi.AccessResponse
	err := c.get(ctx, "/v1/access", &resp)
	return resp, err
}

// ConnectResolve is POST /v1/connect/resolve — a fresh, full re-resolve
// (spec.md D1), never derived from a cached My Hosts snapshot. Used by
// directory_ssh.go's Connect action.
func (c *directoryClient) ConnectResolve(ctx context.Context, target string) (directoryapi.ConnectResolveResponse, error) {
	var resp directoryapi.ConnectResolveResponse
	err := c.postJSON(ctx, "/v1/connect/resolve", directoryapi.ConnectResolveRequest{Target: target}, &resp)
	return resp, err
}
