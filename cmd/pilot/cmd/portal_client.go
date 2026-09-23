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

	"github.com/kjelly/pilot/internal/gatewayapi"
)

// portalClient is `pilot portal`'s only allowed dependency (spec.md §28):
// it talks to pilot-access-gateway over its Unix socket and nothing else
// — no roster, no inventory, and no Gateway service credential. The separate
// Portal credential session may hold one ephemeral end-user ccache for
// controlled SSH; it is never part of this API client.
type portalClient struct {
	httpClient *http.Client
}

func newPortalClient(socketPath string) *portalClient {
	return &portalClient{
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

func (c *portalClient) do(req *http.Request, out any) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("pilot-access-gateway unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read pilot-access-gateway response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var errResp gatewayapi.ErrorResponse
		_ = json.Unmarshal(body, &errResp)
		if errResp.Error != "" {
			return fmt.Errorf("%s (HTTP %d)", errResp.Error, resp.StatusCode)
		}
		return fmt.Errorf("pilot-access-gateway returned HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode pilot-access-gateway response: %w", err)
	}
	return nil
}

func (c *portalClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *portalClient) postJSON(ctx context.Context, path string, body, out any) error {
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
func (c *portalClient) Identity(ctx context.Context) (gatewayapi.IdentityResponse, error) {
	var resp gatewayapi.IdentityResponse
	err := c.get(ctx, "/v1/identity", &resp)
	return resp, err
}

// Access is GET /v1/access.
func (c *portalClient) Access(ctx context.Context) (gatewayapi.AccessResponse, error) {
	var resp gatewayapi.AccessResponse
	err := c.get(ctx, "/v1/access", &resp)
	return resp, err
}

// ConnectAuthorize is POST /v1/connect/authorize — a fresh, full
// re-authorize (spec.md §16), never derived from a cached My Hosts
// snapshot. Used by Phase 5's controlled-SSH Connect action.
// ConnectAuthorize asks the gateway for a fresh connect decision. sessionID
// is bound into the per-session ingest token when the target records; it
// never affects the HBAC/scope decision (per-host recording spec §15).
func (c *portalClient) ConnectAuthorize(ctx context.Context, target, sessionID string) (gatewayapi.ConnectAuthorizeResponse, error) {
	var resp gatewayapi.ConnectAuthorizeResponse
	err := c.postJSON(ctx, "/v1/connect/authorize", gatewayapi.ConnectAuthorizeRequest{Target: target, SessionID: sessionID}, &resp)
	return resp, err
}
