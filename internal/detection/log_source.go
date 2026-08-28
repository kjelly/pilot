package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// LokiTimeout is the default per-request timeout for Loki queries — the
// same budget as the Thanos metrics client (spec1.md §14 reuses Pilot's
// existing metrics-source conventions for the log source too).
const LokiTimeout = QueryTimeout

// LokiClient queries Loki's query_range API (spec1.md §14). It never
// pushes/writes — Detect Engine only ever reads.
type LokiClient struct {
	BaseURL    string
	Timeout    time.Duration
	HTTPClient *http.Client
}

// NewLokiClient builds a LokiClient with the given base URL and timeout.
func NewLokiClient(baseURL string, timeout time.Duration) *LokiClient {
	return &LokiClient{BaseURL: baseURL, Timeout: timeout}
}

func (c *LokiClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: c.Timeout}
}

// RawLogLine is one line as Loki returned it, before normalization —
// Stream carries whatever labels this stream had (e.g. pilot_host, site,
// level), which the caller uses to group lines per subject.
type RawLogLine struct {
	Timestamp time.Time
	Stream    map[string]string
	Line      string
}

type lokiQueryRangeResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// QueryRange calls GET <base_url>/loki/api/v1/query_range (spec1.md §14).
// start/end are the query window; limit<=0 means Loki's own default.
func (c *LokiClient) QueryRange(ctx context.Context, logql string, start, end time.Time, limit int) ([]RawLogLine, error) {
	q := url.Values{}
	q.Set("query", logql)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	reqURL := c.BaseURL + "/loki/api/v1/query_range?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build loki query_range request: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki query_range: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki query_range: http %d", resp.StatusCode)
	}

	var env lokiQueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, fmt.Errorf("decode loki query_range response: %w", err)
	}
	if env.Status != "success" {
		return nil, fmt.Errorf("loki query_range status=%q", env.Status)
	}

	var out []RawLogLine
	for _, stream := range env.Data.Result {
		for _, kv := range stream.Values {
			ns, err := strconv.ParseInt(kv[0], 10, 64)
			if err != nil {
				continue // one malformed timestamp skips that line, not the whole query
			}
			out = append(out, RawLogLine{
				Timestamp: time.Unix(0, ns).UTC(),
				Stream:    stream.Stream,
				Line:      kv[1],
			})
		}
	}
	return out, nil
}
