package detection

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLokiClient_QueryRange_HappyPath(t *testing.T) {
	now := time.Now()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/loki/api/v1/query_range" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if got := r.URL.Query().Get("query"); got != `{pilot_host="host-a"}` {
			t.Errorf("unexpected query param: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"status": "success",
			"data": {
				"resultType": "streams",
				"result": [
					{
						"stream": {"pilot_host": "host-a", "site": "site-1"},
						"values": [["%d", "kernel: process 123 killed by OOM"], ["%d", "heartbeat ok"]]
					}
				]
			}
		}`, now.UnixNano(), now.Add(time.Second).UnixNano())
	}))
	defer srv.Close()

	client := &LokiClient{BaseURL: srv.URL, Timeout: 5 * time.Second}
	lines, err := client.QueryRange(context.Background(), `{pilot_host="host-a"}`, now.Add(-time.Minute), now.Add(time.Minute), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d: %+v", len(lines), lines)
	}
	if lines[0].Stream["pilot_host"] != "host-a" || lines[0].Stream["site"] != "site-1" {
		t.Errorf("unexpected stream labels: %+v", lines[0].Stream)
	}
	if lines[0].Line != "kernel: process 123 killed by OOM" {
		t.Errorf("unexpected line: %q", lines[0].Line)
	}
}

func TestLokiClient_QueryRange_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := &LokiClient{BaseURL: srv.URL, Timeout: 5 * time.Second}
	_, err := client.QueryRange(context.Background(), `{pilot_host="host-a"}`, time.Now().Add(-time.Minute), time.Now(), 0)
	if err == nil {
		t.Fatal("expected an error for HTTP 500")
	}
}

func TestLokiClient_QueryRange_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"success","data":{"resultType":"streams","result":[]}}`)
	}))
	defer srv.Close()

	client := &LokiClient{BaseURL: srv.URL, Timeout: 5 * time.Second}
	lines, err := client.QueryRange(context.Background(), `{pilot_host="host-a"}`, time.Now().Add(-time.Minute), time.Now(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("expected 0 lines, got %d", len(lines))
	}
}

func TestLokiClient_QueryRange_MalformedTimestampSkipsOnlyThatLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
			"status": "success",
			"data": {
				"resultType": "streams",
				"result": [
					{"stream": {"pilot_host": "host-a"}, "values": [["not-a-number", "bad"], ["1000000000", "good"]]}
				]
			}
		}`)
	}))
	defer srv.Close()

	client := &LokiClient{BaseURL: srv.URL, Timeout: 5 * time.Second}
	lines, err := client.QueryRange(context.Background(), `{pilot_host="host-a"}`, time.Now().Add(-time.Minute), time.Now(), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0].Line != "good" {
		t.Fatalf("expected exactly the one well-formed line, got %+v", lines)
	}
}
