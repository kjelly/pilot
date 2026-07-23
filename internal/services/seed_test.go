package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedServicesCreatesOnDemandRPMAndHarborProxy(t *testing.T) {
	root := t.TempDir()
	profile := BuiltInDevLite()
	if err := os.MkdirAll(filepath.Join(root, "harbor", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "harbor", "secrets", "admin-password"), []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pulp", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pulp", "secrets", "admin-password"), []byte("pulp-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gotRemote, gotRepository, gotDistribution, gotSync, gotRegistry, gotProject map[string]any
	var taskPolls int
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var body []byte
		if req.Body != nil {
			body, _ = io.ReadAll(req.Body)
		}
		var payload map[string]any
		if len(body) > 0 {
			_ = json.Unmarshal(body, &payload)
		}
		if strings.HasPrefix(req.URL.Path, "/pulp/api/") || strings.HasPrefix(req.URL.Path, "/api/v2.0/") {
			assertBasicAuth(t, req, "admin", map[bool]string{true: "admin-secret", false: "pulp-secret"}[strings.HasPrefix(req.URL.Path, "/api/v2.0/")])
		}
		status := http.StatusOK
		response := any(map[string]any{"results": []any{}})
		switch {
		case req.URL.Path == "/api/v2.0/registries" && req.Method == http.MethodGet:
		case req.URL.Path == "/api/v2.0/registries" && req.Method == http.MethodPost:
			gotRegistry = payload
			status = http.StatusCreated
			response = map[string]any{"id": float64(17)}
		case req.URL.Path == "/api/v2.0/projects" && req.Method == http.MethodGet:
		case req.URL.Path == "/api/v2.0/projects" && req.Method == http.MethodPost:
			gotProject = payload
			status = http.StatusCreated
		case req.URL.Path == "/pulp/api/v3/remotes/rpm/rpm/" && req.Method == http.MethodGet:
		case req.URL.Path == "/pulp/api/v3/remotes/rpm/rpm/" && req.Method == http.MethodPost:
			gotRemote = payload
			status = http.StatusCreated
			response = map[string]any{"pulp_href": "/pulp/api/v3/remotes/rpm/rpm/remote-1/"}
		case req.URL.Path == "/pulp/api/v3/repositories/rpm/rpm/" && req.Method == http.MethodGet:
		case req.URL.Path == "/pulp/api/v3/repositories/rpm/rpm/" && req.Method == http.MethodPost:
			gotRepository = payload
			status = http.StatusCreated
			response = map[string]any{"pulp_href": "/pulp/api/v3/repositories/rpm/rpm/repository-1/", "latest_version_href": nil}
		case req.URL.Path == "/pulp/api/v3/repositories/rpm/rpm/repository-1/" && req.Method == http.MethodGet:
			response = map[string]any{"pulp_href": req.URL.Path, "latest_version_href": nil}
		case req.URL.Path == "/pulp/api/v3/repositories/rpm/rpm/repository-1/sync/" && req.Method == http.MethodPost:
			gotSync = payload
			status = http.StatusAccepted
			response = map[string]any{"task": "/pulp/api/v3/tasks/task-1/"}
		case req.URL.Path == "/pulp/api/v3/tasks/task-1/" && req.Method == http.MethodGet:
			taskPolls++
			response = map[string]any{"state": "completed"}
		case req.URL.Path == "/pulp/api/v3/distributions/rpm/rpm/" && req.Method == http.MethodGet:
		case req.URL.Path == "/pulp/api/v3/distributions/rpm/rpm/" && req.Method == http.MethodPost:
			gotDistribution = payload
			status = http.StatusAccepted
			response = map[string]any{"pulp_href": "/pulp/api/v3/distributions/rpm/rpm/distribution-1/"}
		default:
			return nil, errors.New("unexpected request: " + req.Method + " " + req.URL.Path)
		}
		return jsonResponse(status, response), nil
	})}

	clientConfig, err := seedServices(context.Background(), profile, root, net.ParseIP("192.168.122.1"), client)
	if err != nil {
		t.Fatalf("seed services: %v", err)
	}
	if gotRemote["policy"] != "on_demand" {
		t.Fatalf("remote policy = %#v, want on_demand", gotRemote["policy"])
	}
	if gotRepository["remote"] != "/pulp/api/v3/remotes/rpm/rpm/remote-1/" {
		t.Fatalf("repository remote = %#v", gotRepository["remote"])
	}
	if gotSync["sync_policy"] != "mirror_content_only" {
		t.Fatalf("sync policy = %#v", gotSync["sync_policy"])
	}
	if gotDistribution["repository"] != "/pulp/api/v3/repositories/rpm/rpm/repository-1/" {
		t.Fatalf("distribution repository = %#v", gotDistribution["repository"])
	}
	if gotRegistry["type"] != "docker-hub" || gotRegistry["url"] != "https://registry-1.docker.io" {
		t.Fatalf("registry payload = %#v", gotRegistry)
	}
	if gotProject["project_name"] != "dockerhub" || gotProject["registry_id"] != float64(17) {
		t.Fatalf("project payload = %#v", gotProject)
	}
	if taskPolls == 0 || !strings.Contains(clientConfig.RPMBaseURL, "/dev-lite/almalinux-9-baseos") {
		t.Fatalf("seed result = %+v, task polls=%d", clientConfig, taskPolls)
	}
	auth := clientConfig // keep the contract assertion local to avoid logging secrets
	_ = auth
}

func TestSeedServicesIsIdempotentForExistingResources(t *testing.T) {
	root := t.TempDir()
	profile := BuiltInDevLite()
	if err := os.MkdirAll(filepath.Join(root, "harbor", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "harbor", "secrets", "admin-password"), []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "pulp", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pulp", "secrets", "admin-password"), []byte("pulp-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	posts := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodPost {
			posts++
			return nil, errors.New("unexpected mutating request on idempotent seed: " + req.URL.Path)
		}
		if strings.HasPrefix(req.URL.Path, "/pulp/api/") || strings.HasPrefix(req.URL.Path, "/api/v2.0/") {
			assertBasicAuth(t, req, "admin", map[bool]string{true: "admin-secret", false: "pulp-secret"}[strings.HasPrefix(req.URL.Path, "/api/v2.0/")])
		}
		var response any = map[string]any{"results": []any{}}
		switch req.URL.Path {
		case "/api/v2.0/registries":
			response = map[string]any{"results": []any{map[string]any{"id": float64(17), "name": "docker-hub", "type": "docker-hub", "url": "https://registry-1.docker.io"}}}
		case "/api/v2.0/projects":
			response = map[string]any{"results": []any{map[string]any{"project_name": "dockerhub", "registry_id": float64(17), "metadata": map[string]string{"public": "true"}}}}
		case "/pulp/api/v3/remotes/rpm/rpm/":
			response = map[string]any{"results": []any{map[string]any{"pulp_href": "/pulp/api/v3/remotes/rpm/rpm/remote-1/", "name": "dev-lite-almalinux-9-baseos", "url": "https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/", "policy": "on_demand"}}}
		case "/pulp/api/v3/repositories/rpm/rpm/":
			response = map[string]any{"results": []any{map[string]any{"pulp_href": "/pulp/api/v3/repositories/rpm/rpm/repository-1/", "name": "dev-lite-almalinux-9-baseos", "remote": "/pulp/api/v3/remotes/rpm/rpm/remote-1/", "latest_version_href": "/pulp/api/v3/repositories/rpm/rpm/repository-1/versions/1/"}}}
		case "/pulp/api/v3/distributions/rpm/rpm/":
			response = map[string]any{"results": []any{map[string]any{"pulp_href": "/pulp/api/v3/distributions/rpm/rpm/distribution-1/", "name": "dev-lite-almalinux-9-baseos", "base_path": "dev-lite/almalinux-9-baseos", "repository": "/pulp/api/v3/repositories/rpm/rpm/repository-1/"}}}
		default:
			return nil, errors.New("unexpected request: " + req.Method + " " + req.URL.Path)
		}
		return jsonResponse(http.StatusOK, response), nil
	})}
	if _, err := seedServices(context.Background(), profile, root, net.ParseIP("192.168.122.1"), client); err != nil {
		t.Fatal(err)
	}
	if posts != 0 {
		t.Fatalf("idempotent seed made %d POST requests", posts)
	}
}

func TestSeedServicesRequiresHarborAdminSecret(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "pulp", "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pulp", "secrets", "admin-password"), []byte("pulp-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, map[string]any{"results": []any{}}), nil
	})}
	if _, err := seedServices(context.Background(), BuiltInDevLite(), root, net.ParseIP("192.168.122.1"), client); err == nil || !strings.Contains(err.Error(), "admin password") {
		t.Fatalf("want missing admin password error, got %v", err)
	}
}

func TestPulpRepositoryEmptyTreatsVersionZeroAsEmpty(t *testing.T) {
	if !pulpRepositoryEmpty(pulpRepository{LatestVersionHref: "/pulp/api/v3/repositories/rpm/rpm/id/versions/0/"}) {
		t.Fatal("version 0 must trigger the initial metadata sync")
	}
	if pulpRepositoryEmpty(pulpRepository{LatestVersionHref: "/pulp/api/v3/repositories/rpm/rpm/id/versions/1/"}) {
		t.Fatal("a published version must not trigger another initial sync")
	}
}

func jsonResponse(status int, value any) *http.Response {
	b, _ := json.Marshal(value)
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(strings.NewReader(string(b))), Header: make(http.Header)}
}

func assertBasicAuth(t *testing.T, req *http.Request, user, password string) {
	t.Helper()
	gotUser, gotPassword, ok := req.BasicAuth()
	if !ok || gotUser != user || gotPassword != password {
		t.Fatalf("unexpected basic auth: %q %q %v", gotUser, gotPassword, ok)
	}
}
