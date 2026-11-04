package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtureManifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{},"layers":[]}`

func fixtureDescriptors() map[Capability]DataProbe {
	sum := sha256.Sum256([]byte(fixtureManifest))
	digest := hex.EncodeToString(sum[:])
	return map[Capability]DataProbe{APT: {Resource: "http://upstream.invalid/dists/noble/InRelease", Contains: "PGP SIGNED MESSAGE"}, RPM: {Resource: "/pulp/content/test/repodata/repomd.xml", Contains: "<repomd"}, OCI: {Resource: "/v2/test/manifests/sha256:" + digest, SHA256: digest}}
}
func fixtureBody(path string) string {
	switch path {
	case "/acng-report.html":
		return "<html><title>Apt-Cacher NG Command And Control Page</title></html>"
	case "/pulp/api/v3/status/":
		return `{"database_connection":{"connected":true},"redis_connection":{"connected":false},"online_workers":[{"name":"test-worker"}],"online_content_apps":[{"name":"test-content"}]}`
	case "/api/v2.0/health":
		return `{"status":"healthy","components":[{"name":"core","status":"healthy"}]}`
	case "/api/v2.0/users/current":
		return `{"username":"admin","sysadmin_flag":true}`
	case "/pulp/api/v3/users/":
		return `{"results":[]}`
	}
	if strings.Contains(path, "InRelease") {
		return "-----BEGIN PGP SIGNED MESSAGE-----"
	}
	if strings.Contains(path, "repomd.xml") {
		return `<repomd xmlns="http://linux.duke.edu/metadata/repo"/>`
	}
	if strings.Contains(path, "/manifests/") {
		return fixtureManifest
	}
	return ""
}
func TestRequirementsContract(t *testing.T) {
	for _, r := range []Requirements{{}, {APT, APT}, {"unknown"}} {
		if _, e := NormalizeRequirements(r); e == nil {
			t.Fatalf("accepted invalid requirements: %#v", r)
		}
	}
	n, e := NormalizeRequirements(nil)
	if e != nil || !reflect.DeepEqual(n, Requirements{APT, RPM, OCI}) {
		t.Fatalf("legacy default=%v %v", n, e)
	}
	for _, raw := range []string{"", "apt,apt", "apt,nope"} {
		if _, e := ParseRequirements(raw); e == nil {
			t.Fatal(raw)
		}
	}
}
func TestCapabilitySelectionIndependentDataReadiness(t *testing.T) {
	m, _, runner := healthyLifecycleFixture(t)
	var mu sync.Mutex
	aptDown, harborAuthDenied, harborDataDenied := false, true, false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if (aptDown && (strings.Contains(r.URL.Path, "InRelease") || r.URL.Path == "/acng-report.html")) || (harborDataDenied && strings.Contains(r.URL.Path, "/manifests/")) {
			w.WriteHeader(503)
			return
		}
		if harborAuthDenied && r.URL.Path == "/api/v2.0/users/current" {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, fixtureBody(r.URL.Path))
	}))
	defer server.Close()
	if e := m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) {
		s[0].Running = false
		s[0].Client.AptProxyURL = server.URL
		s[0].Client.RPMBaseURL = server.URL
		s[0].Client.RegistryMirrorURL = server.URL
		s[0].Client.DataProbes = fixtureDescriptors()
		return s, nil
	}); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(m.store.Path())
	hashes := bundleHashes(t, m.root)
	if _, e := m.ClientConfigFor(context.Background(), Requirements{APT}); e != nil {
		t.Fatalf("APT-only blocked by unrelated management: %v", e)
	}
	if _, e := m.ClientConfigFor(context.Background(), Requirements{OCI}); e != nil {
		t.Fatalf("independently proven OCI data rejected by management401: %v", e)
	}
	status, e := m.Status(context.Background())
	if e != nil || status.Capabilities[OCI].ManagementAuth.Reason != "http-401" || status.Capabilities[OCI].Data.State != "ready" || status.Capabilities[OCI].ObservedAt.IsZero() {
		t.Fatalf("missing independent observation: %+v %v", status, e)
	}
	mu.Lock()
	aptDown = true
	harborAuthDenied = false
	mu.Unlock()
	if _, e := m.ClientConfigFor(context.Background(), Requirements{OCI}); e != nil {
		t.Fatalf("OCI blocked by unrelated APT: %v", e)
	}
	if _, e := m.ClientConfigFor(context.Background(), Requirements{APT}); e == nil {
		t.Fatal("required failed APT accepted")
	}
	if _, e := m.ClientConfig(context.Background()); e == nil {
		t.Fatal("legacy all default accepted failed APT")
	}
	mu.Lock()
	aptDown = false
	harborDataDenied = true
	mu.Unlock()
	if _, e := m.ClientConfigFor(context.Background(), Requirements{APT}); e != nil {
		t.Fatalf("APT blocked by unrelated OCI data failure: %v", e)
	}
	if _, e := m.ClientConfigFor(context.Background(), Requirements{OCI}); e == nil {
		t.Fatal("required failed OCI data accepted")
	}
	for _, call := range runner.calls {
		if !strings.Contains(call, " ps --format json") {
			t.Fatalf("observation executed lifecycle: %s", call)
		}
	}
	after, _ := os.ReadFile(m.store.Path())
	if string(before) != string(after) || !reflect.DeepEqual(hashes, bundleHashes(t, m.root)) {
		t.Fatal("readonly observations mutated state/bundle or executed lifecycle")
	}
}
func TestNativeHealthRejectsStatusOnlyAndInitializing(t *testing.T) {
	for _, c := range []Capability{APT, RPM, OCI} {
		for _, body := range []string{"", `{}`, `not-json`, `{"status":"unhealthy","components":[{"status":"healthy"}]}`, `{"database_connection":{"connected":true},"online_workers":[],"online_content_apps":[]}`} {
			if nativeHealth(c, []byte(body)) {
				t.Fatalf("%s accepted unhealthy/malformed: %s", c, body)
			}
		}
	}
	for c, path := range map[Capability]string{APT: "/acng-report.html", RPM: "/pulp/api/v3/status/", OCI: "/api/v2.0/health"} {
		if !nativeHealth(c, []byte(fixtureBody(path))) {
			t.Fatalf("%s rejected native schema", c)
		}
	}
}
func TestRequiredCapabilityRejectsHealthHTTPAndMissingDescriptor(t *testing.T) {
	m, _, _ := healthyLifecycleFixture(t)
	for _, code := range []int{200, 401, 403, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				body := fixtureBody(r.URL.Path)
				responseCode := 200
				if r.URL.Path == "/api/v2.0/health" {
					responseCode = code
					body = `{"status":"unhealthy"}`
				}
				return &http.Response{StatusCode: responseCode, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
			})}
			if _, e := m.ClientConfigFor(context.Background(), Requirements{OCI}); e == nil {
				t.Fatal("required OCI accepted bad native health")
			}
		})
	}
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixtureBody(r.URL.Path))), Header: make(http.Header)}, nil
	})}
	if e := m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) { delete(s[0].Client.DataProbes, OCI); return s, nil }); e != nil {
		t.Fatal(e)
	}
	if _, e := m.ClientConfigFor(context.Background(), Requirements{OCI}); e == nil || !strings.Contains(e.Error(), "missing-descriptor") {
		t.Fatalf("missing descriptor not fail closed: %v", e)
	}
}
func TestCapabilityProbeCancellationAndDeadline(t *testing.T) {
	m, _, _ := healthyLifecycleFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	_ = m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) {
		s[0].Client.AptProxyURL = server.URL
		s[0].Client.RPMBaseURL = server.URL
		s[0].Client.RegistryMirrorURL = server.URL
		return s, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, e := m.ClientConfigFor(ctx, Requirements{APT}); e == nil {
		t.Fatal("timeout accepted")
	}
	if time.Since(start) > time.Second {
		t.Fatal("caller cancellation ignored")
	}
}
func TestProfileDataProbeRoundTrip(t *testing.T) {
	p := BuiltInDevLite()
	p.DataProbes = fixtureDescriptors()
	if e := p.Validate(); e != nil {
		t.Fatal(e)
	}
	b, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	var out Profile
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(p.DataProbes, out.DataProbes) {
		t.Fatal("descriptor roundtrip lost")
	}
	for _, c := range []Capability{APT, RPM, OCI} {
		v := p.DataProbes[c]
		v.SHA256 = "bad"
		if v.Validate(c) == nil {
			t.Fatal("invalid digest accepted")
		}
	}
}

func TestOCIAnonymousBearerDataProofAndUnsafeChallenge(t *testing.T) {
	for _, fault := range []string{"none", "cross-origin", "wrong-scope", "malformed-token", "bad-digest", "denied"} {
		t.Run(fault, func(t *testing.T) {
			m, _, _ := healthyLifecycleFixture(t)
			descriptor := fixtureDescriptors()[OCI]
			var server *httptest.Server
			tokenReads := 0
			server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/service/token" {
					tokenReads++
					if r.Header.Get("Authorization") != "" {
						t.Error("data token request forwarded credential")
					}
					if fault == "malformed-token" {
						_, _ = io.WriteString(w, `{}`)
					} else {
						_, _ = io.WriteString(w, `{"token":"synthetic-public-pull-token"}`)
					}
					return
				}
				if r.URL.Path == descriptor.Resource {
					if fault == "denied" || r.Header.Get("Authorization") != "Bearer synthetic-public-pull-token" {
						realm := server.URL + "/service/token"
						scope := "repository:test:pull"
						if fault == "cross-origin" {
							realm = "http://other.invalid/service/token"
						}
						if fault == "wrong-scope" {
							scope = "repository:test:push,pull"
						}
						w.Header().Set("WWW-Authenticate", `Bearer realm="`+realm+`",service="harbor-registry",scope="`+scope+`"`)
						w.WriteHeader(401)
						return
					}
					if fault == "bad-digest" {
						_, _ = io.WriteString(w, "corrupt")
					} else {
						_, _ = io.WriteString(w, fixtureManifest)
					}
					return
				}
				_, _ = io.WriteString(w, fixtureBody(r.URL.Path))
			}))
			defer server.Close()
			_ = m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) {
				s[0].Client.RegistryMirrorURL = server.URL
				return s, nil
			})
			_, e := m.ClientConfigFor(context.Background(), Requirements{OCI})
			if (e == nil) != (fault == "none") {
				t.Fatalf("bearer proof result fault=%s err=%v", fault, e)
			}
			if (fault == "cross-origin" || fault == "wrong-scope") && tokenReads != 0 {
				t.Fatal("unsafe challenge caused token read")
			}
		})
	}
}

func TestInvalidUnrequiredDataDescriptorDoesNotBlockAPT(t *testing.T) {
	m, p, _ := healthyLifecycleFixture(t)
	p.DataProbes = map[Capability]DataProbe{OCI: {Resource: "not-valid"}}
	if e := p.Validate(); e != nil {
		t.Fatalf("unrelated descriptor blocked profile loading: %v", e)
	}
	_ = m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) {
		s[0].Client.DataProbes[OCI] = DataProbe{Resource: "invalid"}
		return s, nil
	})
	if _, e := m.ClientConfigFor(context.Background(), Requirements{APT}); e != nil {
		t.Fatalf("invalid unrequired OCI blocked APT: %v", e)
	}
	if _, e := m.ClientConfigFor(context.Background(), Requirements{OCI}); e == nil {
		t.Fatal("selected invalid descriptor accepted")
	}
}

func TestCapturedNativeHealthSchemas(t *testing.T) {
	for c, file := range map[Capability]string{APT: "acng-native-report.html", RPM: "pulp-native-status.json", OCI: "harbor-native-health.json"} {
		body, e := os.ReadFile("testdata/" + file)
		if e != nil {
			t.Fatal(e)
		}
		if !nativeHealth(c, body) {
			t.Fatalf("native %s response schema rejected", c)
		}
	}
}

func TestHealthyPulpManagementObservationUsesNativeUsersPath(t *testing.T) {
	m, _, _ := healthyLifecycleFixture(t)
	s, e := m.current()
	if e != nil {
		t.Fatal(e)
	}
	observed := m.observeCapabilities(context.Background(), s)
	if observed[RPM].ManagementAuth.State != "ready" {
		t.Fatalf("healthy Pulp management path not authenticated: %+v", observed[RPM].ManagementAuth)
	}
}
