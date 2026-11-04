package vmtarget

import (
	"context"
	"encoding/json"
	"github.com/kjelly/pilot/internal/services"
	"go.yaml.in/yaml/v3"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTopologyCapabilityUnionAndNodeRoundTrip(t *testing.T) {
	spec := TopologySpec{Services: "local", ServiceCapabilities: services.Requirements{services.APT}, Nodes: []TopologyNode{{Name: "apt"}, {Name: "oci", ServiceCapabilities: services.Requirements{services.OCI}}}}
	b, e := yaml.Marshal(spec)
	if e != nil {
		t.Fatal(e)
	}
	var restored TopologySpec
	if e = yaml.Unmarshal(b, &restored); e != nil {
		t.Fatal(e)
	}
	if e = restored.Validate(); e != nil {
		t.Fatal(e)
	}
	union, e := restored.ServiceRequirements()
	if e != nil || !reflect.DeepEqual(union, services.Requirements{services.APT, services.OCI}) {
		t.Fatalf("union=%v %v", union, e)
	}
	if !reflect.DeepEqual(restored.RequirementsFor(restored.Nodes[0]), services.Requirements{services.APT}) || !reflect.DeepEqual(restored.RequirementsFor(restored.Nodes[1]), services.Requirements{services.OCI}) {
		t.Fatal("node override lost")
	}
	restored.Nodes[0].ServiceCapabilities = services.Requirements{}
	if restored.Validate() == nil {
		t.Fatal("explicit empty node accepted")
	}
	restored.Nodes[0].ServiceCapabilities = services.Requirements{"bogus"}
	if restored.Validate() == nil {
		t.Fatal("unknown node capability accepted")
	}
	restored.ServiceCapabilities = nil
	restored.Nodes[0].ServiceCapabilities = nil
	restored.Nodes[1].ServiceCapabilities = nil
	union, e = restored.ServiceRequirements()
	if e != nil || len(union) != 3 {
		t.Fatal("legacy topology no longer requires all")
	}
}
func TestGuestNativeDataProbeMatchesContentAndDigest(t *testing.T) {
	if _, e := exec.LookPath("python3"); e != nil {
		t.Fatal("python3 needed for guest verifier harness")
	}
	script := filepath.Join(t.TempDir(), "probe.py")
	if e := os.WriteFile(script, []byte(serviceProbePython), 0600); e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"none", "corrupt", "auth-denied"} {
		t.Run(fault, func(t *testing.T) {
			descriptor := vmServiceDescriptors()[services.OCI]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/service/token" {
					_, _ = w.Write([]byte(`{"token":"public-token"}`))
					return
				}
				if fault == "auth-denied" || r.Header.Get("Authorization") != "Bearer public-token" {
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+"http://"+r.Host+`/service/token",service="harbor-registry",scope="repository:test:pull"`)
					w.WriteHeader(401)
					return
				}
				body := vmFixtureManifest
				if fault == "corrupt" {
					body = "wrong"
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			config, _ := json.Marshal(map[string]string{"capability": "oci", "endpoint": server.URL, "resource": descriptor.Resource, "sha256": descriptor.SHA256})
			out, e := exec.CommandContext(context.Background(), "python3", script, string(config)).CombinedOutput()
			if (e == nil) != (fault == "none") {
				t.Fatalf("guest proof fault=%s error=%v output=%s", fault, e, out)
			}
			if strings.Contains(string(out), "public-token") {
				t.Fatal("guest probe leaked bearer")
			}
		})
	}
}

func TestGuestDataProbeHasHardTotalDeadline(t *testing.T) {
	script := filepath.Join(t.TempDir(), "probe.py")
	if e := os.WriteFile(script, []byte(serviceProbePython), 0600); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(40 * time.Millisecond):
				if _, e := w.Write([]byte("x")); e != nil {
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
	}))
	defer server.Close()
	config, _ := json.Marshal(map[string]string{"capability": "rpm", "endpoint": server.URL, "resource": "/repodata/repomd.xml", "contains": "repomd"})
	start := time.Now()
	out, e := exec.Command("timeout", "0.3", "python3", script, string(config)).CombinedOutput()
	exit, ok := e.(*exec.ExitError)
	if !ok || exit.ExitCode() != 124 || time.Since(start) > time.Second {
		t.Fatalf("slow drip escaped hard deadline: %v %s", e, out)
	}
	bootstrap := testServiceBootstrap(t)
	cloud, e := bootstrap.RenderCloudInit()
	if e != nil || !strings.Contains(cloud, `["timeout","10","python3"`) {
		t.Fatalf("cloud-init omitted hard deadline: %v", e)
	}
}

func TestGuestRegistryTokenCriticalSchemaParity(t *testing.T) {
	script := filepath.Join(t.TempDir(), "probe.py")
	if e := os.WriteFile(script, []byte(serviceProbePython), 0600); e != nil {
		t.Fatal(e)
	}
	for _, test := range []struct {
		name, body string
		ready      bool
	}{
		{"token", `{"token":"synthetic"}`, true}, {"access", `{"access_token":"synthetic"}`, true}, {"null-fallback", `{"token":null,"access_token":"synthetic"}`, true}, {"empty-fallback", `{"token":"","access_token":"synthetic"}`, true}, {"zero-fallback", `{"token":0,"access_token":"synthetic"}`, false}, {"false-fallback", `{"token":false,"access_token":"synthetic"}`, false}, {"array-fallback", `{"token":[],"access_token":"synthetic"}`, false}, {"object-fallback", `{"token":{},"access_token":"synthetic"}`, false}, {"wrong-alternate", `{"token":"synthetic","access_token":0}`, false}, {"null", `null`, false}, {"array", `[]`, false}, {"empty-object", `{}`, false}, {"trailing", `{"token":"synthetic"} trailing`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			descriptor := vmServiceDescriptors()[services.OCI]
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/service/token" {
					_, _ = w.Write([]byte(test.body))
					return
				}
				if r.Header.Get("Authorization") == "Bearer synthetic" {
					_, _ = w.Write([]byte(vmFixtureManifest))
					return
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="`+"http://"+r.Host+`/service/token",service="harbor-registry",scope="repository:test:pull"`)
				w.WriteHeader(401)
			}))
			defer server.Close()
			config, _ := json.Marshal(map[string]string{"capability": "oci", "endpoint": server.URL, "resource": descriptor.Resource, "sha256": descriptor.SHA256})
			out, e := exec.Command("python3", script, string(config)).CombinedOutput()
			if (e == nil) != test.ready {
				t.Fatalf("guest token schema ready=%t want=%t: %v %s", e == nil, test.ready, e, out)
			}
		})
	}
}
