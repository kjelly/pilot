package services

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestNativeHealthCriticalSchemaMatrix(t *testing.T) {
	tests := []struct {
		name  string
		c     Capability
		body  string
		ready bool
	}{
		{"apt-native", APT, fixtureBody("/acng-report.html"), true}, {"apt-case-whitespace", APT, "<HTML><TITLE>  APT-CACHER NG\n COMMAND AND CONTROL PAGE </TITLE></HTML>", true}, {"apt-generic-brand", APT, "<html>apt-cacher-ng</html>", false}, {"apt-unrelated-title", APT, "<html><title>Error</title>apt-cacher-ng</html>", false},
		{"harbor-native", OCI, fixtureBody("/api/v2.0/health"), true}, {"harbor-missing-names", OCI, `{"status":"healthy","components":[{"status":"healthy"}]}`, false}, {"harbor-partial", OCI, `{"status":"healthy","components":[{"name":"core","status":"healthy"}]}`, false}, {"harbor-duplicate", OCI, `{"status":"healthy","components":[{"name":"core","status":"healthy"},{"name":"database","status":"healthy"},{"name":"registry","status":"healthy"},{"name":"core","status":"healthy"}]}`, false}, {"harbor-null-component", OCI, `{"status":"healthy","components":[null]}`, false}, {"harbor-wrong-status-type", OCI, `{"status":true,"components":[]}`, false},
		{"pulp-native-optional-redis", RPM, fixtureBody("/pulp/api/v3/status/"), true}, {"pulp-null-workers", RPM, `{"database_connection":{"connected":true},"online_workers":[null],"online_content_apps":[{"name":"content"}]}`, false}, {"pulp-wrong-db-type", RPM, `{"database_connection":{"connected":"true"},"online_workers":[{"name":"worker"}],"online_content_apps":[{"name":"content"}]}`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := nativeHealth(test.c, []byte(test.body)); got != test.ready {
				t.Fatalf("native critical schema ready=%t want=%t", got, test.ready)
			}
		})
	}
	for _, c := range []Capability{RPM, OCI} {
		for _, body := range []string{`null`, `[]`, `{}`, `false`, `{"status":"healthy"} trailing`} {
			if nativeHealth(c, []byte(body)) {
				t.Fatalf("%s accepted malformed/absent critical fields: %s", c, body)
			}
		}
	}
}
func TestNativeManagementCriticalSchemaMatrix(t *testing.T) {
	tests := []struct {
		name  string
		c     Capability
		body  string
		ready bool
	}{
		{"pulp-empty-list", RPM, `{"results":[]}`, true}, {"pulp-users", RPM, `{"results":[{"username":"admin","id":1}]}`, true}, {"pulp-null", RPM, `{"results":null}`, false}, {"pulp-string", RPM, `{"results":"bad"}`, false}, {"pulp-object", RPM, `{"results":{}}`, false}, {"pulp-null-row", RPM, `{"results":[null]}`, false}, {"pulp-empty-row", RPM, `{"results":[{}]}`, false}, {"pulp-number-name", RPM, `{"results":[{"username":42}]}`, false}, {"pulp-trailing", RPM, `{"results":[]} trailing`, false},
		{"harbor-admin", OCI, `{"username":"admin","sysadmin_flag":true}`, true}, {"harbor-non-admin", OCI, `{"username":"user","sysadmin_flag":false}`, false}, {"harbor-string-bool", OCI, `{"username":"admin","sysadmin_flag":"true"}`, false}, {"harbor-null-name", OCI, `{"username":null,"sysadmin_flag":true}`, false}, {"harbor-trailing", OCI, `{"username":"admin","sysadmin_flag":true} trailing`, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validManagementIdentity(test.c, []byte(test.body)); got != test.ready {
				t.Fatalf("management critical schema ready=%t want=%t", got, test.ready)
			}
		})
	}
	for _, c := range []Capability{RPM, OCI} {
		for _, body := range []string{`null`, `[]`, `{}`, `false`} {
			if validManagementIdentity(c, []byte(body)) {
				t.Fatalf("%s accepted absent critical identity fields", c)
			}
		}
	}
}
func TestRegistryTokenCriticalSchemaMatrix(t *testing.T) {
	for _, test := range []struct {
		name, body string
		ready      bool
	}{
		{"token", `{"token":"synthetic"}`, true}, {"access", `{"access_token":"synthetic"}`, true}, {"null-fallback", `{"token":null,"access_token":"synthetic"}`, true}, {"empty-fallback", `{"token":"","access_token":"synthetic"}`, true}, {"zero-fallback", `{"token":0,"access_token":"synthetic"}`, false}, {"false-fallback", `{"token":false,"access_token":"synthetic"}`, false}, {"array-fallback", `{"token":[],"access_token":"synthetic"}`, false}, {"object-fallback", `{"token":{},"access_token":"synthetic"}`, false}, {"wrong-alternate", `{"token":"synthetic","access_token":0}`, false}, {"null", `null`, false}, {"array", `[]`, false}, {"empty-object", `{}`, false}, {"trailing", `{"token":"synthetic"} trailing`, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, _, _ := healthyLifecycleFixture(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/service/token" {
					_, _ = io.WriteString(w, test.body)
					return
				}
				if strings.Contains(r.URL.Path, "/manifests/") {
					if r.Header.Get("Authorization") == "Bearer synthetic" {
						_, _ = io.WriteString(w, fixtureManifest)
						return
					}
					w.Header().Set("WWW-Authenticate", `Bearer realm="`+"http://"+r.Host+`/service/token",service="harbor-registry",scope="repository:test:pull"`)
					w.WriteHeader(401)
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
			if (e == nil) != test.ready {
				t.Fatalf("token critical schema ready=%t want=%t: %v", e == nil, test.ready, e)
			}
		})
	}
}

func TestCapturedNativePulpManagementSchema(t *testing.T) {
	body, e := os.ReadFile("testdata/pulp-native-users.json")
	if e != nil {
		t.Fatal(e)
	}
	if !validManagementIdentity(RPM, body) {
		t.Fatal("captured native authenticated Pulp users schema rejected")
	}
}
