package cmd

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/services"
	"github.com/kjelly/pilot/internal/statefile"
)

func TestServicesCredentialImportThroughCobra(t *testing.T) {
	const sentinel = "SENTINEL-issue237-authorized-admin"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if r.URL.Path != "/api/v2.0/users/current" || !ok || user != "admin" || password != sentinel {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(sentinel))
			return
		}
		_, _ = w.Write([]byte(`{"username":"admin","sysadmin_flag":true}`))
	}))
	defer server.Close()
	legacy, discovery := t.TempDir(), t.TempDir()
	bundle, err := services.RenderBundle(services.BuiltInDevLite(), services.DataRoot(legacy), net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	bundle.Client.RegistryMirrorURL = server.URL
	store, err := statefile.New[services.ServiceState](legacy, "services.json", 1, "services")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Mutate(func([]services.ServiceState) ([]services.ServiceState, error) {
		return []services.ServiceState{{Profile: "dev-lite", Fingerprint: bundle.Client.Fingerprint, Root: bundle.Root, ComposePath: bundle.ComposePath, Client: bundle.Client, BindIP: "127.0.0.1", Running: true}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := services.NewSharedManager(services.DiscoveryOptions{Directory: discovery, AdoptFrom: legacy}, nil); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(bundle.Root, "harbor/secrets/admin-password")
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), sentinel+"-source")
	if err := os.WriteFile(source, []byte(sentinel+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_SERVICES_DIR", discovery)
	oldDir, oldAdopt, oldCfg := servicesDir, servicesAdoptFrom, cfgFile
	oldCtx, oldOut, oldErr := rootCmd.Context(), rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	servicesDir, servicesAdoptFrom, cfgFile = "", "", ""
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	t.Cleanup(func() {
		servicesDir, servicesAdoptFrom, cfgFile = oldDir, oldAdopt, oldCfg
		rootCmd.SetArgs(nil)
		rootCmd.SetContext(oldCtx)
		rootCmd.SetOut(oldOut)
		rootCmd.SetErr(oldErr)
		_ = servicesCredentialsImportCmd.Flags().Set("secret-file", "")
		_ = servicesCredentialsImportCmd.Flags().Set("kind", "harbor-admin")
	})
	execute := func(args ...string) error {
		stdout.Reset()
		stderr.Reset()
		rootCmd.SetArgs(args)
		return rootCmd.ExecuteContext(context.Background())
	}
	if err := execute("services", "status", "--json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "credential-unavailable") {
		t.Fatal("status did not report unavailable management credential")
	}
	if err := execute("services", "up"); err == nil {
		t.Fatal("management up accepted missing secret")
	}

	if err := execute("services", "credentials", "import", "--secret-file", source); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout.String()+stderr.String(), sentinel) {
		t.Fatal("import leaked source name or secret through Cobra output")
	}
	if !strings.Contains(stdout.String(), "validated and published") {
		t.Fatal("Cobra did not execute import")
	}
	got, _ := os.ReadFile(target)
	if string(got) != sentinel+"\n" {
		t.Fatal("Cobra did not publish validated credential")
	}
	if err := os.WriteFile(source, []byte("SENTINEL-invalid-admin\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err = execute("services", "credentials", "import", "--secret-file", source)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("wrong credential not rejected: %v", err)
	}
	if strings.Contains(stdout.String()+stderr.String()+err.Error(), sentinel) || strings.Contains(stdout.String()+stderr.String()+err.Error(), "SENTINEL-invalid") {
		t.Fatal("failed Cobra import leaked a credential")
	}
	got, _ = os.ReadFile(target)
	if string(got) != sentinel+"\n" {
		t.Fatal("failed Cobra import replaced valid association")
	}
}
