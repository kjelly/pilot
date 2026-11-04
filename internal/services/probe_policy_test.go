package services

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func legacyPolicyFixture(t *testing.T) (*Manager, Profile, *sharedLifecycleRunner, *atomic.Int64) {
	t.Helper()
	legacy, discovery := t.TempDir(), t.TempDir()
	legacyFixture(t, legacy)
	runner := &sharedLifecycleRunner{}
	m, e := NewSharedManager(DiscoveryOptions{Directory: discovery, AdoptFrom: legacy}, runner)
	if e != nil {
		t.Fatal(e)
	}
	if e = m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) { s[0].Client.DataProbes = nil; return s, nil }); e != nil {
		t.Fatal(e)
	}
	requests := &atomic.Int64{}
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests.Add(1)
		code := 200
		body := fixtureBody(r.URL.Path)
		if r.URL.Path == "/api/v2.0/users/current" {
			code = 401
			body = ""
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	return m, BuiltInDevLite(), runner, requests
}

func TestProbePolicyDoesNotChangePhysicalFingerprint(t *testing.T) {
	p := BuiltInDevLite()
	before, e := p.Fingerprint()
	if e != nil {
		t.Fatal(e)
	}
	// Captured by executing immutable base e8b1512e, not recomputed by this test.
	const pre238BuiltInFingerprint = "467bcda0bffb942135744ab60b91d242abd3f150b1b10631fad7573e7464ca0d"
	if before != pre238BuiltInFingerprint {
		t.Fatalf("pre-238 physical fingerprint changed: %s", before)
	}
	p.DataProbes = fixtureDescriptors()
	after, e := p.Fingerprint()
	if e != nil || before != after {
		t.Fatalf("readonly probe policy changed physical identity: %s -> %s %v", before, after, e)
	}
	for _, change := range []func(*Profile){func(p *Profile) { p.Apt.Upstream += "/other" }, func(p *Profile) { p.Apt.Port++ }, func(p *Profile) { p.Harbor.HTTPPort++ }, func(p *Profile) { p.Storage.MaxBytes++ }, func(p *Profile) {
		p.RPM.Repos = append([]RPMRepository{}, p.RPM.Repos...)
		p.RPM.Repos[0].Upstream += "other"
	}} {
		different := p
		change(&different)
		fp, e := different.Fingerprint()
		if e != nil || fp == before {
			t.Fatalf("physical mutation lost fingerprint binding: %v", e)
		}
	}
}

func TestLegacyProfilePolicyConsumesWithoutBackfillOrManagementRepair(t *testing.T) {
	m, p, runner, _ := legacyPolicyFixture(t)
	if e := os.WriteFile(filepath.Join(m.root, "harbor/secrets/admin-password"), []byte("synthetic-wrong-management-association\n"), 0600); e != nil {
		t.Fatal(e)
	}
	consumer, e := NewSharedManagerContext(context.Background(), DiscoveryOptions{Directory: m.Directory(), ConsumptionOnly: true}, runner)
	if e != nil {
		t.Fatal(e)
	}
	consumer.client = m.client
	before, _ := os.ReadFile(m.store.Path())
	hashes := bundleHashes(t, m.root)
	for _, lookup := range []func() (ClientConfig, error){func() (ClientConfig, error) {
		return consumer.ClientConfigForProfile(context.Background(), p, net.ParseIP("192.168.122.1"), Requirements{APT})
	}, func() (ClientConfig, error) { return consumer.ClientConfigFor(context.Background(), Requirements{APT}) }} {
		client, e := lookup()
		if e != nil || client.DataProbes != nil {
			t.Fatalf("legacy APT required backfill or management repair: %v %+v", e, client.DataProbes)
		}
	}
	if _, e := consumer.ClientConfigForProfile(context.Background(), p, net.ParseIP("192.168.122.1"), Requirements{OCI}); e == nil || !strings.Contains(e.Error(), "missing-descriptor") {
		t.Fatalf("legacy OCI missing descriptor accepted: %v", e)
	}
	after, _ := os.ReadFile(m.store.Path())
	if !bytes.Equal(before, after) || !reflect.DeepEqual(hashes, bundleHashes(t, m.root)) || len(runner.calls) != 0 {
		t.Fatal("readonly legacy policy lookup changed state/cache or ran lifecycle")
	}
}

func TestExplicitPolicyRegistrationKeepsCanonicalClientAndVerifiesDigest(t *testing.T) {
	for _, fault := range []string{"none", "bad-digest", "missing-descriptor"} {
		t.Run(fault, func(t *testing.T) {
			m, p, _, _ := legacyPolicyFixture(t)
			p.DataProbes = fixtureDescriptors()
			if fault == "bad-digest" {
				d := p.DataProbes[OCI]
				d.SHA256 = strings.Repeat("a", 64)
				d.Resource = "/v2/test/manifests/sha256:" + d.SHA256
				p.DataProbes[OCI] = d
			}
			if fault == "missing-descriptor" {
				delete(p.DataProbes, OCI)
			}
			before, e := m.current()
			if e != nil {
				t.Fatal(e)
			}
			if fault != "none" {
				_, e := m.ClientConfigForProfile(context.Background(), p, net.ParseIP(before.BindIP), Requirements{OCI})
				if e == nil {
					t.Fatal("unproven OCI policy passed")
				}
				after, _ := m.current()
				if !reflect.DeepEqual(before, after) {
					t.Fatal("failed policy changed state")
				}
				return
			}
			client, e := m.ClientConfigForProfile(context.Background(), p, net.ParseIP(before.BindIP), Requirements{OCI})
			if e != nil {
				t.Fatalf("explicit readonly OCI descriptor requires stack rebuild: %v", e)
			}
			expected := client
			expected.DataProbes = p.ClientDataProbes()
			claim := Consumer{ID: "policy-domain", Name: "policy-vm", StateDirectory: t.TempDir(), DiscoveryDirectory: m.Directory(), InstanceID: client.InstanceID, Generation: client.Generation, Capabilities: "oci"}
			if e = m.RegisterConsumerWithPolicy(context.Background(), expected, claim, Requirements{OCI}, p, p.ClientDataProbes()); e != nil {
				t.Fatalf("readonly policy contaminated canonical client identity: %v", e)
			}
			after, e := m.current()
			if e != nil || !reflect.DeepEqual(before.Client, after.Client) || after.Client.DataProbes != nil || len(after.Consumers) != 1 {
				t.Fatalf("registration backfilled or changed canonical client: %v", e)
			}
		})
	}
}

func TestPhysicalProfileAndClientTamperingRejectedBeforeProbes(t *testing.T) {
	for _, fault := range []string{"wrong-profile", "upstream", "profile-endpoint", "bind", "state-endpoint", "generation", "owner", "ca", "caller-contract"} {
		t.Run(fault, func(t *testing.T) {
			m, p, _, requests := legacyPolicyFixture(t)
			state, e := m.current()
			if e != nil {
				t.Fatal(e)
			}
			expected := registeredClient(state)
			bind := net.ParseIP(state.BindIP)
			switch fault {
			case "wrong-profile":
				p.Name = "other"
			case "upstream":
				p.Apt.Upstream += "/other"
			case "profile-endpoint":
				p.Apt.Port++
			case "bind":
				bind = net.ParseIP("127.0.0.1")
				expected.HostIP = bind.String()
			case "state-endpoint":
				_ = m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) {
					s[0].Client.AptProxyURL = "http://foreign.invalid:3142"
					return s, nil
				})
			case "generation":
				_ = m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) { s[0].Generation++; return s, nil })
			case "owner":
				data, e := os.ReadFile(filepath.Join(m.root, ".pilot-services-owner.json"))
				if e != nil {
					t.Fatal(e)
				}
				data = bytes.ReplaceAll(data, []byte(state.InstanceID), []byte("foreign-owner"))
				if e = os.WriteFile(filepath.Join(m.root, ".pilot-services-owner.json"), data, 0600); e != nil {
					t.Fatal(e)
				}
			case "ca":
				if e = os.WriteFile(filepath.Join(m.root, "ca/ca.pem"), []byte("foreign-ca"), 0600); e != nil {
					t.Fatal(e)
				}
			case "caller-contract":
				expected.RegistryMirrorURL = "http://foreign.invalid:8081"
			}
			if fault != "caller-contract" {
				if _, e = m.ClientConfigForProfile(context.Background(), p, bind, Requirements{APT}); e == nil {
					t.Fatal("tampered physical lookup accepted")
				}
			}
			claim := Consumer{ID: "tamper-domain", Name: "tamper-vm", StateDirectory: t.TempDir(), DiscoveryDirectory: m.Directory(), InstanceID: state.InstanceID, Generation: state.Generation, Capabilities: "apt"}
			if e = m.RegisterConsumerWithPolicy(context.Background(), expected, claim, Requirements{APT}, p, p.ClientDataProbes()); e == nil {
				t.Fatal("tampered registration accepted")
			}
			if requests.Load() != 0 {
				t.Fatalf("identity mismatch probed endpoints before refusal: %d", requests.Load())
			}
			after, _ := m.current()
			if len(after.Consumers) != 0 {
				t.Fatal("identity mismatch registered a guest")
			}
		})
	}
}

func TestPartialFirstInitializationRetainsUsableAPTIdentity(t *testing.T) {
	runner := &sharedLifecycleRunner{}
	m, e := NewSharedManager(DiscoveryOptions{Directory: t.TempDir()}, runner)
	if e != nil {
		t.Fatal(e)
	}
	p := BuiltInDevLite()
	p.Harbor.InstallerURL = "https://installer.invalid/harbor.tgz"
	archive := harborTestArchive(t)
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := []byte(fixtureBody(r.URL.Path))
		code := 200
		if strings.HasSuffix(r.URL.Path, "harbor.tgz") {
			body = archive
		}
		if r.URL.Path == "/api/v2.0/users/current" {
			code = 401
			body = nil
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
	m.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
		return ClientConfig{}, errors.New("synthetic unrelated Harbor initialization failure")
	}
	if e = m.Up(context.Background(), p, net.ParseIP("192.168.122.1")); e == nil {
		t.Fatal("failed unrelated initialization was hidden")
	}
	state, e := m.current()
	if e != nil || state.Running || state.InstanceID == "" || state.Client.InstanceID != state.InstanceID || state.Client.Generation != state.Generation {
		t.Fatalf("partial initialization lost canonical client identity: %+v %v", state, e)
	}
	reopened, e := NewSharedManagerContext(context.Background(), DiscoveryOptions{Directory: m.Directory(), ConsumptionOnly: true}, runner)
	if e != nil {
		t.Fatalf("partial ready APT cannot be discovered: %v", e)
	}
	reopened.client = m.client
	calls := len(runner.calls)
	before, _ := os.ReadFile(m.store.Path())
	if _, e = reopened.ClientConfigForProfile(context.Background(), p, net.ParseIP(state.BindIP), Requirements{APT}); e != nil {
		t.Fatalf("partial APT blocked by unrelated Harbor initialization: %v", e)
	}
	after, _ := os.ReadFile(m.store.Path())
	if !bytes.Equal(before, after) || len(runner.calls) != calls {
		t.Fatal("partial APT consumption repaired or rewrote the stack")
	}
}

func TestLegacyPolicyFallbackRequiresExactBuiltInIdentity(t *testing.T) {
	for _, fault := range []string{"name", "fingerprint", "apt-endpoint", "host-ip", "registry-project"} {
		t.Run(fault, func(t *testing.T) {
			m, _, _, requests := legacyPolicyFixture(t)
			if e := m.store.Mutate(func(s []ServiceState) ([]ServiceState, error) {
				switch fault {
				case "name":
					s[0].Profile = "custom"
					s[0].Client.Profile = "custom"
				case "fingerprint":
					s[0].Fingerprint = "custom-fingerprint"
					s[0].Client.Fingerprint = "custom-fingerprint"
				case "apt-endpoint":
					s[0].Client.AptProxyURL = "http://foreign.invalid:3142"
				case "host-ip":
					s[0].Client.HostIP = "127.0.0.2"
				case "registry-project":
					s[0].Client.RegistryProjects["docker-hub"] = "http://foreign.invalid:8081/dockerhub"
				}
				return s, nil
			}); e != nil {
				t.Fatal(e)
			}
			if _, e := m.ClientConfigFor(context.Background(), Requirements{APT}); e == nil {
				t.Fatal("legacy policy guessed from name/OS instead of exact physical identity and endpoints")
			}
			state, e := m.current()
			if e != nil {
				t.Fatal(e)
			}
			claim := Consumer{ID: "legacy-tamper-domain", Name: "legacy-tamper-vm", StateDirectory: t.TempDir(), DiscoveryDirectory: m.Directory(), InstanceID: state.InstanceID, Generation: state.Generation, Capabilities: "apt"}
			if e = m.RegisterConsumerFor(context.Background(), registeredClient(state), claim, Requirements{APT}); e == nil {
				t.Fatal("legacy tampered registration accepted")
			}
			if requests.Load() != 0 {
				t.Fatal("unknown or tampered legacy profile probed before explicit physical identity validation")
			}
			after, e := m.current()
			if e != nil || len(after.Consumers) != 0 {
				t.Fatal("tampered legacy fallback registered a consumer")
			}
		})
	}
}
