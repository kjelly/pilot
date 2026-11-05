package services

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// delayedUnselectedProbe makes the requested APT data proof succeed before the
// caller cancels during an unrelated OCI read. Requests never mutate the fixture.
func delayedUnselectedProbe(t *testing.T, m *Manager, cancel context.CancelFunc, archive []byte) {
	t.Helper()
	aptDone := make(chan struct{})
	ociStarted := make(chan struct{})
	var aptOnce, ociOnce sync.Once
	m.client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "harbor.tgz") {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(archive)), Header: make(http.Header)}, nil
		}
		if r.URL.Path == "/api/v2.0/health" {
			ociOnce.Do(func() { close(ociStarted) })
			<-r.Context().Done()
			// Model a response completing concurrently with cancellation.
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixtureBody(r.URL.Path))), Header: make(http.Header)}, nil
		}
		if strings.Contains(r.URL.Path, "InRelease") {
			aptOnce.Do(func() { close(aptDone) })
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(fixtureBody(r.URL.Path))), Header: make(http.Header)}, nil
	})}
	go func() {
		select {
		case <-aptDone:
		case <-time.After(3 * time.Second):
			return
		}
		select {
		case <-ociStarted:
			cancel()
		case <-time.After(3 * time.Second):
		}
	}()
}
func TestCanceledCapabilityObservationCannotPublishOrReturnSuccess(t *testing.T) {
	t.Run("up", func(t *testing.T) {
		m, e := NewManager(t.TempDir(), &fakeRunner{})
		if e != nil {
			t.Fatal(e)
		}
		p := BuiltInDevLite()
		p.Harbor.InstallerURL = "https://installer.invalid/harbor.tgz"
		bundle, e := RenderBundle(p, m.root, net.ParseIP("127.0.0.1"))
		if e != nil {
			t.Fatal(e)
		}
		bundle.Client.DataProbes = fixtureDescriptors()
		m.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
			return bundle.Client, nil
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		delayedUnselectedProbe(t, m, cancel, harborTestArchive(t))
		e = m.Up(ctx, p, net.ParseIP("127.0.0.1"))
		state, se := m.current()
		if se != nil {
			t.Fatal(se)
		}
		if !errors.Is(e, context.Canceled) || state.Running {
			t.Fatalf("canceled observation published running state or success: err=%v running=%t", e, state.Running)
		}
	})
	for _, operation := range []string{"client", "register", "status"} {
		t.Run(operation, func(t *testing.T) {
			m, _, _ := healthyLifecycleFixture(t)
			before, e := os.ReadFile(m.store.Path())
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			delayedUnselectedProbe(t, m, cancel, nil)
			var resultErr error
			switch operation {
			case "client":
				_, resultErr = m.ClientConfigFor(ctx, Requirements{APT})
			case "register":
				s, e := m.current()
				if e != nil {
					t.Fatal(e)
				}
				consumer := Consumer{ID: "canceled-domain", Name: "canceled-vm", StateDirectory: t.TempDir(), DiscoveryDirectory: m.Directory(), InstanceID: s.InstanceID, Generation: s.Generation, Capabilities: "apt"}
				resultErr = m.RegisterConsumerFor(ctx, s.Client, consumer, Requirements{APT})
			case "status":
				var status Status
				status, resultErr = m.Status(ctx)
				if status.Running || len(status.Capabilities) != 3 {
					t.Fatalf("canceled status did not return partial observations with running=false: %+v", status)
				}
			}
			if !errors.Is(resultErr, context.Canceled) {
				t.Fatalf("canceled %s returned success or lost cancellation: %v", operation, resultErr)
			}
			after, e := os.ReadFile(m.store.Path())
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("canceled %s published state", operation)
			}
		})
	}
}
