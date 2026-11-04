package services

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func healthyLifecycleFixture(t *testing.T) (*Manager, Profile, *sharedLifecycleRunner) {
	t.Helper()
	legacy, discovery := t.TempDir(), t.TempDir()
	legacyFixture(t, legacy)
	runner := &sharedLifecycleRunner{}
	manager, err := NewSharedManager(DiscoveryOptions{Directory: discovery, AdoptFrom: legacy}, runner)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fixtureBody(r.URL.Path)))
	}))
	t.Cleanup(server.Close)
	if err := manager.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		states[0].BindIP = "127.0.0.1"
		states[0].Client.HostIP = "127.0.0.1"
		states[0].Client.AptProxyURL, states[0].Client.RPMBaseURL, states[0].Client.RegistryMirrorURL = server.URL, server.URL, server.URL
		states[0].Client.DataProbes = fixtureDescriptors()
		states[0].ConsumerTracking = true
		return states, nil
	}); err != nil {
		t.Fatal(err)
	}
	return manager, BuiltInDevLite(), runner
}

func TestSharedHealthyAttachDoesNotMutate(t *testing.T) {
	manager, profile, runner := healthyLifecycleFixture(t)
	before, err := os.ReadFile(manager.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	hashes := bundleHashes(t, manager.root)
	modtimes := map[string]time.Time{}
	if err := filepath.WalkDir(manager.root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err == nil {
			modtimes[path] = info.ModTime()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	manager.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
		t.Fatal("healthy attach seeded resources")
		return ClientConfig{}, nil
	}
	for range 2 {
		if err := manager.Up(context.Background(), profile, net.ParseIP("127.0.0.1")); err != nil {
			t.Fatal(err)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("healthy attach ran commands: %v", runner.calls)
	}
	after, _ := os.ReadFile(manager.store.Path())
	if string(before) != string(after) || !reflect.DeepEqual(hashes, bundleHashes(t, manager.root)) {
		t.Fatal("healthy attach rewrote state or bundle")
	}
	for path, before := range modtimes {
		info, err := os.Stat(path)
		if err != nil || !info.ModTime().Equal(before) {
			t.Fatalf("healthy attach changed timestamp: %s", path)
		}
	}
}

func TestSharedUnhealthyAttachRequiresExplicitRepair(t *testing.T) {
	manager, profile, runner := healthyLifecycleFixture(t)
	manager.client = &http.Client{Transport: failingLifecycleTransport{}}
	before, _ := os.ReadFile(manager.store.Path())
	err := manager.Up(context.Background(), profile, net.ParseIP("127.0.0.1"))
	if err == nil || !strings.Contains(err.Error(), "explicit services repair") {
		t.Fatalf("health failure did not refuse mutation: %v", err)
	}
	after, _ := os.ReadFile(manager.store.Path())
	if len(runner.calls) != 0 || string(before) != string(after) {
		t.Fatal("failed attach mutated services")
	}
}

type failingLifecycleTransport struct{}

func (failingLifecycleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("injected temporary health failure")
}

func TestDurableConsumersSurviveReopenAndGuardEveryMaintenancePath(t *testing.T) {
	manager, profile, runner := healthyLifecycleFixture(t)
	client, err := manager.ClientConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	consumer := Consumer{ID: "synthetic-domain-uuid", Name: "synthetic-vm", StateDirectory: t.TempDir(), DiscoveryDirectory: manager.Directory(), InstanceID: client.InstanceID, Generation: client.Generation}
	if err := manager.RegisterConsumer(context.Background(), client, consumer); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSharedManager(DiscoveryOptions{Directory: manager.Directory()}, runner)
	if err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]func() error{
		"down":  func() error { return reopened.Down(context.Background()) },
		"purge": func() error { return reopened.Purge(context.Background(), true) },
		"repair": func() error {
			return reopened.Repair(context.Background(), profile, net.ParseIP("127.0.0.1"), MaintenanceOptions{AcknowledgeLegacyClients: true})
		},
	} {
		if err := operation(); err == nil || !strings.Contains(err.Error(), "registered VM consumer") {
			t.Fatalf("%s bypassed consumer: %v", name, err)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatalf("protected maintenance ran commands: %v", runner.calls)
	}
	wrong := consumer
	wrong.Generation++
	if err := reopened.ReleaseConsumer(context.Background(), wrong); err == nil {
		t.Fatal("wrong generation released consumer")
	}
	if err := reopened.ForgetConsumer(context.Background(), consumer.ID, false); err == nil {
		t.Fatal("unconfirmed interruption released consumer")
	}
	if err := reopened.ForgetConsumer(context.Background(), "other", true); err == nil {
		t.Fatal("unknown consumer ID was accepted")
	}
	if err := reopened.ReleaseConsumer(context.Background(), consumer); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyMaintenanceRequiresExplicitInterruptionAcknowledgement(t *testing.T) {
	manager, _, runner := healthyLifecycleFixture(t)
	if err := manager.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		states[0].ConsumerTracking = false
		return states, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Down(context.Background()); err == nil || !strings.Contains(err.Error(), "acknowledge-legacy-clients") {
		t.Fatalf("legacy clients were not protected: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatal("legacy refusal mutated services")
	}
	if err := manager.DownWithOptions(context.Background(), MaintenanceOptions{AcknowledgeLegacyClients: true}); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleLockWaitAndConstructorCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	legacy, dir := t.TempDir(), t.TempDir()
	legacyFixture(t, legacy)
	child := discoveryProcess(ctx, dir, legacy, "hold")
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		t.Fatal("child did not acquire transaction")
	}
	waitCtx, stop := context.WithTimeout(ctx, 80*time.Millisecond)
	defer stop()
	if _, err := NewSharedManagerContext(waitCtx, DiscoveryOptions{Directory: dir}, &fakeRunner{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("constructor wait ignored cancellation: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	manager, err := NewSharedManagerContext(ctx, DiscoveryOptions{Directory: dir}, &fakeRunner{})
	if err != nil {
		t.Fatalf("crashed holder retained lock: %v", err)
	}
	lock, err := lockOperation(rootLockPath(manager.root))
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	for _, operation := range []func(context.Context) error{
		func(ctx context.Context) error {
			return manager.Up(ctx, BuiltInDevLite(), net.ParseIP("192.168.122.1"))
		},
		manager.Down,
		func(ctx context.Context) error { return manager.Purge(ctx, true) },
	} {
		waitCtx, stop := context.WithTimeout(ctx, 60*time.Millisecond)
		err := operation(waitCtx)
		stop()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("operation wait ignored cancellation: %v", err)
		}
	}
}

type processLifecycleRunner struct{ ledger string }

func (r processLifecycleRunner) Run(_ context.Context, dir, name string, args ...string) (CommandResult, error) {
	file, err := os.OpenFile(r.ledger, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return CommandResult{}, err
	}
	_, err = fmt.Fprintln(file, strings.Join(append([]string{name}, args...), " "))
	file.Close()
	if err != nil {
		return CommandResult{}, err
	}
	return (&sharedLifecycleRunner{}).Run(context.Background(), dir, name, args...)
}

func (r processLifecycleRunner) RunInput(_ context.Context, dir, input, _ string, _ ...string) (CommandResult, error) {
	return fixtureDatabaseResult(dir, input), nil
}

func TestLifecycleProcessHelper(t *testing.T) {
	mode := os.Getenv("PILOT_LIFECYCLE_HELPER")
	if mode == "" {
		return
	}
	if mode == "domain-hold" {
		unlock, err := LockConsumerDomain(context.Background(), os.Getenv("PILOT_TEST_DOMAIN_NAME"))
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		fmt.Println("locked")
		select {}
	}
	dir, ledger := os.Getenv("PILOT_LIFECYCLE_DIR"), os.Getenv("PILOT_LIFECYCLE_LEDGER")
	if mode == "register" {
		manager, err := NewSharedManager(DiscoveryOptions{Directory: dir}, &sharedLifecycleRunner{})
		if err != nil {
			t.Fatal(err)
		}
		client, err := manager.ClientConfig(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		consumer := Consumer{ID: "synthetic-persistent-domain", Name: "persistent-vm", StateDirectory: ledger, DiscoveryDirectory: manager.Directory(), InstanceID: client.InstanceID, Generation: client.Generation}
		if err := manager.RegisterConsumer(context.Background(), client, consumer); err != nil {
			t.Fatal(err)
		}
		return
	}
	m, err := NewManager(dir, processLifecycleRunner{ledger})
	if err != nil {
		t.Fatal(err)
	}
	m.seed = func(ctx context.Context, p Profile, root string, ip net.IP, _ *http.Client) (ClientConfig, error) {
		if err := os.WriteFile(ledger+".seed", []byte("entered"), 0600); err != nil {
			return ClientConfig{}, err
		}
		time.Sleep(200 * time.Millisecond)
		b, err := RenderBundle(p, root, ip)
		b.Client.AptProxyURL, b.Client.RPMBaseURL, b.Client.RegistryMirrorURL = os.Getenv("PILOT_LIFECYCLE_HEALTH"), os.Getenv("PILOT_LIFECYCLE_HEALTH"), os.Getenv("PILOT_LIFECYCLE_HEALTH")
		return b.Client, err
	}
	var operationErr error
	switch mode {
	case "down":
		operationErr = m.Down(context.Background())
	case "purge":
		operationErr = m.Purge(context.Background(), true)
	default:
		operationErr = m.Up(context.Background(), BuiltInDevLite(), net.ParseIP("127.0.0.1"))
	}
	if operationErr != nil {
		t.Fatal(operationErr)
	}
}

func TestConsumerDomainLockCoordinatesIndependentDirectories(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	name := fmt.Sprintf("synthetic-domain-lock-%d", os.Getpid())
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleProcessHelper$")
	command.Dir = t.TempDir()
	command.Env = append(os.Environ(), "PILOT_LIFECYCLE_HELPER=domain-hold", "PILOT_TEST_DOMAIN_NAME="+name, "PILOT_LIFECYCLE_DIR="+t.TempDir())
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		t.Fatal("domain holder did not acquire lock")
	}
	waitCtx, stop := context.WithTimeout(ctx, 60*time.Millisecond)
	defer stop()
	if unlock, err := LockConsumerDomain(waitCtx, name); !errors.Is(err, context.DeadlineExceeded) {
		if unlock != nil {
			unlock()
		}
		t.Fatalf("independent manager bypassed same-domain lock: %v", err)
	}
	other, err := LockConsumerDomain(ctx, name+"-other")
	if err != nil {
		t.Fatalf("unrelated domain blocked: %v", err)
	}
	other()
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	unlock, err := LockConsumerDomain(ctx, name)
	if err != nil {
		t.Fatalf("crashed provisioner retained domain lock: %v", err)
	}
	unlock()
}

func TestOperationLockRejectsSymlinkHardlinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "symlink")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}
	if file, err := lockOperation(link); err == nil {
		file.Close()
		t.Fatal("operation lock followed symlink")
	}
	hardlink := filepath.Join(dir, "hardlink")
	if err := os.Link(original, hardlink); err != nil {
		t.Fatal(err)
	}
	if file, err := lockOperation(hardlink); err == nil {
		file.Close()
		t.Fatal("operation lock accepted ambiguous hardlink")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if file, err := lockOperation(fifo); err == nil {
		file.Close()
		t.Fatal("operation lock accepted FIFO")
	}
}

func TestConsumerRegistrationSurvivesProvisionerProcessExit(t *testing.T) {
	manager, _, _ := healthyLifecycleFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleProcessHelper$")
	command.Env = append(os.Environ(), "PILOT_LIFECYCLE_HELPER=register", "PILOT_LIFECYCLE_DIR="+manager.Directory(), "PILOT_LIFECYCLE_LEDGER="+t.TempDir())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("registration process: %v %s", err, output)
	}
	consumers, err := manager.Consumers(ctx)
	if err != nil || len(consumers) != 1 {
		t.Fatalf("process exit lost durable consumer: %+v %v", consumers, err)
	}
	if err := manager.Down(ctx); err == nil || !strings.Contains(err.Error(), "registered VM consumer") {
		t.Fatalf("exited provisioner permitted cache teardown: %v", err)
	}
}

func TestConcurrentLifecycleUpVersusDownAndPurge(t *testing.T) {
	for _, mode := range []string{"down", "purge"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			dir, ledger := t.TempDir(), filepath.Join(t.TempDir(), "commands")
			installer := filepath.Join(DataRoot(dir), "harbor/installer")
			if err := os.MkdirAll(installer, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(installer, "install.sh"), []byte("fixture"), 0700); err != nil {
				t.Fatal(err)
			}
			command := func(operation string) *exec.Cmd {
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleProcessHelper$")
				cmd.Env = append(os.Environ(), "PILOT_LIFECYCLE_HELPER="+operation, "PILOT_LIFECYCLE_DIR="+dir, "PILOT_LIFECYCLE_LEDGER="+ledger)
				return cmd
			}
			first := command("up")
			if err := first.Start(); err != nil {
				t.Fatal(err)
			}
			for {
				if _, err := os.Stat(ledger + ".seed"); err == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("up did not reach seed")
				case <-time.After(10 * time.Millisecond):
				}
			}
			if output, err := command(mode).CombinedOutput(); err != nil {
				t.Fatalf("%s: %v %s", mode, err, output)
			}
			if err := first.Wait(); err != nil {
				t.Fatal(err)
			}
			manager, err := NewManager(dir, &fakeRunner{})
			if err != nil {
				t.Fatal(err)
			}
			state, err := manager.current()
			if err != nil || state.Running {
				t.Fatalf("up published over %s: %+v %v", mode, state, err)
			}
			if mode == "purge" {
				if _, err := os.Stat(manager.root); !os.IsNotExist(err) {
					t.Fatal("up restored purged cache")
				}
			}
		})
	}
}

func TestConcurrentLifecycleUpReusesPublishedResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dir, ledger := t.TempDir(), filepath.Join(t.TempDir(), "commands")
	installer := filepath.Join(DataRoot(dir), "harbor/installer")
	if err := os.MkdirAll(installer, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installer, "install.sh"), []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"username":"admin","sysadmin_flag":true}`))
	}))
	defer server.Close()
	command := func() *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLifecycleProcessHelper$")
		cmd.Env = append(os.Environ(), "PILOT_LIFECYCLE_HELPER=up", "PILOT_LIFECYCLE_DIR="+dir, "PILOT_LIFECYCLE_LEDGER="+ledger, "PILOT_LIFECYCLE_HEALTH="+server.URL)
		return cmd
	}
	first, second := command(), command()
	alias := filepath.Join(t.TempDir(), "same-discovery")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	second.Dir = t.TempDir()
	second.Env = append(second.Env, "PILOT_LIFECYCLE_DIR="+alias)
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(ledger + ".seed"); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("first up did not reach seed")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if output, err := second.CombinedOutput(); err != nil {
		t.Fatalf("waiting attach failed: %v %s", err, output)
	}
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	commands, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(commands), "./prepare"); got != 1 {
		t.Fatalf("concurrent up mutated stack %d times: %s", got, commands)
	}
}
