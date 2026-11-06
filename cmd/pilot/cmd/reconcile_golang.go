package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/freeiparpc"
	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/sshdial"
)

// The --engine values of pilot reconcile.
const (
	reconcileEngineAnsible = "ansible"
	reconcileEngineGolang  = identityreconcile.EngineName
)

// golangPreviewBlockedExitCode is the exit code of a Go preview that
// produced a plan holding blocked objects (spec §2.3); any other failure
// exits 1.
const golangPreviewBlockedExitCode = 3

var (
	reconcileEngineFlag  string
	reconcilePlanOutFlag string
)

// golangDialer is the SSH side of the Go engine: sshdial.Dialer, replaced
// in tests.
type golangDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	FQDN(ctx context.Context) (string, error)
	CA(ctx context.Context) (*x509.CertPool, error)
	// Close ends every ssh the dialer started and returns once each is
	// reaped; afterwards it starts none.
	Close()
}

var newGolangDialer = func(t sshdial.Target) golangDialer { return &sshdial.Dialer{Target: t} }

// newGolangIPAClient builds the JSON-RPC client of the preview: the
// constructor of the client, replaced in tests that wrap it. The preview
// asks it for a read-only client and nothing else.
var newGolangIPAClient = freeiparpc.New

// validateReconcileEngineFlags rejects every combination the Go engine
// does not support before anything is read (spec §2.1).
func validateReconcileEngineFlags(engine string, previewOnly, force bool, components []string, actions, planOut string) error {
	switch engine {
	case reconcileEngineAnsible:
		if planOut != "" {
			return fmt.Errorf("--plan-out 只能與 --engine %s 一起使用", reconcileEngineGolang) // gate: engine-plan-out
		}
		return nil
	case reconcileEngineGolang:
	default:
		return fmt.Errorf("--engine 只能是 %s 或 %s", reconcileEngineAnsible, reconcileEngineGolang) // gate: engine-unknown
	}
	switch {
	case actions != "":
		return fmt.Errorf("--engine %s 不能與 --actions 同時使用", reconcileEngineGolang) // gate: engine-actions
	case force || !previewOnly:
		return fmt.Errorf("--engine %s 目前只提供預覽：請加 --preview-only，不要加 --force", reconcileEngineGolang) // gate: engine-preview-only
	case len(components) != 1 || components[0] != "freeipa-identity":
		return fmt.Errorf("--engine %s 只處理 --component freeipa-identity 的使用者與群組", reconcileEngineGolang) // gate: engine-component
	}
	return nil
}

// golangLogoutTimeout bounds the session_logout the preview sends on the way
// out, which must run after Ctrl-C and after --timeout ended the preview. A
// variable so a test can shorten it.
var golangLogoutTimeout = 10 * time.Second

// golangPreviewError carries the preview's exit code.
type golangPreviewError struct {
	err  error
	code int
}

func (e *golangPreviewError) Error() string { return e.err.Error() }
func (e *golangPreviewError) ExitCode() int { return e.code }
func (e *golangPreviewError) Unwrap() error { return e.err }

// runReconcileGolangPreview plans the users and groups of the identity
// roster with the Go engine and writes nothing to FreeIPA (spec §2.2).
// Every failure exits 1 and only a produced plan with blocked objects exits
// 3 (spec §2.3): an error wrapping a child process's *exec.ExitError is an
// ExitCoder too, so returned as it is it would end pilot with that child's
// status, and a 3 from ansible would read as "blocked". errors.Is still
// reaches the inner sentinels through Unwrap.
func runReconcileGolangPreview(cmd *cobra.Command) error {
	err := golangPreview(cmd)
	var coded *golangPreviewError
	if err == nil || errors.As(err, &coded) {
		return err // gate: exit-code-passthrough
	}
	return &golangPreviewError{err: err, code: 1} // gate: exit-code-1
}

func golangPreview(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	planOut := ""
	if reconcilePlanOutFlag != "" {
		abs, err := filepath.Abs(expandHomeDir(reconcilePlanOutFlag))
		if err != nil {
			return err // gate: plan-out-abs
		}
		if _, err := os.Lstat(abs); err == nil {
			return fmt.Errorf("--plan-out %s 已存在；不覆寫", abs) // gate: plan-out-exists
		}
		// Fail now, not after the whole read: the file is written last.
		if info, err := os.Stat(filepath.Dir(abs)); err != nil || !info.IsDir() {
			return fmt.Errorf("--plan-out %s 的上層目錄 %s 不存在或不是目錄", abs, filepath.Dir(abs)) // gate: plan-out-dir
		}
		planOut = abs
	}
	timeout, err := parseDeployTimeout(reconcileTimeoutFlag)
	if err != nil {
		return err // gate: timeout-parse
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return err // gate: runtime-prepare
	}
	// Ctrl-C, SIGTERM and SIGHUP end the preview like --timeout does: every
	// child process is killed with what it started and the session logged
	// out (spec §2.5). The first signal cancels; the second, with the default
	// action restored, ends pilot at once. Only the Go preview: the Ansible
	// engine's handlers do not all observe their context (see
	// withServiceCommandSignals). The children run in their own session
	// (withIsolatedChildren), so the terminal's signals reach only pilot,
	// which is why SIGHUP is handled too, unless it was ignored at start
	// (nohup): Notify would turn that ignore off.
	signals := []os.Signal{os.Interrupt, syscall.SIGTERM}
	if !signal.Ignored(syscall.SIGHUP) {
		signals = append(signals, syscall.SIGHUP)
	}
	sigCtx, stop := signal.NotifyContext(withIsolatedChildren(withDeployAnsibleRuntime(cmd.Context(), runtime)), signals...)
	defer stop()
	context.AfterFunc(sigCtx, stop)
	ctx, cancel := context.WithTimeout(sigCtx, timeout)
	defer cancel()

	inv := workspacePath(reconcileDirFlag, reconcileInventoryFlag)
	if err := validateFileExists(inv); err != nil {
		return err // gate: inventory-missing
	}
	if err := inventoryCurrentWithHosts(inv); err != nil {
		return err // gate: inventory-vs-hosts
	}
	snapshot, err := loadDeployInventorySnapshot(ctx, inv)
	if err != nil {
		return err // gate: ansible-inventory
	}
	violations, err := validateDeploymentCompletenessSnapshot(inv, snapshot)
	if err != nil {
		return err // gate: completeness-error
	}
	if len(violations) > 0 {
		return formatCompletenessViolations(violations) // gate: completeness
	}
	hosts, err := resolvePatternHosts(ctx, inv, "freeipa-server", limitFlag)
	if err != nil {
		return err // gate: list-hosts
	}
	if len(hosts) != 1 {
		return fmt.Errorf("freeipa-identity 需要剛好一台 freeipa-server 主機(contract hostCardinality: exactly-one)，--limit %q 之後有 %d 台：%v", limitFlag, len(hosts), hosts) // gate: exactly-one-server
	}
	host := hosts[0]
	stage, err := golangPreviewStage(host, snapshot.Groups, stageFlag, stagingAttestedHoursFlag)
	if err != nil {
		return err // gate: stage-gate
	}
	hostVars := snapshot.HostVars[host]

	rosterPath, _ := hostVars["freeipa_roster_file"].(string)
	if strings.TrimSpace(rosterPath) == "" {
		return fmt.Errorf("%s 沒有設定 freeipa_roster_file", host) // gate: roster-file-unset
	}
	rosterPath = resolveRosterPath(filepath.Dir(inv), rosterPath)
	rosterData, err := readSecretVarsFile(ctx, rosterPath, runtime.Env)
	if err != nil {
		return fmt.Errorf("讀取 roster: %w", err) // gate: roster-read
	}
	var root map[string]any
	if err := yaml.Unmarshal(rosterData, &root); err != nil {
		return fmt.Errorf("解析 roster %s: %w", rosterPath, err) // gate: roster-yaml
	}
	desired, err := identityreconcile.FromRosterWithForms(root, rosterData)
	if err != nil {
		return fmt.Errorf("roster %s: %w", rosterPath, err) // gate: roster-adapter
	}
	declaredServer, err := rosterServer(root)
	if err != nil {
		return fmt.Errorf("roster %s: %w", rosterPath, err) // gate: roster-server-type
	}
	var vaultData []byte
	if varsFile := defaultVaultFile(inv); varsFile != "" {
		if vaultData, err = readSecretVarsFile(ctx, varsFile, runtime.Env); err != nil {
			return fmt.Errorf("讀取 vault vars 檔: %w", err) // gate: vault-vars-read
		}
	}
	password, err := inventory.ResolveIPAAdminPassword(vaultData, rosterData)
	if err != nil {
		return err // gate: admin-password
	}
	target, err := sshdial.TargetFromHostVars(host, hostVars)
	if err != nil {
		return fmt.Errorf("--engine %s 不支援這台主機的 SSH 連線設定：%w", reconcileEngineGolang, err) // gate: ssh-target
	}

	dialer := newGolangDialer(target)
	// The first deferred call here, so the last to run: after the logout
	// and CloseIdleConnections it ends what is still running, among it a
	// tunnel whose TLS handshake a net/http dial goroutine still waits on
	// once the logout gave up, and returns when each ssh is reaped: no ssh
	// is left when the preview returns (spec §2.5).
	defer dialer.Close()
	fqdn, err := dialer.FQDN(ctx)
	if err != nil {
		return fmt.Errorf("讀取 %s 的 FQDN: %w", host, err) // gate: fqdn-read
	}
	if declaredServer != "" && !strings.EqualFold(declaredServer, fqdn) {
		return fmt.Errorf("roster freeipa.server 是 %s，但 %s 的 hostname -f 是 %s", declaredServer, host, fqdn) // gate: roster-server
	}
	ca, err := dialer.CA(ctx)
	if err != nil {
		return fmt.Errorf("讀取 %s 的 IPA CA: %w", host, err) // gate: ca-read
	}
	client, err := newGolangIPAClient(freeiparpc.Config{FQDN: fqdn, CA: ca, DialContext: dialer.DialContext, ReadOnly: true})
	if err != nil {
		return err // gate: client-new
	}
	// After the logout: ends the idle tunnel with a TLS close_notify. It is not
	// what guarantees that no ssh -W is left: for a dial still in progress it
	// only cancels the dial's context and returns, and net/http ends that
	// connection later in a goroutine of its own. dialer.Close does (above).
	defer client.CloseIdleConnections()
	if err := client.Login(ctx, desired.Principal, password); err != nil {
		return fmt.Errorf("登入 FreeIPA: %w", err) // gate: login
	}
	defer func() {
		// Not ctx: the session must end after Ctrl-C and after --timeout too;
		// bounded, since the server may be what is not answering.
		lctx, done := context.WithTimeout(context.WithoutCancel(ctx), golangLogoutTimeout)
		defer done()
		_ = client.Logout(lctx)
	}()
	server, err := client.CheckServer(ctx)
	if err != nil {
		return err // gate: check-server
	}
	observedAt := time.Now()
	obs, err := identityreconcile.Observe(ctx, client, desired.Principal)
	if err != nil {
		return err // gate: observe
	}
	plan := identityreconcile.Build(desired, obs.Users, obs.Groups)
	stats := client.Stats()
	if stats.Writes != 0 {
		// Before anything is printed or written: a preview that sent a write
		// has no plan to show.
		return fmt.Errorf("內部錯誤：預覽送出了 %d 個寫入", stats.Writes) // gate: writes-guard
	}
	doc := identityreconcile.NewDocument(desired, obs, plan,
		identityreconcile.Target{
			InventoryHost: host, FQDN: fqdn, Destination: sshdial.DefaultDestination,
			SSH: identityreconcile.SSHTarget{Host: target.Host, Port: target.Port, User: target.User},
		},
		identityreconcile.Server{Version: server.ServerVersion, APIVersion: server.APIVersion},
		pilotRevision(), observedAt,
		identityreconcile.Stats{HTTPRequests: stats.HTTPRequests, Reads: stats.Reads, Writes: stats.Writes, Relogins: stats.Relogins, ReadRetries: stats.ReadRetries},
	)
	printGolangPreview(out, doc, stage)
	if planOut != "" {
		if err := writeGolangPlan(planOut, doc); err != nil {
			return err // gate: plan-write
		}
		fmt.Fprintf(out, "plan JSON：%s\n", planOut)
	}
	if doc.Result == identityreconcile.ResultBlocked {
		return &golangPreviewError{err: fmt.Errorf("--engine %s 預覽：%d 個物件被阻擋，見上方清單", reconcileEngineGolang, len(doc.Blocked)), code: golangPreviewBlockedExitCode} // gate: blocked-plan
	}
	return nil
}

// inventoryCurrentWithHosts fails when a sibling hosts.yml renders to a
// different inventory: the Ansible path regenerates it, a read-only
// preview must not write it.
func inventoryCurrentWithHosts(inv string) error {
	dir, err := filepath.Abs(filepath.Dir(inv))
	if err != nil {
		return err // gate: hosts-abs-dir
	}
	hostsPath := filepath.Join(dir, "hosts.yml")
	absInv, err := filepath.Abs(inv)
	if err != nil {
		return err // gate: hosts-abs-inventory
	}
	data, err := os.ReadFile(hostsPath)
	if hostsPath == absInv || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err // gate: hosts-read
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return err // gate: hosts-parse
	}
	rendered, err := generateInventoryFromHosts(hf)
	if err != nil {
		return err // gate: hosts-render
	}
	current, err := os.ReadFile(absInv)
	if err != nil {
		return err // gate: hosts-read-inventory
	}
	if string(current) != rendered {
		return fmt.Errorf("%s 與 hosts.yml 不一致；--engine %s 是唯讀預覽，不會重新產生 inventory：請先執行 pilot inventory generate", inv, reconcileEngineGolang) // gate: hosts-stale
	}
	return nil
}

// golangPreviewStage applies the playbook's stage gates (AGENTS.md §4.3):
// a host in the prod or staging group needs that stage, and a staging or
// prod stage needs a host in that group. --stage on the command line is
// the confirmation, as for the Ansible engine; prod needs an attestation.
func golangPreviewStage(host string, groups map[string][]string, stage, attestedHours string) (string, error) {
	if stage == "" {
		stage = "sandbox"
	}
	in := func(group string) bool { return slices.Contains(groups[group], host) }
	switch {
	case in("prod") && stage != "prod":
		return "", fmt.Errorf("%s 在 prod group，但 stage 是 %s：請加 --stage prod", host, stage) // gate: stage-prod-group
	case in("staging") && stage != "staging":
		return "", fmt.Errorf("%s 在 staging group，但 stage 是 %s：請加 --stage staging", host, stage) // gate: stage-staging-group
	case (stage == "staging" || stage == "prod") && !in(stage):
		return "", fmt.Errorf("stage %s 需要 %s 在 %s group", stage, host, stage) // gate: stage-needs-group
	}
	if stage == "prod" {
		hours, err := strconv.Atoi(attestedHours)
		if err != nil || hours < 0 || hours > 168 {
			return "", fmt.Errorf("--stage prod 需要 --staging-attested-within-hours 0–168") // gate: stage-attestation
		}
	}
	return stage, nil
}

// readSecretVarsFile reads a vars file, decrypting an ansible-vault file
// in memory with the secret ansible-playbook would find (spec §3). The
// decryption is bounded by ctx, the preview's --timeout.
func readSecretVarsFile(ctx context.Context, path string, env []string) ([]byte, error) {
	if isVaultEncrypted(path) {
		return inventory.ViewVaultFileAmbient(ctx, path, env)
	}
	return os.ReadFile(path)
}

// rosterServer is the roster's freeipa.server, which must name the host the
// preview reads (spec §4). The roster validator does not check its type, and
// a value of another type that was ignored would skip that check: it is
// refused instead. Absent and null are unset. (identityreconcile.FromRoster
// has already refused a freeipa that is not a mapping.)
func rosterServer(root map[string]any) (string, error) {
	fi, _ := root["freeipa"].(map[string]any)
	v, ok := fi["server"]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("freeipa.server 是 %T，不是字串", v) // gate: roster-server-value
	}
	return strings.TrimSpace(s), nil
}

func pilotRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	revision, modified := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		return "unknown"
	}
	if modified {
		revision += "+modified"
	}
	return revision
}

func printGolangPreview(out io.Writer, doc identityreconcile.Document, stage string) {
	fmt.Fprintf(out, "═══ pilot reconcile --engine %s — 唯讀預覽（不寫入 FreeIPA）═══\n", doc.Engine.Name)
	fmt.Fprintf(out, "範圍：%s　stage：%s　目標：%s（%s）　FreeIPA %s／API %s\n",
		doc.Scope, stage, doc.Target.InventoryHost, doc.Target.FQDN, doc.Server.Version, doc.Server.APIVersion)
	fmt.Fprintf(out, "讀到 %d 位使用者、%d 個群組\n", doc.Observation.Users, doc.Observation.Groups)
	counts := map[string]int{}
	for _, op := range doc.Operations {
		counts[op.Kind]++
	}
	if len(doc.Operations) == 0 {
		fmt.Fprintln(out, "計畫：沒有任何寫入")
	} else {
		fmt.Fprintf(out, "計畫：%d 個寫入\n", len(doc.Operations))
		for _, kind := range identityreconcile.Kinds {
			if counts[kind] > 0 {
				fmt.Fprintf(out, "  %-28s %d\n", kind, counts[kind])
			}
		}
		for _, op := range doc.Operations {
			if op.Destructive {
				fmt.Fprintf(out, "  ⚠️  %s %s（破壞性）\n", op.Kind, op.Object)
			}
		}
	}
	for _, b := range doc.Blocked {
		fmt.Fprintf(out, "🚫 阻擋 %s：%s — %s\n", b.Object, b.Reason, b.Detail)
	}
	for _, r := range doc.Reports.SSHKeys {
		fmt.Fprintf(out, "ℹ️  %s 的 SSH key 與 roster 不同（由 Ansible engine 處理）\n", r.User)
	}
	for _, r := range doc.Reports.ImplicitMembershipPrune {
		fmt.Fprintf(out, "ℹ️  %s 沒有宣告 %s 成員：authoritative 會撤銷這類的所有直接成員\n", r.Group, strings.Join(r.Kinds, "、"))
	}
	if len(doc.Reports.NotInScope) > 0 {
		sections := slices.Clone(doc.Reports.NotInScope)
		sort.Strings(sections)
		fmt.Fprintf(out, "ℹ️  不在 Go engine 範圍（由 Ansible engine 處理）：%s\n", strings.Join(sections, ", "))
	}
	fmt.Fprintf(out, "讀取：%d 個 HTTP 請求、%d 個讀取、%d 個寫入\n", doc.Stats.HTTPRequests, doc.Stats.Reads, doc.Stats.Writes)
}

func writeGolangPlan(path string, doc identityreconcile.Document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err // gate: plan-marshal
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("--plan-out: %w", err) // gate: plan-open
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err // gate: plan-write-bytes
	}
	return f.Close() // gate: plan-close
}
