// deploy.go implements `pilot deploy`, an interactive promptui wizard
// that lets someone unfamiliar with Ansible run a real deployment
// without hand-assembling an `ansible-playbook ...` command line.
//
// It does not reimplement any deployment logic — it only walks the
// user through the same decisions DELIVERY.md documents (inventory
// path, preflight, full-site vs. single-component, stage gate,
// vault secrets, dry-run vs. apply) and then shells out to
// ansible-playbook via internal/ansible.Runner, streaming output live.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/manifoldco/promptui"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/anomalyco/pilot/internal/ansible"
)

var deployInventoryFlag string

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "互動式部署精靈 — 不需要熟悉 ansible-playbook 也能佈署",
	Long: `pilot deploy 用問答的方式引導你完成一次佈署：挑 inventory、挑要
套用的元件(或全站)、挑 stage(sandbox/staging/prod)、決定要不要先預覽
(--check --diff)，最後才真正執行 ansible-playbook，過程全程印出真實輸出。

這是 DELIVERY.md 手動組指令的替代路徑，行為完全一致(同一套 stage/confirm
gate、同一份 Playbook 對照表)——熟悉 Ansible 的人仍可以照 DELIVERY.md 手動執行。`,
	RunE: runDeploy,
}

func init() {
	deployCmd.Flags().StringVarP(&deployInventoryFlag, "inventory", "i", "inventory.yml", "預先填入的 inventory 路徑(精靈仍會再問一次，可直接按 Enter 採用)")
	rootCmd.AddCommand(deployCmd)
}

// errDeployAborted marks a wizard step the user explicitly cancelled
// (Ctrl-C, Ctrl-D, or a "no" on a safety confirmation). runDeploy
// treats it as a clean, silent exit rather than a real failure.
var errDeployAborted = errors.New("已取消")

func runDeploy(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("pilot deploy 需要互動式終端機(TTY)才能問問題；非互動場景請直接用 ansible-playbook（見 DELIVERY.md）")
	}

	runner := ansible.NewRunner()
	runner.StdoutWriter = out
	runner.StderrWriter = cmd.ErrOrStderr()

	fmt.Fprintln(out, "═══ pilot deploy — 互動式部署精靈 ═══")
	fmt.Fprintln(out, "每一步都可以直接按 Enter 採用預設值；Ctrl-C 隨時可以取消。")
	fmt.Fprintln(out)

	inv, err := promptText("Inventory 檔路徑", deployInventoryFlag, validateFileExists)
	if err != nil {
		return abortOrErr(err)
	}

	if promptConfirm("要不要先看一下這份 inventory 的 host/group 結構？(ansible-inventory --graph)", true) {
		previewInventoryGraph(cmd.Context(), out, inv)
		fmt.Fprintln(out)
	}

	ok, err := runPreflight(cmd.Context(), runner, out, inv)
	if err != nil {
		return abortOrErr(err)
	}
	if !ok {
		return nil
	}

	scopeIdx, err := promptSelectIndex("要佈署什麼？", []string{
		"全站部署(site.yml) — 一次套用 inventory 裡已經填好機器的所有元件",
		"單一元件 — 從清單挑一支 apply playbook",
	})
	if err != nil {
		return abortOrErr(err)
	}

	if scopeIdx == 0 {
		err = runSiteDeploy(cmd.Context(), runner, out, inv)
	} else {
		err = runSinglePlaybookDeploy(cmd.Context(), runner, out, inv)
	}
	return abortOrErr(err)
}

// abortOrErr swallows errDeployAborted (and errors wrapping it) so a
// user-initiated cancel exits 0 instead of printing a scary "Error:".
func abortOrErr(err error) error {
	if errors.Is(err, errDeployAborted) {
		return nil
	}
	return err
}

// ---- shared prompt helpers -------------------------------------------------

// maxSelectSize caps how many rows promptui.Select tries to show at
// once. promptui's own doc comment on Size is "the number of items
// that should appear on the select before scrolling is necessary" —
// passing len(items) (the previous behavior here) means "never
// scroll", which pushes any menu longer than the terminal's height
// off-screen with no way to reach the rest. Capping it lets promptui's
// built-in scroll indicators (▲/▼) take over once a menu grows past
// this many rows.
const maxSelectSize = 12

func promptSelectIndex(label string, items []string) (int, error) {
	size := len(items)
	if size > maxSelectSize {
		size = maxSelectSize
	}
	p := promptui.Select{Label: label, Items: items, Size: size}
	idx, _, err := p.Run()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errDeployAborted, err)
	}
	return idx, nil
}

func promptText(label, def string, validate func(string) error) (string, error) {
	p := promptui.Prompt{Label: label, Default: def, Validate: validate, AllowEdit: true}
	v, err := p.Run()
	if err != nil {
		return "", fmt.Errorf("%w: %v", errDeployAborted, err)
	}
	return v, nil
}

// promptConfirm asks a yes/no question and returns defaultYes when the
// user just presses Enter. promptui's IsConfirm only distinguishes
// "typed y" (nil error) from everything else, so we special-case an
// empty answer ourselves instead of relying on its default handling.
func promptConfirm(question string, defaultYes bool) bool {
	suffix := " [Y/n]"
	if !defaultYes {
		suffix = " [y/N]"
	}
	p := promptui.Prompt{Label: question + suffix}
	ans, err := p.Run()
	if err != nil {
		// Ctrl-C/Ctrl-D: treat as "no" (safest default for a
		// question the user didn't actually answer).
		return false
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans == "" {
		return defaultYes
	}
	return ans == "y" || ans == "yes"
}

func validateFileExists(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("不能留空")
	}
	if _, err := os.Stat(p); err != nil {
		return fmt.Errorf("找不到檔案: %s", p)
	}
	return nil
}

func validateOptionalKV(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, tok := range strings.Fields(s) {
		if !strings.Contains(tok, "=") {
			return fmt.Errorf("%q 不是 key=value 格式", tok)
		}
	}
	return nil
}

func validateHoursWithinWeek(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fmt.Errorf("請輸入數字(小時)")
	}
	if n < 0 || n > 168 {
		return fmt.Errorf("必須是 0-168 之間(超過 7 天視為沒有效的 staging 驗證)")
	}
	return nil
}

// ---- inventory preview / preflight -----------------------------------------

func previewInventoryGraph(ctx context.Context, out io.Writer, inv string) {
	r := ansible.NewRunner()
	r.Binary = "ansible-inventory"
	r.StdoutWriter = out
	res, err := r.Run(ctx, "-i", inv, "--graph")
	if err != nil {
		fmt.Fprintf(out, "(無法執行 ansible-inventory：%v)\n", err)
		return
	}
	if res.ExitCode != 0 {
		fmt.Fprintf(out, "(ansible-inventory 結束碼 %d，上面輸出可能有錯誤訊息)\n", res.ExitCode)
	}
}

// runPreflight offers to run playbooks/preflight.yml before anything
// else is applied. Returns ok=false when the user chose to stop
// instead of continuing past a failed (or skipped) preflight.
func runPreflight(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string) (bool, error) {
	idx, err := promptSelectIndex("要先跑前置檢查(preflight)嗎？", []string{
		"完整前置檢查(含 SSH 連線測試)",
		"只做靜態檢查(機器還沒開機/還連不上時用；不連線)",
		"跳過前置檢查",
	})
	if err != nil {
		return false, err
	}
	if idx == 2 {
		return true, nil
	}
	fmt.Fprintln(out, "── 執行 playbooks/preflight.yml ──")
	args := []string{"playbooks/preflight.yml", "-i", inv}
	if idx == 1 {
		args = append(args, "--tags", "static")
	}
	res, err := runner.Run(ctx, args...)
	if err != nil {
		return false, fmt.Errorf("執行 preflight 失敗: %w", err)
	}
	fmt.Fprintln(out)
	if res.ExitCode == 0 {
		fmt.Fprintln(out, "✅ 前置檢查通過")
		return true, nil
	}
	fmt.Fprintf(out, "❌ 前置檢查沒有全過(結束碼 %d)\n", res.ExitCode)
	return promptConfirm("仍要繼續佈署嗎？(不建議 — 上面的錯誤通常代表 inventory 填錯或連不上機器)", false), nil
}

// ---- stage gate -------------------------------------------------------------

// stageDecision is the outcome of asking "sandbox / staging / prod",
// already carrying whatever confirm_* / attestation vars that choice
// requires. The caller still has to attach the stage value itself
// under the right variable name (stage vs. patch_stage for
// os-patch-sla, or both when driving the aggregate site.yml).
type stageDecision struct {
	Stage       string
	ConfirmVars []string // e.g. []string{"confirm_staging=true"}
}

func promptStageDecision(out io.Writer, context string) (stageDecision, error) {
	idx, err := promptSelectIndex(fmt.Sprintf("[%s] 要套用到哪個 stage？", context), []string{
		"sandbox（預設；沙盒/測試機，不需要額外確認）",
		"staging（測試環境，需要額外確認）",
		"prod（正式環境，需要額外確認 + 近 7 天內的 staging 驗證證明）",
	})
	if err != nil {
		return stageDecision{}, err
	}
	switch idx {
	case 0:
		return stageDecision{Stage: "sandbox"}, nil
	case 1:
		fmt.Fprintln(out, "⚠️  即將對已歸類進 staging 的機器套用真正的變更。")
		if !promptConfirm("確定要繼續嗎？", false) {
			return stageDecision{}, errDeployAborted
		}
		return stageDecision{Stage: "staging", ConfirmVars: []string{"confirm_staging=true"}}, nil
	case 2:
		fmt.Fprintln(out, "⚠️  即將對已歸類進 prod 的機器套用真正的變更。")
		hours, err := promptText("上次 staging 驗證距今幾小時？(0-168，即 7 天內)", "24", validateHoursWithinWeek)
		if err != nil {
			return stageDecision{}, err
		}
		_, err = promptText(`為避免手滑，請輸入大寫 "PROD" 以確認要套用到正式環境`, "", func(s string) error {
			if s != "PROD" {
				return fmt.Errorf(`必須完全輸入 "PROD"`)
			}
			return nil
		})
		if err != nil {
			return stageDecision{}, err
		}
		return stageDecision{
			Stage:       "prod",
			ConfirmVars: []string{"confirm_prod=true", "staging_attested_within_hours=" + hours},
		}, nil
	}
	return stageDecision{}, fmt.Errorf("unreachable")
}

// ---- vault / secrets --------------------------------------------------------

type vaultInput struct {
	ExtraVarsFile     string // -e @<file>
	VaultPasswordFile string // --vault-password-file <file>
	AskVaultPass      bool   // --ask-vault-pass (needs stdin wired to the terminal)
}

func promptVault(out io.Writer, hint string) (vaultInput, error) {
	label := "這次佈署需要密碼變數嗎？(例如 FreeIPA/Keycloak 的管理密碼，走 ansible-vault 加密檔)"
	if hint != "" {
		fmt.Fprintf(out, "ℹ️  這個元件通常需要：%s\n", hint)
	}
	idx, err := promptSelectIndex(label, []string{
		"不需要",
		"需要 — 我有一份 ansible-vault 加密的 vars 檔",
	})
	if err != nil {
		return vaultInput{}, err
	}
	if idx == 0 {
		return vaultInput{}, nil
	}
	varsFile, err := promptText("vars 檔路徑(ansible-vault 加密過的 yaml)", "", validateFileExists)
	if err != nil {
		return vaultInput{}, err
	}
	decryptIdx, err := promptSelectIndex("怎麼解密？", []string{
		"用密碼檔(--vault-password-file)",
		"執行時手動輸入密碼(--ask-vault-pass)",
	})
	if err != nil {
		return vaultInput{}, err
	}
	if decryptIdx == 1 {
		return vaultInput{ExtraVarsFile: varsFile, AskVaultPass: true}, nil
	}
	passFile, err := promptText("vault 密碼檔路徑", "", validateFileExists)
	if err != nil {
		return vaultInput{}, err
	}
	return vaultInput{ExtraVarsFile: varsFile, VaultPasswordFile: passFile}, nil
}

func (v vaultInput) args() []string {
	var out []string
	if v.ExtraVarsFile != "" {
		out = append(out, "-e", "@"+v.ExtraVarsFile)
	}
	if v.VaultPasswordFile != "" {
		out = append(out, "--vault-password-file", v.VaultPasswordFile)
	}
	if v.AskVaultPass {
		out = append(out, "--ask-vault-pass")
	}
	return out
}

// ---- execution: dry-run first, then optionally apply -----------------------

// executeDeployment builds the final ansible-playbook argv from the
// choices gathered by the caller, offers a --check --diff preview
// first, and — only if that preview succeeds and the user asks for it
// — re-runs the same command for real. Returns an error only for
// infrastructure failures or user cancellation; a failed ansible run
// is reported to the user but does not make pilot deploy itself error
// (the streamed output already told them what went wrong).
func executeDeployment(ctx context.Context, runner *ansible.Runner, out io.Writer, playbook, inv, limit, tags string, extraVars []string, vault vaultInput) error {
	baseArgs := []string{playbook, "-i", inv}
	if limit != "" {
		baseArgs = append(baseArgs, "--limit", limit)
	}
	if tags != "" {
		baseArgs = append(baseArgs, "--tags", tags)
	}
	for _, v := range extraVars {
		baseArgs = append(baseArgs, "-e", v)
	}
	baseArgs = append(baseArgs, vault.args()...)

	if vault.AskVaultPass {
		runner.Stdin = os.Stdin
	}

	dryRunFirst := promptConfirm("要先預覽(--check --diff)再決定要不要真的套用嗎？", true)

	runOnce := func(check bool) (*ansible.Result, error) {
		mode := "套用"
		args := baseArgs
		if check {
			mode = "預覽(--check --diff)"
			args = append([]string{"--check", "--diff"}, baseArgs...)
		}
		fmt.Fprintf(out, "\n▶ %s：ansible-playbook %s\n\n", mode, strings.Join(args, " "))
		if !promptConfirm("確定要執行以上指令嗎？", true) {
			return nil, errDeployAborted
		}
		return runner.Run(ctx, args...)
	}

	if dryRunFirst {
		res, err := runOnce(true)
		if err != nil {
			return err
		}
		fmt.Fprintln(out)
		if res.ExitCode != 0 {
			fmt.Fprintf(out, "❌ 預覽失敗(結束碼 %d)，請看上面的輸出修正後再重新執行 pilot deploy。\n", res.ExitCode)
			return nil
		}
		fmt.Fprintln(out, "✅ 預覽完成，沒有錯誤。")
		if !promptConfirm("預覽看起來沒問題，要接著套用真正的變更嗎？", false) {
			fmt.Fprintln(out, "先在這裡停下來，沒有套用任何變更。")
			return nil
		}
	}

	res, err := runOnce(false)
	if err != nil {
		return err
	}
	fmt.Fprintln(out)
	if res.ExitCode == 0 {
		fmt.Fprintln(out, "✅ 套用完成。")
	} else {
		fmt.Fprintf(out, "❌ 套用失敗(結束碼 %d)，請看上面的輸出。\n", res.ExitCode)
	}
	return nil
}

// ---- full-site flow ---------------------------------------------------------

func runSiteDeploy(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string) error {
	fmt.Fprintln(out, "全站部署會套用 inventory 裡每一個已經填了機器的角色 group；")
	fmt.Fprintln(out, "沒填機器的角色會自動跳過，不需要為它們準備 group_vars/vault。")
	fmt.Fprintln(out)

	decision, err := promptStageDecision(out, "site.yml")
	if err != nil {
		return err
	}
	// site.yml aggregates every apply playbook; most read `stage`,
	// os-patch-sla reads `patch_stage` — set both so one answer here
	// covers every component (see AGENTS.md §4.3 / os-patch-sla note).
	extraVars := []string{"stage=" + decision.Stage, "patch_stage=" + decision.Stage}
	extraVars = append(extraVars, decision.ConfirmVars...)

	limit, err := promptText("要限定只套用到某台主機嗎？(--limit，留空 = 不限定)", "", nil)
	if err != nil {
		return err
	}
	tags, err := promptText("要只跑某幾類元件嗎？(--tags，例如 freeipa,keycloak；留空 = 全部)", "", validateOptionalKV)
	if err != nil {
		return err
	}

	vault, err := promptVault(out, "只有你的 inventory 實際填了 freeipa-server/keycloak/keycloak-db 機器時才需要")
	if err != nil {
		return err
	}

	extra, err := promptText("還有其他 -e 變數要帶嗎？(格式 key=value，可空白分隔多個；留空 = 沒有)", "", validateOptionalKV)
	if err != nil {
		return err
	}
	extraVars = append(extraVars, strings.Fields(extra)...)

	return executeDeployment(ctx, runner, out, "playbooks/site.yml", inv, limit, tags, extraVars, vault)
}

// ---- single-playbook flow ---------------------------------------------------

func runSinglePlaybookDeploy(ctx context.Context, runner *ansible.Runner, out io.Writer, inv string) error {
	labels := make([]string, len(deployCatalog))
	for i, p := range deployCatalog {
		labels[i] = p.Label
	}
	idx, err := promptSelectIndex("挑一個要佈署的元件", labels)
	if err != nil {
		return err
	}
	entry := deployCatalog[idx]

	if entry.Note != "" {
		fmt.Fprintf(out, "ℹ️  %s\n", entry.Note)
	}

	var extraVars []string
	if len(entry.InfraRoles) > 0 {
		roleIdx, err := promptSelectIndex("選擇角色(infra_role)", entry.InfraRoles)
		if err != nil {
			return err
		}
		extraVars = append(extraVars, "infra_role="+entry.InfraRoles[roleIdx])
	}

	defaultGroup := entry.DefaultGroup
	switch {
	case defaultGroup != "":
		// use as-is
	case len(entry.InfraRoles) > 0:
		defaultGroup = "(跟 infra_role 相同)"
	default:
		defaultGroup = "(見上方提示)"
	}
	targetGroup, err := promptText(
		fmt.Sprintf("要限定只套用到哪個 group/host 嗎？(-e target_group=...；留空 = 用預設 group %q；可用交集語法如 'dns:&prod')", defaultGroup),
		"", nil,
	)
	if err != nil {
		return err
	}
	if targetGroup != "" {
		extraVars = append(extraVars, "target_group="+targetGroup)
	}

	decision, err := promptStageDecision(out, entry.Label)
	if err != nil {
		return err
	}
	extraVars = append(extraVars, entry.StageVar+"="+decision.Stage)
	extraVars = append(extraVars, decision.ConfirmVars...)

	limit, err := promptText("要限定只套用到某台主機嗎？(--limit，留空 = 不限定)", "", nil)
	if err != nil {
		return err
	}
	tags, err := promptText("要只跑某幾個檢查項目嗎？(--tags，例如 C1,C2；留空 = 全部)", "", validateOptionalKV)
	if err != nil {
		return err
	}

	vault, err := promptVault(out, entry.VaultHint)
	if err != nil {
		return err
	}

	extra, err := promptText("還有其他 -e 變數要帶嗎？(格式 key=value，可空白分隔多個；留空 = 沒有)", "", validateOptionalKV)
	if err != nil {
		return err
	}
	extraVars = append(extraVars, strings.Fields(extra)...)

	return executeDeployment(ctx, runner, out, entry.Playbook, inv, limit, tags, extraVars, vault)
}
