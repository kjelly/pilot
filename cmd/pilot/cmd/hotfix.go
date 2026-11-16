package cmd

import "github.com/spf13/cobra"

// hotfixCmd groups one-shot corrections of known environment problems. Each
// scenario is its own subcommand with its own spec (docs/verification/) and
// playbook; the group itself does nothing, so `pilot hotfix` prints the list.
// Subcommands take the same inventory, stage, limit, timeout and --force /
// --preview-only arguments as `pilot deploy`, and reuse its implementations of
// them rather than copying them.
var hotfixCmd = &cobra.Command{
	Use:   "hotfix",
	Short: "修正已知的環境問題（一次性、day-2；每個情境一個子指令）",
	Long: `pilot hotfix 把「環境出了某種已知狀況、需要先修好才能繼續 pilot deploy」的處理，
做成一個個子指令。每個子指令只處理一種情境，先偵測、印出計畫、確認後才動手，
而且偵測不到問題就什麼都不做。

子指令的 inventory、--limit、--stage、--timeout、--force、--preview-only 與
pilot deploy 的語意相同。`,
}

func init() {
	rootCmd.AddCommand(hotfixCmd)
}
