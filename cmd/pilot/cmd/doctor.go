package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/vmtarget"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Perform self-diagnosis on connection, models, and environments",
	Run:   runDoctor,
}

func runDoctor(cmd *cobra.Command, args []string) {
	ctx := context.Background()
	cfg := loadConfig()
	fmt.Println("🏥 Starting pilot self-diagnosis...")
	fmt.Println("======================================")

	allPassed := true

	// 1. Check Ollama server connection
	fmt.Printf("[1] Checking Ollama server connection at %s... ", cfg.OllamaURL)
	client := ollama.NewClient(cfg.OllamaURL, cfg.Model)
	if err := client.Ping(ctx); err != nil {
		fmt.Printf("\033[31mFAILED\033[0m (%v)\n", err)
		fmt.Println("    -> Please ensure the Ollama server is running. Try: 'ollama serve'")
		allPassed = false
	} else {
		fmt.Println("\033[32mOK\033[0m")
	}

	// 2. Check LLM model
	fmt.Printf("[2] Checking LLM model %q... ", cfg.Model)
	models, err := client.ListModels(ctx)
	if err != nil {
		fmt.Printf("\033[31mFAILED to list models\033[0m (%v)\n", err)
		allPassed = false
	} else {
		found := false
		for _, m := range models {
			if m == cfg.Model {
				found = true
				break
			}
		}
		if found {
			fmt.Println("\033[32mOK\033[0m")
		} else {
			fmt.Printf("\033[33mWARNING\033[0m (model %q not pulled)\n", cfg.Model)
			fmt.Printf("    -> Please pull it first. Run: 'ollama pull %s'\n", cfg.Model)
		}
	}

	// 3. Check Embedding model (used only for the playbook index; the
	//    module docs index uses bleve BM25 and needs no embedder).
	fmt.Printf("[3] Checking Embedding model %q (for playbook index)... ", playbookEmbedMod)
	foundEmb := false
	for _, m := range models {
		if m == playbookEmbedMod {
			foundEmb = true
			break
		}
	}
	if foundEmb {
		fmt.Println("\033[32mOK\033[0m")
	} else {
		fmt.Printf("\033[33mWARNING\033[0m (embedding model %q not pulled)\n", playbookEmbedMod)
		fmt.Printf("    -> Only needed if you index user playbooks. Run: 'ollama pull %s'\n", playbookEmbedMod)
	}

	// 4. Check Ansible installation
	fmt.Printf("[4] Checking Ansible installation... ")
	ansiblePath, err := exec.LookPath("ansible")
	if err != nil {
		fmt.Println("\033[31mFAILED\033[0m")
		fmt.Println("    -> 'ansible' was not found in PATH. Please install ansible-core or ansible.")
		allPassed = false
	} else {
		ver, err := docs.AnsibleVersion(ctx)
		if err != nil {
			fmt.Printf("\033[32mOK\033[0m (path: %s, but version check failed: %v)\n", ansiblePath, err)
		} else {
			fmt.Printf("\033[32mOK\033[0m (%s)\n", ver)
		}
	}

	// 5. Check Ansible-lint installation (optional but recommended)
	fmt.Printf("[5] Checking 'ansible-lint' installation... ")
	lintPath, err := exec.LookPath("ansible-lint")
	if err != nil {
		fmt.Println("\033[33mWARNING\033[0m")
		fmt.Println("    -> 'ansible-lint' was not found in PATH. Pre-flight linting checks will be skipped.")
		fmt.Println("       To enable linting, install it via: 'pip install ansible-lint'")
	} else {
		cmd := exec.Command("ansible-lint", "--version")
		if verOut, err := cmd.Output(); err == nil {
			verStr := strings.TrimSpace(string(verOut))
			if idx := strings.Index(verStr, "\n"); idx != -1 {
				verStr = verStr[:idx]
			}
			fmt.Printf("\033[32mOK\033[0m (path: %s, %s)\n", lintPath, verStr)
		} else {
			fmt.Printf("\033[32mOK\033[0m (path: %s)\n", lintPath)
		}
	}

	// 6. Check Ansible playbook syntax-checker
	fmt.Printf("[6] Checking 'ansible-playbook' executable... ")
	apPath, err := exec.LookPath("ansible-playbook")
	if err != nil {
		fmt.Println("\033[31mFAILED\033[0m")
		fmt.Println("    -> 'ansible-playbook' was not found in PATH.")
		allPassed = false
	} else {
		fmt.Printf("\033[32mOK\033[0m (path: %s)\n", apPath)
	}

	// 7. Check SQLite history database
	dbPath := filepath.Join(cfg.DataDir, "history.db")
	fmt.Printf("[7] Checking SQLite database at %s... ", dbPath)
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		fmt.Printf("\033[31mFAILED to create data dir\033[0m (%v)\n", err)
		allPassed = false
	} else {
		_, statErr := os.Stat(dbPath)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				fmt.Println("\033[32mOK\033[0m (will be initialized on next run)")
			} else {
				fmt.Printf("\033[31mFAILED\033[0m (%v)\n", statErr)
				allPassed = false
			}
		} else {
			fmt.Println("\033[32mOK\033[0m")
		}
	}

	// 8. Check RAG Docs index status (bleve-backed BM25)
	blevePath := moduleBlevePath(cfg.DataDir)
	fmt.Printf("[8] Checking RAG docs index at %s... ", blevePath)
	if _, err := os.Stat(blevePath); err != nil {
		fmt.Printf("\033[33mWARNING\033[0m (not built yet)\n")
		fmt.Println("    -> Local Ansible module index is missing. Run: 'pilot index-docs' to build it.")
	} else {
		meta, err := loadIndexMeta(cfg.DataDir)
		if err != nil {
			fmt.Printf("\033[32mOK\033[0m (built, but metadata unreadable: %v)\n", err)
		} else {
			fmt.Printf("\033[32mOK\033[0m (built, contains %d chunks from %d modules)\n", meta.ChunkCount, meta.ModuleCount)
		}
	}

	// 9. Check vm-target golden-image prerequisites (optional feature:
	//    only matters when using 'pilot vm-target'). Without KVM access
	//    virt-customize falls back to software emulation and appliance
	//    boots take minutes instead of seconds.
	fmt.Printf("[9] Checking vm-target prerequisites (virt-customize + KVM + appliance DHCP)... ")
	vcPath, vcErr := exec.LookPath("virt-customize")
	var vmHints []string
	if vcErr != nil {
		vmHints = append(vmHints,
			"'virt-customize' was not found in PATH. vm-target will boot uncustomized\n"+
				"       cloud images (slower first boot). Install it via: 'sudo apt install libguestfs-tools'")
	} else {
		if hint := vmtarget.KVMAccessHint(); hint != "" {
			vmHints = append(vmHints, hint)
		}
		if hint := vmtarget.ApplianceDHCPHint(); hint != "" {
			vmHints = append(vmHints, hint)
		}
	}
	if len(vmHints) == 0 {
		fmt.Printf("\033[32mOK\033[0m (path: %s)\n", vcPath)
	} else {
		fmt.Println("\033[33mWARNING\033[0m")
		for _, h := range vmHints {
			fmt.Printf("    -> %s\n", h)
		}
	}

	fmt.Println("======================================")
	if allPassed {
		fmt.Println("\033[32m✓ All critical checks passed! pilot is ready to fly. 🚀\033[0m")
	} else {
		fmt.Println("\033[31m❌ Some checks failed. Please resolve the issues highlighted above.\033[0m")
	}
}
