package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/vmtarget"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Perform self-diagnosis on the ansible toolchain and environments",
	Run:   runDoctor,
}

func runDoctor(cmd *cobra.Command, args []string) {
	cfg := loadConfig()
	fmt.Println("🏥 Starting pilot self-diagnosis...")
	fmt.Println("======================================")

	allPassed := true

	// 1. Check Ansible installation
	fmt.Printf("[1] Checking Ansible installation... ")
	ansiblePath, err := exec.LookPath("ansible")
	if err != nil {
		fmt.Println("\033[31mFAILED\033[0m")
		fmt.Println("    -> 'ansible' was not found in PATH. Please install ansible-core or ansible.")
		allPassed = false
	} else {
		if verOut, err := exec.Command("ansible", "--version").Output(); err == nil {
			verStr := strings.TrimSpace(string(verOut))
			if idx := strings.Index(verStr, "\n"); idx != -1 {
				verStr = verStr[:idx]
			}
			fmt.Printf("\033[32mOK\033[0m (%s)\n", verStr)
		} else {
			fmt.Printf("\033[32mOK\033[0m (path: %s, but version check failed: %v)\n", ansiblePath, err)
		}
	}

	// 2. Check Ansible-lint installation (optional but recommended)
	fmt.Printf("[2] Checking 'ansible-lint' installation... ")
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

	// 3. Check Ansible playbook syntax-checker
	fmt.Printf("[3] Checking 'ansible-playbook' executable... ")
	apPath, err := exec.LookPath("ansible-playbook")
	if err != nil {
		fmt.Println("\033[31mFAILED\033[0m")
		fmt.Println("    -> 'ansible-playbook' was not found in PATH.")
		allPassed = false
	} else {
		fmt.Printf("\033[32mOK\033[0m (path: %s)\n", apPath)
	}

	// 4. Check SQLite history database
	dbPath := filepath.Join(cfg.DataDir, "history.db")
	fmt.Printf("[4] Checking SQLite database at %s... ", dbPath)
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

	// 5. Check vm-target golden-image prerequisites (optional feature:
	//    only matters when using 'pilot vm-target'). Without KVM access
	//    virt-customize falls back to software emulation and appliance
	//    boots take minutes instead of seconds.
	fmt.Printf("[5] Checking vm-target prerequisites (virt-customize + KVM + appliance DHCP)... ")
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
