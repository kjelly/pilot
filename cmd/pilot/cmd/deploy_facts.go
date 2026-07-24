// deploy_facts.go gathers per-host OS/resource facts before a deploy's
// contract preflight check runs. Without this, delivery.PreflightRequest.Facts
// was always empty and every component/host pair printed a permanent
// "facts unavailable" warning — the check was fully wired end-to-end except
// for an actual facts source.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kjelly/pilot/internal/delivery"
)

// hostFactsProbeCommand is a read-only shell one-liner run per host via an
// ad-hoc `ansible -m shell` call. It never mutates the target and needs no
// privilege escalation, so it is safe to run unconditionally before every
// deploy's preflight step.
const hostFactsProbeCommand = `. /etc/os-release 2>/dev/null; printf '%s;%s;%s;%s;%s\n' "$ID" "$VERSION_ID" "$(nproc 2>/dev/null)" "$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')" "$(df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9')"`

const hostFactsProbeTimeout = 20 * time.Second
const hostFactsProbeConcurrency = 8

// rpmMajorOnlyDistros truncates /etc/os-release's VERSION_ID to its major
// component for distro families whose contracts declare a bare major
// version (e.g. contracts/freeipa-server.yaml's "9"), since these distros
// report a full point release (e.g. "9.4") where Ubuntu's VERSION_ID is
// already the exact two-part string ("22.04"/"24.04") contracts expect.
var rpmMajorOnlyDistros = map[string]bool{"almalinux": true, "rocky": true, "rhel": true}

// gatherHostFacts probes every host concurrently and returns whatever facts
// it could collect. A host that is unreachable, times out, or returns
// unparsable output is simply absent from the result — ValidateContractPreflight
// already treats a missing entry as a non-fatal warning, so a partial result
// is always safe to hand it.
func gatherHostFacts(ctx context.Context, inventory string, hosts []string) map[string]delivery.HostFacts {
	facts := make(map[string]delivery.HostFacts, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, hostFactsProbeConcurrency)
	for _, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()
			f, err := probeHostFacts(ctx, inventory, host)
			if err != nil {
				return
			}
			mu.Lock()
			facts[host] = f
			mu.Unlock()
		}(host)
	}
	wg.Wait()
	return facts
}

func probeHostFacts(ctx context.Context, inventory, host string) (delivery.HostFacts, error) {
	cctx, cancel := context.WithTimeout(ctx, hostFactsProbeTimeout)
	defer cancel()
	command := deployAnsibleCommand(cctx, "ansible", host, "-i", inventory, "-m", "shell", "-a", hostFactsProbeCommand)
	if command.Env == nil {
		command.Env = os.Environ()
	}
	command.Env = append(command.Env, "ANSIBLE_LOAD_CALLBACK_PLUGINS=1", "ANSIBLE_STDOUT_CALLBACK=ansible.posix.json")
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return delivery.HostFacts{}, fmt.Errorf("probe %s: %w: %s", host, err, strings.TrimSpace(stderr.String()))
	}
	line, err := extractAdHocStdout(stdout.String(), host)
	if err != nil {
		return delivery.HostFacts{}, err
	}
	return parseHostFactsLine(line)
}

// adHocCallbackDoc is the (partial) shape of the document
// ANSIBLE_STDOUT_CALLBACK=ansible.posix.json writes for a single-task ad-hoc
// run: each targeted host's module stdout, keyed by inventory hostname.
type adHocCallbackDoc struct {
	Plays []struct {
		Tasks []struct {
			Hosts map[string]struct {
				Stdout      string `json:"stdout"`
				RC          int    `json:"rc"`
				Failed      bool   `json:"failed"`
				Unreachable bool   `json:"unreachable"`
			} `json:"hosts"`
		} `json:"tasks"`
	} `json:"plays"`
}

func extractAdHocStdout(rawJSON, host string) (string, error) {
	var doc adHocCallbackDoc
	if err := json.Unmarshal([]byte(rawJSON), &doc); err != nil {
		return "", fmt.Errorf("parse ansible callback output for %s: %w", host, err)
	}
	for _, play := range doc.Plays {
		for _, task := range play.Tasks {
			result, ok := task.Hosts[host]
			if !ok {
				continue
			}
			if result.Unreachable {
				return "", fmt.Errorf("host %s unreachable", host)
			}
			if result.Failed || result.RC != 0 {
				return "", fmt.Errorf("host %s facts probe failed (rc=%d)", host, result.RC)
			}
			return result.Stdout, nil
		}
	}
	return "", fmt.Errorf("no ansible callback result for host %s", host)
}

// parseHostFactsLine parses the ";"-delimited line hostFactsProbeCommand
// prints: distro id;version id;cpu count;ram MiB;disk GiB available on /.
func parseHostFactsLine(line string) (delivery.HostFacts, error) {
	fields := strings.Split(strings.TrimSpace(line), ";")
	if len(fields) != 5 {
		return delivery.HostFacts{}, fmt.Errorf("unexpected facts probe output %q", line)
	}
	distro := strings.ToLower(strings.TrimSpace(fields[0]))
	version := strings.TrimSpace(fields[1])
	if rpmMajorOnlyDistros[distro] {
		if major, _, ok := strings.Cut(version, "."); ok {
			version = major
		}
	}
	cpu, err := strconv.Atoi(strings.TrimSpace(fields[2]))
	if err != nil {
		return delivery.HostFacts{}, fmt.Errorf("parse cpu count from %q: %w", line, err)
	}
	ram, err := strconv.Atoi(strings.TrimSpace(fields[3]))
	if err != nil {
		return delivery.HostFacts{}, fmt.Errorf("parse ram MiB from %q: %w", line, err)
	}
	disk, err := strconv.Atoi(strings.TrimSpace(fields[4]))
	if err != nil {
		return delivery.HostFacts{}, fmt.Errorf("parse disk GiB from %q: %w", line, err)
	}
	return delivery.HostFacts{
		Available: true,
		Distro:    distro,
		Version:   version,
		CPU:       cpu,
		RAMMiB:    ram,
		DiskGiB:   disk,
	}, nil
}
