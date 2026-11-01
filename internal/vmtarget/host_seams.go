package vmtarget

import "context"

// HostSeams replaces the steps of Up and Down that depend on the machine the
// code runs on, so a test of a caller outside this package (the vm-target
// CLI) can drive the real Manager against shim binaries on a host with no
// libvirt QEMU account and no Ansible fact cache. A nil field keeps the
// production behaviour. Production code never sets it.
type HostSeams struct {
	// GrantQEMUOverlayAccess replaces the POSIX-ACL grant for the local
	// libvirt QEMU service account. The production grant fails when neither
	// libvirt-qemu nor qemu exists, which is true of every machine without
	// libvirt installed.
	GrantQEMUOverlayAccess func(ctx context.Context, overlayPath string) error
	// DropFacts replaces the Ansible fact-cache cleanup, which reads the
	// ansible-config of the host and deletes cache files by host name.
	DropFacts func(ctx context.Context, hosts []string) error
}

// NewManagerWithHostSeams is NewManager with the host-dependent steps of s
// replaced. Only tests use it; see HostSeams.
func NewManagerWithHostSeams(stateDir, vmDir string, s HostSeams) (*Manager, error) {
	m, err := NewManager(stateDir, vmDir)
	if err != nil {
		return nil, err
	}
	if s.GrantQEMUOverlayAccess != nil {
		m.grantLibvirtQEMUOverlayAccess = s.GrantQEMUOverlayAccess
	}
	if s.DropFacts != nil {
		m.dropFacts = s.DropFacts
	}
	return m, nil
}
