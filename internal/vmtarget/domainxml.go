package vmtarget

import (
	"fmt"
	"strings"
)

// renderDomainXML produces a minimal, deterministic libvirt domain
// definition for a vm target. We hand-write the XML (rather than shell
// out to virt-install) so every knob is explicit and reproducible.
//
// Choices:
//   - <type>kvm</type> for hardware acceleration (/dev/kvm). On hosts
//     without KVM, libvirt errors clearly at `virsh start`; we surface
//     that rather than silently falling back to slow emulation.
//   - virtio disk + net for performance.
//   - cdrom carrying the cloud-init NoCloud seed.iso.
//   - fixed MAC (derived from the name) so the VM always claims the same
//     DHCP lease, making the IP deterministic.
//   - serial+console + a qemu-guest-agent channel for diagnosability.
func renderDomainXML(t *Target) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "<domain type='kvm'>\n")
	fmt.Fprintf(&sb, "  <name>%s</name>\n", t.Name)
	fmt.Fprintf(&sb, "  <memory unit='MiB'>%d</memory>\n", t.MemoryMB)
	fmt.Fprintf(&sb, "  <currentMemory unit='MiB'>%d</currentMemory>\n", t.MemoryMB)
	fmt.Fprintf(&sb, "  <vcpu placement='static'>%d</vcpu>\n", t.VCPUs)
	sb.WriteString("  <os>\n")
	sb.WriteString("    <type arch='x86_64' machine='q35'>hvm</type>\n")
	sb.WriteString("    <boot dev='hd'/>\n")
	sb.WriteString("  </os>\n")
	sb.WriteString("  <features>\n    <acpi/>\n    <apic/>\n  </features>\n")
	sb.WriteString("  <cpu mode='host-passthrough' check='none'/>\n")
	sb.WriteString("  <clock offset='utc'/>\n")
	sb.WriteString("  <on_poweroff>destroy</on_poweroff>\n")
	sb.WriteString("  <on_reboot>restart</on_reboot>\n")
	sb.WriteString("  <on_crash>destroy</on_crash>\n")
	sb.WriteString("  <devices>\n")
	sb.WriteString("    <emulator>/usr/bin/qemu-system-x86_64</emulator>\n")
	// Root disk: per-target qcow2 overlay (backed by the immutable base).
	sb.WriteString("    <disk type='file' device='disk'>\n")
	sb.WriteString("      <driver name='qemu' type='qcow2'/>\n")
	fmt.Fprintf(&sb, "      <source file='%s'/>\n", t.OverlayPath)
	sb.WriteString("      <target dev='vda' bus='virtio'/>\n")
	sb.WriteString("    </disk>\n")
	// cloud-init NoCloud seed, attached as a READ-ONLY VIRTIO DISK.
	//
	// This must NOT be a SATA/IDE cdrom: on q35, ds-identify runs in
	// early boot (cloud-init-local) before the AHCI/sr driver has the
	// cdrom ready, so it finds no datasource and SILENTLY DISABLES
	// cloud-init for the whole boot — no network config, no SSH key, no
	// lease, and a 3-minute "waiting for IP" timeout with zero clues.
	// A virtio-blk device is present immediately, so ds-identify always
	// sees the cidata label. (Confirmed empirically; do not "simplify"
	// back to a cdrom.)
	sb.WriteString("    <disk type='file' device='disk'>\n")
	sb.WriteString("      <driver name='qemu' type='raw'/>\n")
	fmt.Fprintf(&sb, "      <source file='%s'/>\n", t.SeedPath)
	sb.WriteString("      <target dev='vdb' bus='virtio'/>\n")
	sb.WriteString("      <readonly/>\n")
	sb.WriteString("    </disk>\n")
	// Network: attach to the named libvirt network with the fixed MAC.
	sb.WriteString("    <interface type='network'>\n")
	fmt.Fprintf(&sb, "      <source network='%s'/>\n", t.Network)
	fmt.Fprintf(&sb, "      <mac address='%s'/>\n", t.MAC)
	sb.WriteString("      <model type='virtio'/>\n")
	sb.WriteString("    </interface>\n")
	// Serial console for debugging a stuck boot.
	sb.WriteString("    <serial type='pty'><target port='0'/></serial>\n")
	sb.WriteString("    <console type='pty'><target type='serial' port='0'/></console>\n")
	// qemu-guest-agent channel (harmless if the guest has no agent).
	sb.WriteString("    <channel type='unix'>\n")
	sb.WriteString("      <target type='virtio' name='org.qemu.guest_agent.0'/>\n")
	sb.WriteString("    </channel>\n")
	sb.WriteString("    <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>\n")
	sb.WriteString("  </devices>\n")
	sb.WriteString("</domain>\n")
	return sb.String()
}
