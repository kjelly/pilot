// portal_session_known_hosts.go is State D of the `pilot portal-session`
// dispatcher: `pilot-known-hosts-v1 <target-fqdn>` (docs/superpowers/
// specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md
// §10). It prints the target's FreeIPA-published SSH host keys as
// known_hosts lines, so the workstation's inner OpenSSH (via
// KnownHostsCommand) verifies the target end to end against the same
// authoritative ipaSshPubKey the gateway's own pilot-connect path trusts —
// no TOFU, and no host-key MITM by the gateway.
package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/google/uuid"

	"github.com/kjelly/pilot/internal/sessionaudit"
)

// knownHostKeyTypes is the host key type allowlist (spec §10 step 5).
var knownHostKeyTypes = map[string]bool{
	"ssh-ed25519":         true,
	"ecdsa-sha2-nistp256": true,
	"ecdsa-sha2-nistp384": true,
	"ecdsa-sha2-nistp521": true,
	"ssh-rsa":             true,
}

// knownHostsLine validates one FreeIPA ipaSshPubKey value ("<type>
// <base64>[ <comment>]") and renders it as a known_hosts line for host,
// dropping the comment. The key blob's own embedded type string must match
// the declared type, so a mislabeled or corrupted value is rejected rather
// than handed to OpenSSH.
func knownHostsLine(host, key string) (string, bool) {
	fields := strings.Fields(key)
	if len(fields) < 2 || !knownHostKeyTypes[fields[0]] {
		return "", false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) < 4 {
		return "", false
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != fields[0] {
		return "", false
	}
	return host + " " + fields[0] + " " + fields[1], true
}

// runPortalKnownHosts implements spec §10 steps 2-8 (parse and TTY checks
// already happened in the dispatcher). stdout receives either the complete
// set of known_hosts lines or nothing at all.
func runPortalKnownHosts(ctx context.Context, client *portalClient, emitter *sessionaudit.Emitter, stdout io.Writer, target string) error {
	identity, err := client.Identity(ctx)
	if err != nil {
		return errors.New(knownHostsMsgUnavailable)
	}
	ev := sessionaudit.SessionAuditEvent{
		SessionID: uuid.NewString(), User: identity.Username, UID: int(identity.UID), TargetFQDN: target,
		GatewayID: identity.Gateway.ID, GatewayScope: identity.Gateway.Scope,
	}
	resp, err := client.TransportHostKeys(ctx, target)
	if err != nil {
		return errors.New(knownHostsMsgUnavailable)
	}
	if !resp.Allowed {
		ev.Kind = sessionaudit.KindGatewayKnownHostsDenied
		ev.Result = "denied"
		emitter.Emit(ev)
		return errors.New(knownHostsMsgAccessDenied)
	}
	ev.TargetFQDN = resp.Target
	var out bytes.Buffer
	count := 0
	for _, key := range resp.HostKeys {
		if line, ok := knownHostsLine(resp.Target, key); ok {
			out.WriteString(line)
			out.WriteByte('\n')
			count++
		}
	}
	if count == 0 {
		ev.Kind = sessionaudit.KindGatewayKnownHostsDenied
		ev.Result = "no_host_key"
		emitter.Emit(ev)
		return errors.New(knownHostsMsgNoHostKey)
	}
	if _, err := stdout.Write(out.Bytes()); err != nil {
		return errors.New(knownHostsMsgUnavailable)
	}
	ev.Kind = sessionaudit.KindGatewayKnownHostsServed
	ev.Result = "ok"
	ev.HostKeyCount = &count
	emitter.Emit(ev)
	return nil
}
