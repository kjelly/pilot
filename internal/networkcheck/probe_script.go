package networkcheck

// probeScriptSource is uploaded and executed on each source host via
// `ansible <host> -m script -a "<tmpfile> <base64-json>"`. It reads a
// base64-encoded JSON array of {"protocol","host","port","timeoutSeconds"}
// probes from argv[1] and prints a JSON array of
// {"status","detail","resolvedIP","durationMs"} — one entry per input probe,
// same order — to a single stdout line. It performs socket connects/sends
// only: no file writes, no service actions, no privilege escalation. TCP
// success proves reachability regardless of any application-level response
// (a plain connect on an http/https/ldap/... endpoint never inspects the
// protocol payload, so an HTTP 403 or an LDAP bind rejection can never be
// misread as a network failure — see plan §4.2's SeaweedFS 403 example).
// UDP has no handshake, so success only means "no local route error",
// reported as reachable-unconfirmed rather than a health verdict.
const probeScriptSource = `#!/usr/bin/env python3
import base64
import json
import socket
import sys
import time


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None


def elapsed_ms(start):
    return int((time.monotonic() - start) * 1000)


def probe_tcp(host, port, timeout):
    start = time.monotonic()
    ip = resolve(host)
    if ip is None:
        return {"status": "error", "detail": "dns resolution failed", "resolvedIP": "", "durationMs": elapsed_ms(start)}
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        return {"status": "reachable", "detail": "connected", "resolvedIP": ip, "durationMs": elapsed_ms(start)}
    except socket.timeout:
        return {"status": "unreachable", "detail": "timeout", "resolvedIP": ip, "durationMs": elapsed_ms(start)}
    except OSError as exc:
        return {"status": "unreachable", "detail": str(exc), "resolvedIP": ip, "durationMs": elapsed_ms(start)}


def probe_udp(host, port, timeout):
    start = time.monotonic()
    ip = resolve(host)
    if ip is None:
        return {"status": "error", "detail": "dns resolution failed", "resolvedIP": "", "durationMs": elapsed_ms(start)}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip, port))
        sock.send(b"")
        return {"status": "reachable-unconfirmed", "detail": "datagram sent; UDP has no ack to confirm the remote service received it", "resolvedIP": ip, "durationMs": elapsed_ms(start)}
    except OSError as exc:
        return {"status": "unreachable", "detail": str(exc), "resolvedIP": ip, "durationMs": elapsed_ms(start)}
    finally:
        sock.close()


def main():
    payload = json.loads(base64.b64decode(sys.argv[1]).decode())
    results = []
    for item in payload:
        protocol = item.get("protocol", "tcp")
        host = item["host"]
        port = int(item["port"])
        timeout = float(item.get("timeoutSeconds") or 3)
        if protocol == "udp":
            results.append(probe_udp(host, port, timeout))
        else:
            results.append(probe_tcp(host, port, timeout))
    sys.stdout.write(json.dumps(results))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
`
