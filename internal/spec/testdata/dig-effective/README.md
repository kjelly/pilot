# dig captures for C8 (docs/verification/freeipa-dns-client.md)

Captured 2026-11-16 on a disposable three-VM vm-target topology (a FreeIPA 4.13
server on AlmaLinux 9 with `--setup-dns`, an unbound dns tier on Ubuntu 24.04,
and an AlmaLinux 9 consumer), after `freeipa-dns-client-apply.yml` had run.
Each file is what `dig` printed for the exact query C8 sends, run on the
consumer VM:

    dig +time=2 +tries=1 +noall +comments +answer @<server> ipa1.ipa.pilot.internal. <A|AAAA>

Recursion is desired (RD=1), as glibc asks. `<name>.txt` is stdout and
`<name>.rc` is dig's exit status (0 for an answer, 9 for no server reached).
stderr was empty in every capture, so it is not stored.

| files | queried server | dig |
|---|---|---|
| `freeipa_rd_*` | the FreeIPA server's named (authoritative for the zone) | Ubuntu 24.04: DiG 9.18.39 |
| `dnsmasq_*` | the libvirt dnsmasq that DHCP gives a vm-target as its resolver (it does not know the FreeIPA zone: NXDOMAIN) | Ubuntu 24.04: DiG 9.18.39 |
| `unreachable_*` | 192.0.2.1 (TEST-NET-1, nothing answers): dig prints `;; communications error ... timed out` | Ubuntu 24.04: DiG 9.18.39 |
| `el_*` (the same three servers) | | AlmaLinux 9: DiG 9.16.23-RH; its timeout text is `;; connection timed out; no servers could be reached` |

Only edit: the `; COOKIE:` value of the EDNS pseudosection (a per-query nonce
pair) is replaced by zeros of the same length.

The unbound tier answered exactly as the older captures in `../dig-nscheck`
do, so those are reused for the tier, a public resolver (NXDOMAIN), REFUSED
and SERVFAIL (see `../dig-nscheck/README.md`).

## resolvectl and nmcli captures

Read on the same VMs (resolvectl on the Ubuntu node before the playbook ran,
when /etc/resolv.conf was still the systemd-resolved stub; nmcli on the
AlmaLinux 9 node, NetworkManager 1.54.3):

| file | command |
|---|---|
| `resolvectl_dns_stub.txt` | `resolvectl dns` |
| `nmcli_active.txt` | `nmcli -t -f NAME,DEVICE connection show --active` |
| `nmcli_ignore_auto_dns_dhcp.txt` | `nmcli -g ipv4.ignore-auto-dns connection show "System eth0"` before the playbook ran (DHCP DNS in use) |
| `nmcli_ignore_auto_dns_managed.txt` | the same command after `freeipa-dns-client-apply.yml` |
