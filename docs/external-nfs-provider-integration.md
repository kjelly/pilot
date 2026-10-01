# External NFS Provider Integration: FreeIPA with NetApp, Synology, and QNAP

> Status: **DRAFT — UNVERIFIED**  
> Scope: architecture, prerequisites, ownership boundaries, and acceptance criteria  
> Hardware evidence: none; no NetApp, Synology, or QNAP target was available for an actual run  
> Promotion rule: replace this status only after provider-specific apply, verification, negative-path,
> and idempotency evidence has been captured from an immutable candidate revision

## 0. Purpose

This guide describes how to use a NetApp, Synology, or QNAP appliance as an external NFS
provider while Linux clients remain enrolled in FreeIPA.

It does **not** claim that the existing Linux NFS server automation supports storage appliances.
`playbooks/apply/freeipa-nfs-server-apply.yml` expects a Linux host with a package manager,
systemd, a local keytab, `/etc/exports.d`, and POSIX ACL tools. Do not assign that role to a NAS.

The supported architectural split is:

| Owner | Responsibility |
|---|---|
| FreeIPA | Users, groups, numeric UID/GID, Kerberos realm, service principal, host/client enrollment, automount records |
| NAS administrator | NFS service, storage virtual server or NAS hostname, key material, export policy, volume/share ACL, snapshots and availability |
| Pilot | FreeIPA reconciliation, Linux client enrollment, automount client configuration, and observable end-to-end verification |

## 1. Choose the security contract first

Do not treat `sec=sys` and Kerberos NFS as interchangeable deployment variants.

| Mode | Identity proof | Network protection | FreeIPA relationship | Recommended use |
|---|---|---|---|---|
| `sec=sys` | Client-supplied numeric UID/GID | None at the NFS layer | LDAP or synchronized numeric IDs are sufficient | Trusted lab or isolated storage network only |
| `krb5` | Kerberos principal | Authentication only | NAS must use the same realm and resolve UNIX identities | Compatibility testing |
| `krb5i` | Kerberos principal | Authentication and integrity | Same realm, service principal, key material and identity mapping required | Default production target |
| `krb5p` | Kerberos principal | Authentication, integrity and privacy | Same requirements as `krb5i`, with higher CPU cost | Sensitive traffic crossing less-trusted networks |

Downgrading an existing `krb5i` contract to `sec=sys` is a security-requirement change. It requires
explicit approval and a separate verification contract; it is not an implementation shortcut.

## 2. Common prerequisites

These facts must be true before provider-specific configuration begins:

1. **Stable server identity** — The NAS data endpoint has one canonical FQDN. Forward and reverse
   DNS agree, and clients use that FQDN rather than an IP address in automount records.
2. **Time synchronization** — FreeIPA, NAS and clients use reliable NTP sources. Kerberos fails
   closed when clock skew exceeds the realm policy.
3. **Service principal** — FreeIPA contains exactly one `nfs/<nas-fqdn>` principal. Its key material
   is installed through the provider's supported Kerberos workflow and is never committed to Git.
4. **UNIX identity mapping** — NAS lookups return the same `uidNumber`, primary `gidNumber`, and
   supplementary groups that FreeIPA clients resolve. Hash-derived or locally assigned IDs are not
   acceptable when POSIX ownership must remain stable.
5. **NFSv4 identity domain** — The provider and clients agree on the NFSv4 ID-mapping domain.
6. **Export policy** — Only approved client networks or hosts are allowed. Root is squashed, and
   the selected security flavor is required rather than merely permitted as an optional fallback.
7. **Automount contract** — The FreeIPA automount server name, remote path, mount root, and security
   flavor match the actual NAS export exactly.
8. **Recovery ownership** — NAS snapshot/replication and FreeIPA configuration backup have named,
   independent owners. A storage snapshot does not back up the FreeIPA principal or automount map.

## 3. Pilot and inventory model

An appliance-backed environment should model the NAS as an external endpoint, not as a Linux
Ansible target:

- Keep `freeipa-nfs-server` empty unless a Linux NFS server is actually managed by the repository's
  apply playbook.
- Put Linux consumers in both `freeipa-client` and `freeipa-nfs-client`.
- Reconcile the NAS host object and automount records through the canonical FreeIPA roster.
  `freeipa-identity-apply.yml` does this for an appliance as follows:
  - A `hosts[]` entry (with `ip_address`) becomes the IPA host object and a forward A record
    (tag `C13`). No PTR record is created; add reverse DNS separately.
  - `nfs.servers[].shares[].automount` becomes the automount location, map, `auto.master` key and
    share key (tag `C18`). C18 reads only the `automount` fields, so an appliance share needs no
    `source_path`, `ownership`, `acl` or `export`.
  - C18 does not filter on server or share `state` and never deletes automount objects. To retire a
    share, set `automount.enabled: false` and remove its keys with `ipa automountkey-del`.
- Create the NAS service principal and key material outside Pilot. No playbook does it for an
  appliance: `freeipa-nfs-server-apply.yml` adds `nfs/<fqdn>` and writes the keytab only to the local
  `/etc/krb5.keytab` of the Linux host it runs on. Run `ipa service-add nfs/<nas-fqdn>` after the
  host object and A record exist, export the key once with `ipa-getkeytab`, and import it through
  the provider's Kerberos workflow. Running `ipa-getkeytab` again rotates the key. The roster's
  `service_principal.principal` records the name for the Linux server apply contract; it does not
  provision an appliance keytab.
- Set the roster's NFS server and automount server fields to the NAS data FQDN.
- Configure the clients' NFSv4 ID-mapping domain separately. `freeipa-nfs-client-apply.yml`
  configures autofs through `ipa-client-automount` and SSSD; it does not manage `/etc/idmapd.conf`
  or `rpc-gssd`.
- Keep appliance credentials, Kerberos keys and administrative API tokens outside inventory and Git.
- Treat appliance-side provisioning as an explicit external precondition until a provider-specific,
  tested adapter exists.

The current Linux NFS verification spec also checks Linux-local packages, systemd units,
`/etc/exports.d`, and local ACLs. Those rows do not apply to an appliance. A provider-specific spec
must replace them with API- or client-observable checks before an appliance integration can be
marked verified.

## 4. NetApp ONTAP

### 4.1 Suitability

ONTAP is the strongest fit of the three providers for a FreeIPA-oriented Kerberos NFS design.
ONTAP supports NFS Kerberos with `krb5i` and `krb5p`, SVM-level Kerberos realms, external LDAP name
services, and configurable name-service search order. NetApp also documents NTP, DNS, directory
services, and correct forward/reverse resolution as required external services.

Authoritative references:

- [ONTAP NFS support for Kerberos](https://docs.netapp.com/us-en/ontap/nfs-admin/ontap-support-kerberos-concept.html)
- [Using Kerberos with ONTAP NFS](https://docs.netapp.com/us-en/ontap/nfs-config/kerberos-nfs-strong-security-concept.html)
- [LDAP for ONTAP NFS SVMs](https://docs.netapp.com/us-en/ontap/nfs-admin/using-ldap-concept.html)
- [ONTAP name services](https://docs.netapp.com/us-en/ontap/nfs-admin/ontap-name-services-concept.html)

### 4.2 Provider-side configuration objects

The storage administrator must define and review all of these objects:

- An NFS-enabled SVM and data LIF with a stable data FQDN.
- DNS configuration for the SVM, including forward and reverse records and Kerberos discovery.
- An LDAP client profile compatible with FreeIPA's RFC 2307 user and group attributes, preferably
  protected with StartTLS.
- Name-service ordering that uses LDAP for passwd and group lookup and DNS for host lookup.
- A Kerberos realm and a Kerberos-enabled data interface bound to `nfs/<data-fqdn>`.
- NFSv4/NFSv4.1 settings and an ID-mapping domain matching the clients.
- UNIX security style for the volume or qtree unless a reviewed multiprotocol mapping design exists.
- Export rules that require the approved Kerberos flavor and implement root squash.
- Volume/qtree ownership and ACLs expressed using FreeIPA numeric identities.

### 4.3 NetApp-specific acceptance

- The SVM resolves a representative FreeIPA user and all supplementary groups through LDAP.
- The Kerberos-enabled data LIF presents the expected `nfs/<data-fqdn>` identity.
- Export rules do not silently allow `sys` when the contract requires `krb5i` or `krb5p`.
- Client access continues through an SVM LIF failover without changing the automount server name.
- Snapshot restore preserves file ownership and ACLs; FreeIPA objects are restored separately.

## 5. Synology DSM

### 5.1 Suitability

The RS3621RPxs product specification lists NFS Kerberos authentication. DSM documents NFSv4,
Kerberos authentication/integrity/privacy, LDAP client mode and configurable RFC 2307 mappings.
This makes direct FreeIPA integration plausible, but the cited Synology Kerberos walkthrough uses
Active Directory rather than FreeIPA. Treat FreeIPA compatibility as unverified until the exact
RS3621RPxs and DSM build pass the identity-mapping and access tests below.

Authoritative references:

- [RS3621RPxs product specifications](https://www.synology.com/en-us/products/RS3621RPxs)
- [DSM NFS service, NFSv4 domain and Kerberos ID mapping](https://kb.synology.com/en-us/DSM/help/DSM/AdminCenter/file_winmacnfs_nfs?version=7)
- [Synology NFS permissions and Kerberos security flavors](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/file_share_privilege_nfs?version=7)
- [Synology LDAP client configuration](https://kb.synology.com/en-us/DSM/help/DSM/AdminCenter/file_directory_service_join?version=7)
- [Synology Kerberos NFS walkthrough](https://kb.synology.com/en-us/DSM/tutorial/how_to_set_up_kerberized_NFS)
- [Red Hat IdM NFS service principal and keytab procedure](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/configuring_and_using_network_file_services/index)

### 5.2 Current Pilot facts (read-only inspection, 2026-10-01)

The requested `pilot-cli:latest` container was inspected with the existing `infra-config` mounts
read-only. Its inventory contains FreeIPA servers, Linux NFS clients and one Linux NFS server; it
contains no Synology target. The canonical roster has one Linux NFS server with zero shares and an
NFS client selector covering managed clients. These are configuration facts, not evidence that a
NAS export or Kerberos mount works. The NAS FQDN/IP, DSM build and export path are still unknown.

### 5.3 DSM setup procedure (RS3621RPxs / DSM 7.x) — TODO: VERIFY on target hardware

The end-to-end integration for the RS3621RPxs storage appliance is partitioned into four concrete steps:

#### Step 1: Network, DNS and Time Synchronization
1. Assign a static IP address to the RS3621RPxs data interface and configure a canonical FQDN (e.g. `nas.linker.internal`).
2. Register both forward (A) and reverse (PTR) DNS records in FreeIPA DNS:
   - Forward A: `nas.linker.internal` → `<NAS_IP>`
   - Reverse PTR: `<NAS_IP>` → `nas.linker.internal`
   > **Important**: Kerberos GSSAPI authentication strictly requires canonical reverse DNS resolution. If PTR resolution returns an unexpected alias or IP, client Kerberos ticket negotiation will fail closed.
3. Configure the NAS NTP client to synchronize with the FreeIPA server or the authoritative realm time source (e.g. `ipa1.linker.internal`). Clock skew between NAS, FreeIPA, and clients must remain strictly under 5 minutes.

#### Step 2: FreeIPA Service Principal & Keytab Generation
Execute the following on the FreeIPA server (or via an administrative host with `admin` credentials):
```bash
# 1. Acquire admin Kerberos ticket
kinit admin

# 2. Register NAS host object in FreeIPA (if not already managed via Pilot roster)
ipa host-add nas.linker.internal --ip-address=<NAS_IP>

# 3. Create the NFS service principal
ipa service-add nfs/nas.linker.internal

# 4. Export the service keytab to a local file
ipa-getkeytab -p nfs/nas.linker.internal -k /tmp/synology-nfs.keytab
```
Download `/tmp/synology-nfs.keytab` securely for upload into DSM, then remove the temporary file from the server.
> **Keytab Rotation Warning**: Re-running `ipa-getkeytab` increments the Key Version Number (KVNO) in FreeIPA and invalidates previously exported keytabs. If re-issued, the new keytab must be re-imported into DSM immediately.

#### Step 3: Synology DSM LDAP Client Configuration (Identity Synchronization)
1. In DSM, navigate to **Control Panel → Domain/LDAP → LDAP** and check **Enable LDAP Client**.
2. Configure connection parameters:
   - **LDAP Server Address**: `ipa1.linker.internal` (or FreeIPA server IP)
   - **Encryption**: `SSL/TLS` or `StartTLS` (import FreeIPA CA certificate under **Control Panel → Security → Certificate** first)
   - **Base DN**: `dc=linker,dc=internal` (derived from realm domain)
   - **Profile**: Select **Custom** and verify RFC 2307 attribute mappings:
     - User ObjectClass: `posixAccount` (`uidNumber` → UID, `gidNumber` → primary GID, `uid` → username)
     - Group ObjectClass: `posixGroup` (`gidNumber` → GID, `cn` → group name, `memberUid` → member)
   - **Bind DN / Password**: Provide a dedicated directory bind account or admin credentials.
3. **Numeric UID/GID Integrity**: Do **not** enable DSM UID/GID translation/shifting options. Numeric IDs must match FreeIPA Linux clients (`id <username>`) 1:1.
4. Verify under **LDAP Users** and **LDAP Groups** tabs that FreeIPA identities appear with correct numeric IDs.

#### Step 4: Synology DSM NFSv4.1 & Kerberos Service Configuration
1. In DSM, navigate to **Control Panel → File Services → NFS**:
   - Check **Enable NFS Service**.
   - Set **Maximum NFS protocol** to **NFSv4.1** (or NFSv4).
2. Click **Advanced Settings**:
   - **NFSv4 domain**: Set to the client ID-mapping domain (e.g. `linker.internal`, matching `/etc/idmapd.conf`).
   - Under **Kerberos Settings**, click **Add**:
     - **Realm**: `LINKER.INTERNAL` (must be uppercase)
     - **KDC Server**: `ipa1.linker.internal`
     - **Keytab**: Upload `synology-nfs.keytab`
   - Select the uploaded keytab as active for NFS service.

#### Step 5: Shared Folder & NFS Export Permissions
1. Navigate to **Control Panel → Shared Folder**, select the target share (e.g. `projects`), and click **Edit**.
2. Switch to **NFS Permissions** tab and click **Create**:
   - **Hostname or IP**: Allowed client CIDR (e.g. `10.1.0.0/16`, `10.20.40.0/24`) or specific host FQDNs.
   - **Privilege**: Read/Write (or Read-Only).
   - **Squash**: Select **Map root to guest** (`root_squash` requirement per Pilot security contract).
   - **Security**: Select **Kerberos integrity (krb5i)** or **Kerberos privacy (krb5p)**. Uncheck `AUTH_SYS` / `sys` to prevent unauthenticated fallback.
   - Check **Enable asynchronous** and **Allow connections from non-privileged ports** if required by client kernel configuration.
3. Switch to **Permissions** tab:
   - Select **LDAP Users** or **LDAP Groups** from the drop-down.
   - Grant appropriate Read/Write permissions to target FreeIPA groups (e.g. `data-projects-rw`).

---

### 5.4 Pilot Integration: Canonical Roster & Automount Management

Do **not** place the Synology appliance into the `freeipa-nfs-server` Ansible inventory group. `playbooks/apply/freeipa-nfs-server-apply.yml` expects a Linux host and will fail on DSM.

Instead, model the appliance in the canonical identity roster (`.vault/ipa-identity.yaml`):

```yaml
nfs:
  servers:
    - host: nas.linker.internal
      state: present
      service_principal:
        ensure: true
        principal: nfs/nas.linker.internal
      shares:
        - name: nas-projects
          state: present
          automount:
            enabled: true
            location: default
            mount_root: /mnt/nas
            map: auto.nas
            key: projects
            server: nas.linker.internal
            remote_path: /volume1/projects
            options: [fstype=nfs4, sec=krb5i, hard, timeo=600, retrans=2]

nfs_clients:
  - hostgroup: nfs-clients-all
    state: present
    verification_mounts: [/mnt/nas/projects]
```

#### How Pilot reconciles this:
1. `pilot roster lint <roster-path>` validates the roster structure against schema v3.
2. `freeipa-identity-apply.yml` (tag `C18`) connects to the FreeIPA server and idempotently creates:
   - Automount location: `default`
   - Master map key: `auto.master` → key `/mnt/nas`, map `auto.nas`
   - Share map key: `auto.nas` → key `projects`, info `-fstype=nfs4,sec=krb5i,hard,timeo=600,retrans=2 nas.linker.internal:/volume1/projects`
3. `freeipa-nfs-client-apply.yml` runs on enrolled Linux clients (`freeipa-nfs-client` role), configuring `autofs` and the SSSD autofs responder. Clients mount the NAS volume dynamically upon path access without any static `/etc/fstab` entry.

---

### 5.5 Client Verification and Negative-Path Checks

On an enrolled Linux client host (e.g. `ml-kusanagi`):

1. **Authenticated Kerberos Mount Verification**:
   ```bash
   # Acquire user Kerberos ticket from FreeIPA
   kinit <ipa-user>

   # Trigger autofs access
   ls -la /mnt/nas/projects

   # Verify effective mount attributes
   findmnt -t nfs4 /mnt/nas/projects
   # Expected output contains: nfs4, sec=krb5i (or sec=krb5p)
   ```
2. **Read/Write & Ownership Verification**:
   - An authorized user creates a file: verify permissions and group ownership match `posixAccount` / `posixGroup` IDs without numeric shifting.
3. **Negative-Path Verification**:
   - **No Kerberos Ticket**: Destroy ticket with `kdestroy`. Attempt access to `/mnt/nas/projects` — must fail with `Permission denied`.
   - **Root Squash**: Attempt access as local client `root` — access must be mapped to guest/nobody and restricted according to the squash policy.
   - **Unauthorized User**: Access as a user not in the authorized LDAP group — must fail with `Permission denied`.

---

### 5.6 Synology-specific acceptance — TODO: VERIFY on RS3621RPxs

- DSM shows the expected LDAP users/groups with unchanged numeric IDs.
- An authenticated Kerberos principal maps to the intended LDAP identity, never `guest`; verify `GSSAuthName` or the selected DSM mapping path explicitly.
- The NFS permission rule requires the selected Kerberos flavor (`krb5i` / `krb5p`).
- Read/write, read-only and denied FreeIPA identities behave differently as designed.
- The effective NFSv4 ID-mapping domain agrees between DSM and the Linux clients.
- The same checks pass after a DSM reboot and after directory caches are refreshed.

## 6. QNAP QTS and QuTS hero

### 6.1 Suitability

QNAP documents `krb5`, `krb5i`, and `krb5p` for NFSv4 shares. However, its official QTS workflow
states that the NAS host and NFS client must join the same Active Directory server for
Kerberos-backed NFS. QNAP also supports LDAP authentication, but that does not establish official
support for FreeIPA as the NFS Kerberos KDC. Direct FreeIPA + QNAP Kerberos must therefore remain
**unsupported/unverified** unless QNAP confirms the exact model and firmware or an actual lab run
proves the complete contract.

Authoritative references:

- [QTS NFS service and security settings](https://docs.qnap.com/operating-system/qts/5.2.x/en-us/configuring-nfs-service-settings-4A850D3A.html)
- [QNAP LDAP authentication](https://docs.qnap.com/operating-system/quts-hero/4.5.x/en-us/GUID-EBBEBD6A-C258-4B05-B0D9-8651B0E0E288.html)

### 6.2 Supported design choices

Choose and record one of these contracts:

1. **QNAP with `sec=sys`** — Use LDAP or carefully synchronized numeric UID/GID values. Restrict
   access to a trusted storage network and acknowledge the absence of NFS-layer authentication,
   integrity, and privacy.
2. **QNAP with supported AD Kerberos** — Place clients and NAS in the supported AD design. If
   FreeIPA identities are still required elsewhere, treat identity bridging/trust as a separate
   architecture with its own source-of-truth and UID/GID rules.
3. **Direct FreeIPA experiment** — Lab-only until vendor confirmation and complete evidence exist.
   It must not be described as production-supported merely because an LDAP bind succeeds.

### 6.3 QNAP-specific acceptance

- Record the exact NAS model, QTS/QuTS hero build, and the vendor-supported identity source.
- Verify numeric UID/GID resolution independently from SMB or File Station authentication.
- Confirm whether the NFS rule requires Kerberos or silently falls back to `sys`.
- If AD is used, verify the resulting UNIX IDs remain stable and agree with Linux client ownership.
- Repeat RW/RO/deny tests after reboot and directory cache refresh.

## 7. Cross-provider acceptance checklist

An integration is not complete until all applicable observations pass:

| Area | Required observation |
|---|---|
| DNS | NAS FQDN has correct forward and reverse answers from FreeIPA clients and the provider |
| Time | FreeIPA, clients and NAS remain within the Kerberos clock-skew policy |
| Identity | Representative user, primary group and supplementary groups resolve to identical numeric IDs |
| Principal | The server authenticates as exactly `nfs/<nas-fqdn>` |
| Mount security | The effective NFS mount reports the approved `krb5i` or `krb5p` flavor when Kerberos is required |
| RW | An authorized writer can create, modify and remove a test file |
| RO | A read-only identity can read but cannot create, modify or remove content |
| Deny | An unauthorized identity cannot traverse or read the protected export |
| Root squash | Client root does not become unrestricted NAS root or owner |
| Automount | FreeIPA automount resolves and mounts the NAS path without a static client fstab entry |
| Recovery | NAS reboot/failover and client reboot do not change identities, security flavor or automount behavior |
| Negative path | Invalid/expired Kerberos credentials and an unapproved client are denied |
| Audit | Provider and FreeIPA logs identify failed authentication and policy decisions without exposing secrets |

## 8. Rollback boundary

Rollback must preserve the previous working path rather than deleting it immediately:

1. Keep the previous NFS export read-only during the migration window.
2. Restore the prior FreeIPA automount map if the NAS endpoint fails acceptance.
3. Remove the new service principal only after all clients have stopped using it.
4. Revoke and rotate NAS key material through the provider-supported workflow.
5. Restore storage data through provider snapshots/replication; restore FreeIPA objects through the
   FreeIPA backup process.
6. Record whether rollback changed file ownership, ACLs, export security flavor, or client caches.

## 9. Evidence required before promotion

Create a separate provider-specific evidence record containing:

- Exact appliance model, firmware/ONTAP/DSM/QTS version and immutable configuration export hash.
- Candidate commit/tree and hashes of the FreeIPA roster, client automation and verification spec.
- Sanitized DNS, NTP, LDAP/identity, Kerberos principal and export-policy facts.
- Real RW/RO/deny, root-squash, automount, reboot/failover and negative-path verdicts.
- Idempotency evidence for every Pilot-managed reconciliation step.
- Secret-scan result and the controlled location/checksum of raw evidence.

Until that record exists, this document remains a design and readiness guide, not a verified
deployment runbook.
