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
- Reconcile the NAS service principal and automount records through the canonical FreeIPA roster.
- Set the roster's NFS server and automount server fields to the NAS data FQDN.
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

DSM documents NFS security flavors for Kerberos authentication, integrity, and privacy. It also
supports LDAP client mode and custom RFC 2307 mappings. This makes direct FreeIPA integration
plausible, but support varies by model and DSM release and Synology does not explicitly certify
FreeIPA as the Kerberos provider in the cited documentation. Treat it as a compatibility target
that requires a lab proof on the exact appliance and DSM build.

Authoritative references:

- [Synology NFS permissions and Kerberos security flavors](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/file_share_privilege_nfs?version=7)
- [Synology LDAP client configuration](https://kb.synology.com/en-global/DSM/help/DSM/AdminCenter/file_directory_service_ldap)
- [Synology guidance for encrypted NFS transfer](https://kb.synology.com/en-in/DSM/tutorial/what_can_i_do_to_encrypt_data_transmission_when_using_nfs)

### 5.2 Provider-side configuration objects

- Confirm that the exact model and DSM release expose NFSv4 plus Kerberos settings.
- Join DSM to the FreeIPA LDAP directory with an RFC 2307-compatible custom profile.
- Confirm that DSM preserves FreeIPA numeric UID/GID values rather than generating local hashes.
- Configure the NAS FQDN, DNS and NTP before Kerberos settings.
- Configure the Kerberos realm and `nfs/<nas-fqdn>` identity through DSM's supported interface.
- Create the shared folder and NFS permission rule with the required Kerberos flavor.
- Map root to guest unless a separately reviewed workload requires another squash policy.
- Assign read/write and read-only access using directory users/groups, not duplicated local accounts.

### 5.3 Synology-specific acceptance

- DSM shows the expected LDAP users/groups with unchanged numeric IDs.
- A Kerberos user is not mapped to `guest`; this detects missing DSM ID mapping or LDAP membership.
- The NFS permission rule requires the selected Kerberos flavor.
- Read/write, read-only and denied FreeIPA identities behave differently as designed.
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
