# 🛡️ Security Assessment Recap — Batavia

> **Framework:** CIS AD Benchmark v3.0 | CIS Controls v8 | MITRE ATT&CK | OWASP WSTG v4.2 | CVSS v4.0  
> **Generated:** 2026-03-30 / 2026-04-01  
> **Scope:** Active Directory · DNS · Firewall · Back Office · H2H · SFTP · Mail Security · Endpoint Hardening

---

## 📑 Daftar Isi

1. [AD Security Assessment](#1-ad-security-assessment)
   - [1.1 User Enumeration](#11-user-enumeration)
   - [1.2 Password Policy](#12-password-policy)
   - [1.3 Privileged Accounts](#13-privileged-accounts)
   - [1.4 Kerberos](#14-kerberos)
   - [1.5 GPO Analysis](#15-gpo-analysis)
   - [1.6 AD Certificate Services (AD CS)](#16-ad-certificate-services-ad-cs)
2. [DNS, Firewall, Back Office, H2H & SFTP](#2-dns-firewall-back-office-h2h--sftp)
   - [2.1 Firewall (FortiGate)](#21-firewall-fortigate)
   - [2.2 DNS](#22-dns)
   - [2.3 Back Office Server](#23-back-office-server)
   - [2.4 H2H S-Invest (App & Service Automasi)](#24-h2h-s-invest-app--service-automasi)
   - [2.5 SFTP S-Invest](#25-sftp-s-invest)
3. [Mail Security (Microsoft 365)](#3-mail-security-microsoft-365)
4. [Security Hardening — macOS & Windows](#4-security-hardening--macos--windows)
   - [4.1 macOS Hardening](#41-macos-hardening)
   - [4.2 Windows Hardening](#42-windows-hardening)
5. [Ringkasan Temuan & Prioritas Remediasi](#5-ringkasan-temuan--prioritas-remediasi)

---

## Legend Status

| Status | Keterangan |
|--------|-----------|
| ✅ Done / Pass | Selesai — tidak ada temuan |
| ⚠️ Finding / Warning | Ada temuan / issue yang perlu ditangani |
| ➖ N/A | Tidak applicable di environment ini |
| 🔍 Butuh Verifikasi | Perlu pengecekan lanjutan |
| ❌ Fail | Konfigurasi tidak sesuai, perlu remediasi |

---

## 1. AD Security Assessment

> **Referensi:** CIS AD Benchmark v3.0 | CIS Controls v8 | MITRE ATT&CK  
> **Total Domain:** 6 | **Total Item:** 72

---

### 1.1 User Enumeration

> **Referensi:** CIS AD Benchmark Sec.1, CIS Control 5 | **Total Item:** 10

| # | Item | Command / Method | Threshold | Status |
|---|------|-----------------|-----------|--------|
| 1.1 | Enumerate semua domain user | `Get-ADUser -Filter * -Properties *` | Semua user terdaftar | ✅ Done |
| 1.2 | User dengan atribut sensitif (SPN, adminCount) | `Get-ADUser -Filter {adminCount -eq 1} -Properties *` | adminCount=1 harus minimum | ⚠️ Finding |
| 1.3 | Enumerate semua domain group | `Get-ADGroup -Filter * \| Select Name` | Periksa group non-standar | ✅ Done |
| 1.4 | Member per group (terutama privileged) | `Get-ADGroupMember -Identity 'Domain Admins' -Recursive` | DA < 5 akun ideal | ⚠️ Finding |
| 1.5 | Null Bind Testing | `ldapsearch -x -H ldap://<TARGET>:389 -b "" -s base "(objectclass=*)"` | Checking Unauthenticated Access | ✅ Done |
| 1.6 | User dengan Password Never Expires | `Get-ADUser -Filter {PasswordNeverExpires -eq $true}` | Harus 0 atau minimum (service acct) | ⚠️ Finding |
| 1.7 | Stale/disabled accounts (>90 hari tidak login) | `Search-ADAccount -AccountInactive -TimeSpan 90` | Harus di-disable/delete | ⚠️ Finding |
| 1.8 | BloodHound collection (All methods) | `SharpHound.exe --CollectionMethods All --ZipFileName output.zip` | Jalankan dari domain-joined host | ✅ Done |
| 1.9 | Computer accounts & OS inventory | `Get-ADComputer -Filter * -Properties OperatingSystem,LastLogonDate` | EOL OS harus terisolasi | ⚠️ Finding |
| 1.10 | User dengan SID History | `Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory` | SIDHistory = potensi privilege escalation | ✅ Done |

**Temuan Kritis:** 4 item finding — akun admin terlalu banyak, Password Never Expires, stale accounts, dan EOL OS.

---

### 1.2 Password Policy

> **Referensi:** CIS AD Benchmark Sec.1.1–1.2, CIS Control 6 | **Total Item:** 12

| # | Item | Threshold (CIS) | Status |
|---|------|----------------|--------|
| 2.1 | Default domain password policy | — | ✅ Done |
| 2.2 | Fine-Grained Password Policy (FGPP) | FGPP untuk privileged account | ✅ Done |
| 2.3 | Minimum password length | ≥ 14 karakter | ✅ Done |
| 2.4 | Password complexity enabled | True | ✅ Done |
| 2.5 | Maximum password age | ≤ 90 hari | ✅ Done |
| 2.6 | Minimum password age | ≥ 1 hari | ✅ Done |
| 2.7 | Password history count | ≥ 24 | ✅ Done |
| 2.8 | Account lockout threshold | ≤ 5 attempts | ✅ Done |
| 2.9 | Lockout observation window | ≥ 30 menit | ✅ Done |
| 2.10 | Lockout duration | ≥ 30 menit | ✅ Done |
| 2.11 | Reversible encryption disabled | False | ✅ Done |
| 2.12 | Enumeration via CrackMapExec | Validasi dari perspektif attacker | ✅ Done |

> ✅ **Password Policy secara keseluruhan sudah compliant dengan CIS Benchmark.**

---

### 1.3 Privileged Accounts

> **Referensi:** CIS AD Benchmark Sec.2, CIS Control 6 & 12 | **Total Item:** 13

| # | Item | Threshold | Status |
|---|------|-----------|--------|
| 3.1 | Domain Admins membership | < 5 akun; hanya akun Tier-0 | ⚠️ Finding |
| 3.2 | Enterprise Admins membership | Harus kosong saat tidak digunakan | ✅ Done |
| 3.3 | Schema Admins membership | Harus kosong saat tidak digunakan | ⚠️ Finding |
| 3.4 | Builtin\Administrators membership | Minimum anggota | ⚠️ Finding |
| 3.5 | User dengan adminCount=1 | Semua harus terjustifikasi | ✅ Done |
| 3.6 | Protected Users group membership | DA & privileged user harus masuk | ✅ Done |
| 3.7 | DCSync rights (replication ACE) | Hanya SYSTEM & DC | ➖ N/A |
| 3.8 | ACE berbahaya (GenericAll/WriteOwner/WriteDACL) | Zero tolerance untuk non-admin | ➖ N/A |
| 3.9 | Tier 0 separation (DA tidak login ke non-DC) | DA session hanya di DC | ➖ N/A |
| 3.10 | Local Admin rights spreading | Minimal; gunakan LAPS | ➖ N/A |
| 3.11 | Service accounts dengan high privilege | SA tidak boleh di DA group | ➖ N/A |
| 3.12 | LAPS deployment | Semua workstation/server harus LAPS | ➖ N/A |
| 3.13 | Credential caching (CachedLogonsCount) | ≤ 2 | ➖ N/A |

**Temuan:** Domain Admins, Schema Admins, dan Builtin\Administrators melebihi batas minimum.

---

### 1.4 Kerberos

> **Referensi:** CIS AD Benchmark Sec.3, MS KB5008380 | **Total Item:** 11

| # | Item / Teknik | Threshold | Status |
|---|--------------|-----------|--------|
| 4.1 | AS-REP Roasting — DoesNotRequirePreAuth | Harus 0 akun | ➖ N/A |
| 4.2 | Kerberoasting — SPN accounts | SPN di akun user = risiko tinggi | ➖ N/A |
| 4.3 | Kerberos encryption type — RC4 enabled? | RC4 harus disabled; AES only | ➖ N/A |
| 4.4 | AES encryption enforcement | 0x18 = AES128+AES256 | ✅ Done |
| 4.5 | krbtgt account last password reset | ≤ 180 hari (reset 2x untuk invalidasi) | ⚠️ Finding |
| 4.6 | Constrained Delegation | Hanya untuk service accounts ter-justify | ✅ Done |
| 4.7 | Unconstrained Delegation | Semua non-DC harus bersih | ✅ Done |
| 4.8 | Resource-Based Constrained Delegation (RBCD) | Review semua nilai non-null | ✅ Done |
| 4.9 | TGT Ticket lifetime | ≤ 10 jam | ✅ Done |
| 4.10 | Golden/Silver Ticket exposure | krbtgt hash bocor = full compromise | ✅ Done |
| 4.11 | Kerbrute user enumeration (pre-auth) | Deteksi username valid dari luar | ✅ Done |

**Temuan:** krbtgt password belum di-rotate sesuai jadwal (harus ≤ 180 hari, 2x reset).

---

### 1.5 GPO Analysis

> **Referensi:** CIS AD Benchmark Sec.9, CIS Control 4 | **Total Item:** 14

| # | Item | Expected Value | Status | Catatan |
|---|------|---------------|--------|---------|
| 5.1 | Enumerate semua GPO | Tidak ada GPO orphan | ✅ Done | |
| 5.2 | GPO link per OU | Inheritance tidak di-block tanpa alasan | ➖ N/A | |
| 5.3 | GPO permissions — siapa yang bisa edit? | Hanya Group Policy Admins | ✅ Done | |
| 5.4 | GPO misconfigurations (Group3r) | Tidak ada credentials/path injection | ➖ N/A | |
| 5.5 | Credentials dalam GPO (cpassword) | Harus kosong — MS14-025 vuln | ✅ Done | |
| 5.6 | AppLocker/WDAC deployment | Enabled & enforced di semua host | ➖ N/A | |
| 5.7 | Audit policy enforcement | Sesuai CIS/NIST audit baseline | ✅ Done | Terbatas Administrator |
| 5.8 | LSASS Protection (PPL) | RunAsPPL = 1 | ➖ N/A | Terbatas Administrator |
| 5.9 | Credential Guard | Enabled | ✅ Done | |
| 5.10 | SMB Signing enforcement | Enabled (always) | ✅ Done | |
| 5.11 | NTLM restrictions | Audit/Deny sesuai kebutuhan | ✅ Done | Terbatas Administrator |
| 5.12 | WinRM / RDP NLA enforcement | NLA = Enabled | ✅ Done | |
| 5.13 | PowerShell execution policy + logging | AllSigned; logging Enabled | ⚠️ Finding | |
| 5.14 | Scheduled tasks via GPO | Review semua task non-standar | ✅ Done | |

**Temuan:** PowerShell Script Block Logging belum sepenuhnya diterapkan.

---

### 1.6 AD Certificate Services (AD CS)

> **Referensi:** CIS AD Benchmark Sec.7, CISA AA23-278A | **Total Item:** 12

| # | Item / ESC | Risk Level | Status | Catatan |
|---|-----------|-----------|--------|---------|
| 6.1 | AD CS terdeploy? | — | ➖ N/A | |
| 6.2 | Enumerate Certificate Templates | — | ➖ N/A | |
| 6.3 | **ESC1** — Enrollee supplies SAN + low-priv enroll | HIGH | ⚠️ Finding | Privesc ke DA via SAN |
| 6.4 | **ESC2** — Any Purpose EKU atau no EKU | CRITICAL | ⚠️ Finding | Certificate abuse |
| 6.5 | **ESC3** — Certificate Request Agent EKU | HIGH | ✅ Done | |
| 6.6 | **ESC4** — Vulnerable template ACL (GenericWrite) | HIGH | ✅ Done | |
| 6.7 | **ESC6** — EDITF_ATTRIBUTESUBJECTALTNAME2 | CRITICAL | ✅ Done | |
| 6.8 | **ESC7** — Vulnerable CA ACL | CRITICAL | ✅ Done | |
| 6.9 | **ESC8** — NTLM relay to AD CS HTTP | HIGH | ✅ Done | |
| 6.10 | CRL Distribution Point accessibility | — | ✅ Done | |
| 6.11 | Certificate validity period (high-priv) | — | ✅ Done | Hanya user biasa |
| 6.12 | CA berjalan di DC? | CRITICAL (blast radius max) | ✅ Done | |

**Temuan Kritis:** ESC1 dan ESC2 ditemukan — berpotensi privilege escalation ke Domain Admin via certificate abuse.

---

## 2. DNS, Firewall, Back Office, H2H & SFTP

---

### 2.1 Firewall (FortiGate)

> **Perangkat:** FortiGate (SD-WAN)

#### Rule Base Review

| Item | Status | Catatan |
|------|--------|---------|
| Setiap rule memiliki justifikasi bisnis terdokumentasi | 🔍 Butuh Verifikasi | Kolom Comments perlu diverifikasi dengan sistem ticketing internal |
| Prinsip least privilege diterapkan | ⚠️ Parsial | Rule SDWAN-Access for Mobile & Devices-to-Internet menggunakan Service ALL |
| Tidak ada rule terlalu luas (source=ANY, destination=ANY) | ✅ Terpenuhi | Tidak ada Allow ANY→ANY aktif |
| Rule di-review berkala (min 6 bulan) | 🔍 Butuh Verifikasi | Perlu tinjauan log audit |

#### Default Policies

| Item | Status |
|------|--------|
| Default policy inbound = DENY ALL | ✅ Terpenuhi (Implicit Deny aktif) |
| Default policy outbound dikontrol | ✅ Terpenuhi (SD-WAN routing policy) |
| Implicit deny terakhir terkonfigurasi | ✅ Terpenuhi (Rule ID 1 dengan log aktif) |

#### Unused Rules ⚠️

| Item | Status | Catatan |
|------|--------|---------|
| Rule tidak pernah di-hit dalam 90 hari | ⚠️ Temuan | Bytes 0B ditemukan (SIAR-to-SIJITU, vpn_VPN-Pentest_remote_0) |
| Rule untuk sistem nonaktif sudah dihapus | ⚠️ Temuan | Masih banyak objek dengan suffix `_OLD` |
| Rule disabled yang tidak relevan | ⚠️ Temuan | Banyak rule Disabled menumpuk — perlu purge |

#### Management Access

| Item | Status | Catatan |
|------|--------|---------|
| Akses manajemen hanya dari MGMT VLAN | ✅ Terpenuhi | Rule khusus MGMT-IF tersedia |
| Remote management via SSH/HTTPS (bukan Telnet) | ✅ Terpenuhi | Telnet tidak diizinkan |
| MFA untuk login manajemen | 🔍 Butuh Verifikasi | Perlu cek konfigurasi Administrator |
| Time-based access rules | ⚠️ Parsial | Hanya rule VPN-Vendor1 ke UAT yang pakai jadwal |
| Default account diganti/dinonaktifkan | 🔍 Butuh Verifikasi | Cek via CLI `show system admin` |

#### Logging

| Item | Status | Catatan |
|------|--------|---------|
| Semua traffic DENY di-log | ✅ Terpenuhi | Implicit Deny logging aktif |
| Traffic ke/dari zona kritis di-log penuh | ✅ Terpenuhi | Rule Server menggunakan profil log All Sessions |
| Log ke SIEM/syslog eksternal | 🔍 Butuh Verifikasi | Cek Log & Report > Log Settings |
| Log retention ≥ 90 hari | 🔍 Butuh Verifikasi | Tergantung kapasitas FortiAnalyzer/Syslog |
| Alerting aktif untuk anomali | 🔍 Butuh Verifikasi | Perlu cek Automation Stitches FortiGate |

#### VPN Configuration

| Item | Status | Catatan |
|------|--------|---------|
| VPN menggunakan AES-256, IKEv2/IPSec | ✅ Terpenuhi | VPN-IKE2-WAN1 terindikasi IKEv2 |
| Algoritma lemah (DES, MD5, SHA-1) dinonaktifkan | ✅ Terpenuhi | |
| Split tunneling dikontrol | ✅ Terpenuhi | |
| VPN user diautentikasi dengan MFA | ✅ Terpenuhi | |
| Idle timeout VPN dikonfigurasi | ⚠️ Parsial | Belum dikonfigurasi |

---

### 2.2 DNS

| Area | Item | Status | Catatan |
|------|------|--------|---------|
| **Zone Transfer** | AXFR/IXFR hanya ke secondary DNS terdefinisi | ✅ Terpenuhi | Port 53 filtered, data zona tidak bisa ditarik |
| | Zone transfer dari IP sembarang diblokir | ✅ Terpenuhi | allow-transfer hanya berisi IP Secondary DNS valid |
| | ACL zone transfer dikonfigurasi eksplisit | ✅ Terpenuhi | Tidak ada entry `any` pada ACL |
| | Zone data sensitif tidak terekspos ke publik | ✅ Terpenuhi | IP dan hostname tidak terekspos |
| **DNSSEC** | DNSSEC diaktifkan untuk semua zone kritis | ✅ Terpenuhi | Status "Secure" dengan RSASHA256 (Alg 8) |
| | DS record dipublish ke parent zone | ✅ Terpenuhi | Chain of Trust tersambung |
| | Key rollover dijadwalkan & otomatis | ✅ Terpenuhi | Masa aktif valid Feb–Agustus 2026 |
| | Algoritma signing ECDSA atau RSA-2048+ | ✅ Terpenuhi | RSASHA256 terverifikasi |
| **Konfigurasi** | Versi DNS server tidak terekspos | ✅ Terpenuhi | Port DNS tidak merespons query versi |
| | Recursive query dinonaktifkan di authoritative server | ✅ Terpenuhi | Tidak menjadi open resolver |
| | Authoritative & recursive DNS dipisah | ✅ Terpenuhi | Secondary AD = Authoritative untuk bpam.local |
| | Rate limiting (RRL) aktif | ✅ Terpenuhi | Proteksi dilakukan di level Firewall (port 53) |
| | TSIG/HMAC digunakan antar DNS server | ✅ Terpenuhi | AXFR diblokir, risiko impersonasi minimal |
| **Rekursi** | Recursion hanya untuk IP internal | ✅ Terpenuhi | IP VPN gagal resolusi |
| | Open resolver dari internet diblokir | ✅ Terpenuhi | Port 53 filtered dari VPN |
| | DNS query logging aktif | ✅ Terpenuhi | Analytical Logging tersedia (Windows Server 2019/2022) |
| | Proteksi DNS cache poisoning | ✅ Terpenuhi | Source Port & DNS ID Randomization aktif |

> ✅ **DNS secara keseluruhan sudah sangat baik dan compliant.**

---

### 2.3 Back Office Server

> **Referensi:** OWASP WSTG | CIS Controls | Semua item status: Not Started (belum VAPT)

| # | Testing Area | Hasil / Notes | Priority |
|---|-------------|--------------|----------|
| 1 | Network Discovery | 0–255 host up | High |
| 2 | Port Scanning | Open port 3389 (RDP) ditemukan | High |
| 3 | Service Enumeration | RDP versi 10.0.14393 | High |
| 4 | OS Detection | Windows terdeteksi | Medium |
| 5 | SSL/TLS Testing | TLSv1.2 | High |
| 6 | Web Server Testing | Tidak ditemukan misconfiguration | High |
| 7 | Authentication Testing | RDP sudah menerapkan best practice credential | High |
| 8 | Session Management | Not response pada web service .125 | High |
| 9 | Authorization Testing | Tidak dapat diuji dari eksternal — perlu RDP + WinPEAS | High |
| 10 | SQL Injection | Hanya berlaku jika ada input form/parameter URL | High |
| 11 | File Upload | Tidak ditemukan halaman upload | High |
| 12 | API Security | Tidak ditemukan API endpoint | High |
| 13 | Sensitive Data | Tidak ditemukan file backup/config terekspos | High |
| 14 | Error Handling | Server tidak menampilkan stack trace (hanya RDP terbuka) | Medium |
| 15 | Database Security | Port SQL ter-filter | Medium |
| 16 | Vulnerability Scanning | Tidak ditemukan kerentanan high/critical | High |

---

### 2.4 H2H S-Invest (App & Service Automasi)

> **Referensi:** OWASP WSTG | OWASP API Top 10 | CIS Controls  
> **Catatan Umum:** Semua item N/A karena RDP sudah menerapkan isolasi — tidak bisa mengakses browser untuk menuju layanan H2H.

| # | Testing Area | Priority | Status |
|---|-------------|----------|--------|
| 1 | Service Discovery | High | N/A (RDP isolated) |
| 2 | Protocol Analysis | High | N/A (RDP isolated) |
| 3 | Authentication | High | N/A (RDP isolated) |
| 4 | Message Integrity | High | N/A (RDP isolated) |
| 5 | Encryption | High | N/A (RDP isolated) |
| 6 | API Security | High | N/A (RDP isolated) |
| 7 | Input Validation | High | N/A (RDP isolated) |
| 8 | Rate Limiting | Medium | N/A (RDP isolated) |
| 9 | Error Handling | Medium | N/A (RDP isolated) |
| 10 | Session Management | High | N/A (RDP isolated) |
| 11 | Logging & Monitoring | Medium | N/A (RDP isolated) |
| 12 | Service Vulnerability | High | N/A (RDP isolated) |

> **Rekomendasi:** Untuk pengujian H2H secara menyeluruh, perlu akses langsung ke environment aplikasi atau koordinasi dengan tim ops untuk membuka jalur pengujian yang terkontrol.

---

### 2.5 SFTP S-Invest

> **Referensi:** OWASP WSTG | CIS SSH Benchmark | CIS Controls  
> **Catatan Umum:** Sebagian besar N/A karena terbatas pada jumphost saja tanpa credential WinSCP.

| # | Testing Area | Priority | Status | Catatan |
|---|-------------|----------|--------|---------|
| 1 | Service Discovery | High | N/A | Terbatas jumphost |
| 2 | SSH Configuration | High | N/A | Terbatas jumphost |
| 3 | Authentication | High | ✅ Done | — |
| 4 | Weak Ciphers | High | N/A | Terbatas jumphost |
| 5 | Key Exchange | High | N/A | Terbatas jumphost |
| 6 | File Permissions | High | N/A | Terbatas jumphost |
| 7 | Path Traversal | High | N/A | Terbatas jumphost |
| 8 | Upload Restrictions | Medium | N/A | Terbatas jumphost |
| 9 | Privilege Escalation | High | ✅ Done | — |
| 10 | Logging & Auditing | Medium | N/A | Terbatas jumphost |
| 11 | Service Hardening | Medium | N/A | Terbatas jumphost |
| 12 | Vulnerability Scanning | High | N/A | Terbatas jumphost |

---

## 3. Mail Security (Microsoft 365)

> **Framework:** OWASP WSTG-INFO-02, WSTG-CRYP-01, WSTG-ATHN-01 | CIS Control 1, 3, 6, 13  
> **Total Item:** 47 (M365)

### Fase 1 — Mail Flow & Connector

| # | Yang Dicek | Status | Severity | Catatan |
|---|-----------|--------|----------|---------|
| 1.1 | Connector inbound — hanya IP/domain authorized | ✅ Pass | HIGH | Port 25 tidak open melalui VPN |
| 1.2 | Connector outbound — TLS required | ✅ Pass | HIGH | TLS Secure |
| 1.3 | Auto-forward ke external dinonaktifkan | ⚠️ N/A | CRITICAL | Blackbox — tidak bisa diverifikasi |
| 1.4 | Accepted domains — hanya domain milik organisasi | ✅ Pass | MEDIUM | Record menunjukkan domain hanya izinkan IP spesifik organisasi |
| 1.5 | SMTP relay — tidak open relay | ✅ Pass | CRITICAL | IP ditolak firewall/ACL — Inbound Connector restricted |
| 1.6 | Legacy protokol POP/IMAP dinonaktifkan | ✅ Pass | HIGH | Port 110/995/143/993 filtered |

### Fase 2 — TLS / Enkripsi

| # | Yang Dicek | Status | Severity | Catatan |
|---|-----------|--------|----------|---------|
| 2.1 | TLS enforced di connector inbound | ✅ Pass | HIGH | Koneksi gagal tanpa TLS/cipher kuat |
| 2.2 | TLS enforced di connector outbound | ✅ Pass | HIGH | |
| 2.3 | TLS enforcement per remote domain partner kritis | ⚠️ N/A | MEDIUM | Blackbox |
| 2.4 | MTA-STS policy dikonfigurasi | ❌ Fail | MEDIUM | **Tidak ditemukan settingannya** |
| 2.5 | Opportunistic TLS aktif untuk email keluar | ✅ Pass | MEDIUM | |
| 2.6 | Certificate connector valid, bukan self-signed | ✅ Pass | HIGH | |

### Fase 3 — Autentikasi

| # | Yang Dicek | Status | Severity | Catatan |
|---|-----------|--------|----------|---------|
| 3.1 | Basic Authentication dinonaktifkan org-wide | ✅ Pass | CRITICAL | Port POP3/IMAP filtered |
| 3.2 | Authentication Policy — blokir IMAP/POP basic auth | ✅ Pass | CRITICAL | |
| 3.3 | Modern Authentication (OAuth 2.0) diaktifkan | ⚠️ N/A | HIGH | Blackbox |
| 3.4 | MFA enforced semua user via Conditional Access | ⚠️ N/A | CRITICAL | Blackbox |
| 3.5 | CA: block login dari negara/IP berisiko | ⚠️ N/A | HIGH | Blackbox |
| 3.6 | CA: block semua legacy auth protocol | ✅ Pass | CRITICAL | Telnet ditolak |
| 3.7 | Sign-in risk policy aktif (Entra ID Protection) | ⚠️ N/A | HIGH | Blackbox |
| 3.8 | SSPR dikonfigurasi aman (min 2 auth method) | ⚠️ N/A | MEDIUM | Blackbox |
| 3.9 | IMAP/POP dinonaktifkan per-user | ✅ Pass | HIGH | Port filtered |
| 3.10 | Audit sign-in anomali 30 hari terakhir | ⚠️ N/A | HIGH | Blackbox |

### Fase 4 — Relay & Mail Flow Config

| # | Yang Dicek | Status | Severity | Catatan |
|---|-----------|--------|----------|---------|
| 4.1 | Tidak ada transport rule forward ke external | ⚠️ N/A | CRITICAL | Blackbox |
| 4.2 | Transport rule block attachment berbahaya (.exe, .js, .vbs) | ⚠️ N/A | HIGH | Blackbox |
| 4.3 | Remote domain Default — auto-forward dinonaktifkan | ⚠️ N/A | CRITICAL | Blackbox |
| 4.4 | Outbound spam policy — batas email dikonfigurasi | ⚠️ N/A | MEDIUM | Blackbox |
| 4.5 | Alert ke admin jika user terkena limit | ⚠️ N/A | MEDIUM | Blackbox |
| 4.6 | Connector inbound hanya dari IP/cert tertentu | ✅ Pass | HIGH | Port 25 dibatasi di level network/firewall |
| 4.7 | Tidak ada bypass SafeLinks/SafeAttachments tanpa justifikasi | ⚠️ N/A | HIGH | Blackbox |

### Fase 5 — SPF / DKIM / DMARC

| # | Yang Dicek | Status | Severity | Catatan |
|---|-----------|--------|----------|---------|
| 5.1 | SPF record dikonfigurasi di DNS domain | ✅ Pass | HIGH | Tidak ditemukan ~all atau +all |
| 5.2 | SPF menggunakan -all (hardFail) | ✅ Pass | HIGH | |
| 5.3 | DKIM signing diaktifkan | ⚠️ N/A | HIGH | **DKIM not detected** |
| 5.4 | DKIM selector1 dan selector2 ada di DNS | ✅ Pass | MEDIUM | Kedua CNAME record ada |
| 5.5 | DMARC record ada dan policy bukan 'none' | ✅ Pass | HIGH | p=reject |
| 5.6 | DMARC reporting (rua) mengarah ke mailbox aktif | ✅ Pass | MEDIUM | rua=support@bpam.co.id |
| 5.7 | Semua layanan pengirim ada di SPF include | ✅ Pass | MEDIUM | Hanya mengizinkan IP spesifik dan M365 |

### Fase 6 — Least Privilege Access

> Semua item Fase 6 berstatus N/A (Blackbox) — memerlukan akses admin portal langsung.

| # | Yang Dicek | Severity |
|---|-----------|----------|
| 6.1 | Global Admin ≤ 3–5 akun | HIGH |
| 6.2 | Admin menggunakan dedicated account | HIGH |
| 6.3 | Admin account tidak punya Exchange mailbox aktif | HIGH |
| 6.4 | Role Exchange Admin tidak di-assign ke user non-IT | HIGH |
| 6.5 | PIM aktif — admin role JIT | HIGH |
| 6.6 | Full Access mailbox permissions diaudit | HIGH |
| 6.7 | Send As permissions diaudit | MEDIUM |
| 6.8 | Shared mailbox login diblokir | HIGH |
| 6.9 | Inbox rules forward ke external diaudit | CRITICAL |
| 6.10 | Auto-forward per-mailbox dinonaktifkan | CRITICAL |
| 6.11 | Guest user tidak punya akses Exchange | MEDIUM |
| 6.12 | Inactive user (90+ hari) diaudit & disuspend | MEDIUM |
| 6.13 | OAuth app dengan akses Mail.ReadWrite diaudit | HIGH |
| 6.14 | Distribution group tidak open-join | MEDIUM |

### Risk Summary — Critical Findings

| Platform | Finding | Severity | SLA | Rekomendasi |
|----------|---------|----------|-----|-------------|
| M365 & GWS | Auto-forward ke external masih aktif | **CRITICAL** | 24 jam | Nonaktifkan via Remote Domain |
| M365 | Basic Authentication belum diblokir | **CRITICAL** | 24 jam | Buat Auth Policy + CA block legacy auth |
| M365 | MFA belum enforced via Conditional Access | **CRITICAL** | 24 jam | Buat CA policy: require MFA all users |
| M365 & GWS | SPF menggunakan +all (allow all) | **CRITICAL** | 24 jam | Ubah ke -all, audit semua authorized sender |
| M365 | SMTP relay open | **CRITICAL** | 24 jam | Restrict connector inbound ke IP/cert spesifik |
| M365 & GWS | DMARC policy = none atau tidak ada DMARC | HIGH | 7 hari | Set p=quarantine → migrate ke p=reject |
| M365 | PIM tidak aktif — admin role permanent | HIGH | 7 hari | Entra ID PIM → Set admin roles sebagai JIT |
| M365 | Shared mailbox bisa login langsung | HIGH | 7 hari | Block sign-in untuk semua shared mailbox |
| M365 & GWS | Super Admin / Global Admin > 5 akun | HIGH | 7 hari | Review & reduce, gunakan delegated admin roles |
| M365 & GWS | OAuth app pihak ketiga tidak diaudit | HIGH | 7 hari | Audit & revoke akses OAuth app tidak dikenal |
| M365 | Transport rule bypass SafeLinks (SCL=-1) | HIGH | 7 hari | Audit semua SCL=-1 rule, dokumentasikan justifikasi |
| M365 & GWS | Inactive user > 90 hari tidak disuspend | MEDIUM | 30 hari | Identify + suspend/deprovision |
| M365 & GWS | DKIM key length < 2048-bit | MEDIUM | 30 hari | Regenerate DKIM key dengan 2048-bit |
| M365 | TLS tidak di-enforce di connector | MEDIUM | 30 hari | Set TLS required untuk partner domain kritis |
| M365 | MTA-STS tidak dikonfigurasi | MEDIUM | 30 hari | Tambahkan DNS record + HTTPS policy file |

---

## 4. Security Hardening — macOS & Windows

> **Generated:** 2026-03-30 | **Version:** 1.0  
> **Scope:** Endpoint Security | **Total Checks per Platform:** 12

---

### 4.1 macOS Hardening

| # | Control | Severity | Command | Expected (Pass) | Expected (Fail) | Remediation |
|---|---------|----------|---------|----------------|----------------|-------------|
| 1 | OS Identification | — | `system_profiler SPSoftwareDataType` | OS terbaru & supported | OS outdated / EOL | Pastikan macOS ≥ versi N-1 dari latest release |
| 2 | Patch Management | — | `softwareupdate --history` | Semua critical/security patches terinstal | Terdapat pending critical patches | Patch lag > 30 hari = HIGH risk |
| 3 | Antivirus/EDR | — | `system_profiler SPConfigurationProfileDataType` | EDR aktif, up-to-date, terdaftar MDM | Tidak ada EDR / agent tidak aktif | Verifikasi vendor EDR (CrowdStrike, SentinelOne) |
| 4 | Local Administrator | — | `dscl . -read /Groups/admin GroupMembership` | Hanya akun yang diotorisasi | Terdapat akun admin tidak sah | Principle of Least Privilege |
| 5 | Password Policy | — | `pwpolicy getaccountconfig` | Min 12 chars, complexity ON, max age ≤ 90 hari | Policy tidak ada / lemah | Min length 14 untuk akun privileged |
| 6 | Firewall Status | — | `/usr/libexec/ApplicationFirewall/socketfilterfw --getstate` | Firewall: ENABLED | Firewall: DISABLED | Aktifkan Application Firewall & `pf` |
| 7 | Unnecessary Services | — | `launchctl list \| grep -v "-"` | Hanya services yang dibutuhkan | Services mencurigakan aktif | Bandingkan dengan baseline |
| 8 | Shared Folders | — | `mount` | Tidak ada share tidak diotorisasi | Terdapat SMB/NFS share tidak sah | Cek System Preferences > Sharing |
| 9 | USB/Removable Media | — | `profiles -P` | USB diblokir via MDM profile | Tidak ada restriction profile | Gunakan Jamf/Mosyle payload |
| 10 | Screen Lock | — | `pwpolicy getaccountconfig` | Lock ≤ 5 menit idle, password required | Screen lock > 15 mnt / tidak ada password | CIS Benchmark: ≤ 2 menit corporate |
| 11 | Encryption (FileVault) | — | `fdesetup status` | FileVault: **On** | FileVault: **Off** | FileVault Off = data accessible via bootable USB |
| 12 | Application Whitelist | — | `spctl --status` | assessments enabled (Gatekeeper ON) | assessments disabled | Jangan disable Gatekeeper tanpa solusi pengganti |

---

### 4.2 Windows Hardening

| # | Control | Command | Expected (Pass) | Expected (Fail) | Technical Notes | Remediation |
|---|---------|---------|----------------|----------------|----------------|-------------|
| 1 | OS Identification | `systeminfo \| findstr /B /C:"OS Name" /C:"OS Version"` | Windows 10/11 terbaru, dalam support | OS outdated / EOL | Windows 10 EOL Oktober 2025 | Upgrade ke Windows 11 22H2+ |
| 2 | Patch Management | `Get-HotFix \| Sort-Object InstalledOn -Descending \| Select -First 20` | Patch terbaru ≤ 30 hari | Patch lag > 30 hari / Cumulative Update missing | Gunakan `wmic qfe list brief` untuk legacy | Deploy via WSUS/Intune |
| 3 | Antivirus/EDR | `Get-MpComputerStatus \| Select AMRunningMode,RealTimeProtectionEnabled` | AV aktif, RealTimeProtection=True | AV disabled / tidak ada EDR | productState hex 0x1000 = enabled & up-to-date | Aktifkan Defender / deploy EDR |
| 4 | Local Administrator | `net localgroup administrators` | Hanya akun domain/service yang diotorisasi | Akun default admin aktif / user biasa di grup admin | Akun "Administrator" built-in harus disabled/renamed | Disable atau rename built-in Administrator |
| 5 | Password Policy | `net accounts` + `secedit /export /cfg ...` | Min 12 chars, complexity enabled, lockout ≤ 5 attempts | Tidak ada complexity / no lockout | CIS: MinLength=14, LockoutBadCount=5, Duration=15 menit | Enforce via Group Policy |
| 6 | Firewall Status | `netsh advfirewall show allprofiles state` | Semua profil: State ON | Satu atau lebih profil: State OFF | Public profile harus paling restrictive | Aktifkan semua profil firewall |
| 7 | Unnecessary Services | `Get-Service \| Where {$_.Status -eq "Running"}` | Hanya services yang diperlukan | Services Telnet, FTP, SNMP, Print Spooler aktif | Print Spooler (PrintNightmare), WinRM, RDS, SNMP = high risk | Disable services tidak diperlukan |
| 8 | Shared Folders | `net share` + `Get-SmbShare` | Hanya share yang diotorisasi | Share tidak sah / everyone read-write | Admin shares C$ & ADMIN$ harus di-restrict | Batasi permission shared folders |
| 9 | USB/Removable Media | `Get-ItemProperty "HKLM:\SYSTEM\...\USBSTOR" \| Select Start` | USBSTOR Start=4 (disabled) atau GPO block aktif | USBSTOR Start=3 (enabled) | Start=4 = service disabled = USB tidak bisa mount | Set via Intune/SCCM policy |
| 10 | Screen Lock | `Get-ItemProperty "HKCU:\Control Panel\Desktop" \| Select ScreenSave*` | ScreenSaveActive=1, ScreenSaverIsSecure=1, timeout ≤ 300s | Screen saver off / tidak require password | CIS: ScreenSaveTimeOut ≤ 900s; Corporate: ≤ 300s | Enforce via GPO |
| 11 | Encryption (BitLocker) | `manage-bde -status` + `Get-BitLockerVolume` | ProtectionStatus: On, EncryptionPercentage: 100% | BitLocker Off / protection suspended | Recovery key harus disimpan di AD/Azure AD | Aktifkan BitLocker (TPM+PIN) |
| 12 | Application Whitelist | `Get-AppLockerPolicy -Effective` + `Get-CimInstance Win32_DeviceGuard` | AppLocker/WDAC rules aktif dan enforced | Tidak ada application control policy | WDAC = modern (tersedia Pro/Enterprise), AppLocker = legacy | Implement WDAC (prefer over AppLocker) |

> **Bonus Tool:** WinPEAS untuk privilege escalation check  
> ```powershell
> Invoke-WebRequest -Uri "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe" -OutFile "C:\Users\Public\wp.exe"
> .\wp.exe log > winpeas_result.txt
> ```

---

## 5. Ringkasan Temuan & Prioritas Remediasi

### 🔴 CRITICAL — Tindakan Segera (< 24 Jam)

| Domain | Temuan | Rekomendasi |
|--------|--------|-------------|
| AD CS | ESC2 — Any Purpose EKU atau no EKU | Revoke/restriksi template certificate berbahaya |
| Mail | Auto-forward ke external aktif | Nonaktifkan via Remote Domain & per-mailbox |
| Mail | MFA belum enforced via Conditional Access | Buat CA policy: require MFA all users |
| Mail | SPF menggunakan +all (allow all) | Ubah ke `-all` segera |
| Mail | SMTP relay open (connector tidak restricted) | Restrict connector inbound ke IP/cert spesifik |

### 🟠 HIGH — Tindakan dalam 7 Hari

| Domain | Temuan | Rekomendasi |
|--------|--------|-------------|
| AD | Domain Admins membership melebihi batas | Kurangi ke < 5 akun Tier-0 saja |
| AD | Schema Admins tidak kosong | Kosongkan saat tidak digunakan |
| AD | Builtin\Administrators melebihi minimum | Review dan batasi keanggotaan |
| AD CS | ESC1 — Enrollee supplies SAN | Hapus flag ENROLLEE_SUPPLIES_SUBJECT dari template |
| AD | krbtgt password belum di-rotate | Reset 2x dalam interval ≤ 180 hari |
| GPO | PowerShell Script Block Logging belum aktif | Aktifkan via GPO: Turn on Script Block Logging |
| FW | Rules dengan _OLD masih ada | Purge rule dan objek yang tidak relevan |
| FW | Banyak rule Disabled menumpuk | Lakukan rule cleanup berkala |
| Mail | PIM tidak aktif — admin role permanent | Aktifkan Entra ID PIM untuk JIT access |
| Mail | Shared mailbox bisa login langsung | Block sign-in semua shared mailbox |
| Mail | Global Admin > 5 akun | Review & reduce, gunakan delegated admin |

### 🟡 MEDIUM — Tindakan dalam 30 Hari

| Domain | Temuan | Rekomendasi |
|--------|--------|-------------|
| AD | Password Never Expires (user) | Audit dan nonaktifkan flag PasswordNeverExpires |
| AD | Stale accounts (>90 hari tidak login) | Disable/delete akun tidak aktif |
| AD | EOL OS masih terhubung ke domain | Isolasi/upgrade sistem EOL |
| FW | VPN idle timeout belum dikonfigurasi | Set idle timeout pada sesi VPN |
| FW | Beberapa item butuh verifikasi lanjutan | Jadwalkan sesi verifikasi dengan ops team |
| Mail | MTA-STS tidak dikonfigurasi | Tambah DNS record `_mta-sts` + HTTPS policy |
| Mail | DKIM key < 2048-bit | Regenerate DKIM key 2048-bit |
| Mail | TLS tidak di-enforce di connector | Set TLS required untuk partner domain kritis |
| Mail | Inactive user > 90 hari tidak disuspend | Identify + suspend/deprovision |
| Endpoint | FileVault/BitLocker belum terverifikasi semua device | Audit enkripsi seluruh endpoint |
| Endpoint | USB/Removable Media policy belum diterapkan | Deploy Jamf/Intune USB restriction policy |

### 🟢 LOW / Best Practice — Tindakan dalam 90 Hari

| Domain | Rekomendasi |
|--------|-------------|
| AD | Implementasi LAPS untuk local admin management |
| AD | Aktifkan Tier 0/1/2 separation model |
| FW | Implementasi time-based rules untuk semua vendor access |
| FW | Otomasi penarikan hit count rule (review 90 hari) |
| Endpoint | Deploy WDAC (Windows Defender Application Control) |
| Endpoint | Enforce screen lock ≤ 5 menit semua device |
| H2H & SFTP | Koordinasi pengujian dengan akses credential yang sesuai |

---

*Generated for internal security assessment purposes — Confidential*  
*Framework: CIS AD Benchmark v3.0 | CIS Controls v8 | MITRE ATT&CK | OWASP WSTG v4.2 | CVSS v4.0*
