---

## ⚠️ Beyond the Checklist — Cross-Domain Attack Chains

> *"Bad checklists treat domains as silos. The real risk is in the connections."*

This checklist covers individual domains (AD, DNS, Firewall, Mail, Endpoint) as separate sections by design — it makes the assessment structured and trackable. But **real-world risk doesn't respect domain boundaries.**

A finding rated MEDIUM in isolation can become catastrophic when chained with findings from other domains.

### Example — 4 Medium/High findings → Full domain compromise

| Step | Finding | Domain | Severity (alone) |
|------|---------|--------|-----------------|
| 1 | Stale account, `adminCount=1`, password never expires | AD | MEDIUM |
| 2 | Legacy auth (POP3) open, auto-forward enabled, no MFA | Mail | HIGH |
| 3 | BitLocker off, user in local Administrators group | Endpoint | MEDIUM |
| 4 | ADCS ESC1 — low-priv user can supply SAN in cert request | AD CS | HIGH |

**The chain:**
1. Attacker password-sprays the stale AD account via POP3 — no lockout, no MFA
2. Gains mailbox access → harvests credentials from email → auto-forward silently exfiltrates
3. Uses harvested creds to RDP into unencrypted endpoint → credential dump (Mimikatz) → local admin escalation
4. Uses domain user creds + ESC1 to forge a Domain Admin certificate → **Golden Ticket → full environment compromise**

None of these findings are individually labelled CRITICAL. Combined, they represent **total loss of the environment.**

---

### How to use this checklist with attack path thinking

After completing each domain section, **cross-reference your findings** across domains by asking:

- **Access + Auth**: Which accounts appear in both AD findings *and* Mail findings? A user with `adminCount=1` who also has legacy auth enabled is a single point of full compromise.
- **Endpoint + Credential exposure**: Any endpoint finding (BitLocker off, local admin, no EDR) combined with AD privileged account findings dramatically increases credential harvesting risk.
- **ADCS + AD Privilege**: ESC misconfigurations are only exploitable if a threat actor has domain user access — cross-reference against stale/low-hygiene accounts.
- **Firewall + Mail + VPN**: Unused rules or overly permissive VPN access combined with weak mail auth creates lateral movement paths that bypass perimeter defenses.

### Recommended: prioritize by attack path, not just severity

When writing findings for stakeholders, group items by the **worst-case chain they enable**, not just by individual CVSS score. A report that says "4 medium findings" is less actionable than one that says "these 4 findings form a path to Domain Admin."

Tools that support this kind of path analysis:
- **BloodHound** — visualises shortest attack paths to DA in AD environments
- **MITRE ATT&CK Navigator** — maps findings to adversary techniques and shows tactic-level chains
- **PlexTrac / Vectr** — for chaining findings into narrative attack scenarios in reports

---

*This section was added in response to community feedback. Contributions and additional chain examples welcome via PR.*
