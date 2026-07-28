# Digital Forensics Incident Report

> **Fictional training example.** All organizations, hosts, accounts, domains,
> IP addresses, hashes, and events in this report are synthetic. They are not
> production indicators of compromise and must not be added to blocklists.

## Case: IR-2026-07-28-001 — Ransomware on wkstn-023.corp.example

---

## 1. Executive Summary

| Field | Value |
|-------|-------|
| Incident date | 2026-07-28 |
| Affected system | wkstn-023.corp.example (Windows 11) |
| Incident type | Simulated ransomware |
| Severity | High |
| Status | Contained; recovery complete |

At 05:47 UTC, the SOC received an endpoint alert for suspicious access to
`lsass.exe` on `wkstn-023.corp.example`. Investigation found that the user had
opened a macro-enabled attachment at 04:12 UTC. The resulting PowerShell process
downloaded a payload from a documentation-only host and later encrypted files
on the workstation.

The attacker attempted to authenticate to `db01.corp.example`, but the attempt
was denied and no execution or persistence was observed on that server. No
evidence of data exfiltration was identified within the available telemetry.

**Impact assessment:**

- approximately 125 GB of workstation data encrypted;
- workstation unavailable for four hours;
- attempted lateral movement blocked;
- no confirmed compromise of another system; and
- no confirmed data exfiltration.

**Priority recommendations:**

1. reset credentials exposed to the workstation;
2. preserve and validate endpoint, identity, email, and network evidence;
3. strengthen email attachment controls and PowerShell logging; and
4. review segmentation and service-account privileges.

---

## 2. Incident Overview

| Item | Detail |
|------|--------|
| Detection time | 2026-07-28 05:47 UTC |
| Severity | High |
| Confirmed compromised systems | wkstn-023.corp.example |
| Systems with blocked attempts | db01.corp.example |
| Affected data | Approximately 125 GB encrypted locally |
| Initial access vector | Spearphishing attachment |
| Malware classification | Simulated ransomware; family not attributed |
| Simulated infrastructure | 203.0.113.42 and payload.corp.example |

`203.0.113.42` is part of TEST-NET-3, reserved for documentation. The
`.example` namespace is also reserved for examples.

---

## 3. Timeline

| Timestamp (UTC) | Event | Source |
|-----------------|-------|--------|
| 04:12:33 | User opened `Invoice.docm` | Email and endpoint telemetry |
| 04:13:01 | Word spawned PowerShell with an encoded command | Sysmon Event ID 1 |
| 04:13:15 | PowerShell contacted `203.0.113.42` | Proxy and Sysmon Event ID 3 |
| 04:14:22 | Payload executed in the user context | Sysmon Event ID 1 |
| 04:15:00 | Process requested access to `lsass.exe` | Sysmon Event ID 10 |
| 04:20:15 | Network logon attempt to `db01` was denied | Security Event ID 4625 |
| 05:30:00 | Rapid file modifications and extension changes began | EDR telemetry |
| 05:47:12 | EDR generated a high-severity alert | EDR |
| 05:47:30 | Network isolation of `wkstn-023` completed | NAC |
| 06:15:00 | Memory and disk evidence acquired | IR case log |
| 08:30:00 | Workstation rebuilt and restored from a known-good backup | IR case log |

---

## 4. Technical Analysis

### 4.1 Initial Access (T1566.001)

The user received a macro-enabled document from
`invoices@billing.corp.example`. When opened, the document launched PowerShell
and retrieved a payload from
`http://payload.corp.example/training/payload.ps1`.

**Evidence:**

- original message and attachment preserved from the mail system;
- parent-child process relationship from Word to PowerShell;
- proxy request to the simulated payload host; and
- file creation correlated with endpoint telemetry.

### 4.2 Credential Access Attempt (T1003.001)

A process requested access to `lsass.exe`. This is consistent with attempted
credential dumping, but the event alone does not identify a specific tool or
prove that credentials were successfully extracted.

**Evidence:**

- Sysmon Event ID 10 targeting `lsass.exe`;
- correlated endpoint alert; and
- no standalone LSASS dump recovered.

### 4.3 Attempted Lateral Movement (T1021.002)

The compromised workstation attempted a network logon to
`db01.corp.example`. Authentication failed, and no remote service creation,
process execution, or persistence was observed on the target.

**Evidence:**

- Security Event ID 4625 on `db01`;
- corresponding firewall connection record; and
- no Event ID 7045 or corroborating process telemetry on `db01`.

### 4.4 Impact (T1486)

The payload modified user-accessible files at high speed and appended the
`.training-locked` extension. The device was isolated before mapped network
shares were affected.

**Evidence:**

- EDR file-modification telemetry;
- ransom-note artifact named `TRAINING_READ_ME.txt`; and
- restored files validated against backup metadata.

---

## 5. Synthetic Indicator Table

| Type | Synthetic value | Context | Confidence |
|------|-----------------|---------|------------|
| IP | 203.0.113.42 | Documentation-only simulated server | High |
| Domain | payload.corp.example | Reserved example namespace | High |
| URL | `http://payload.corp.example/training/payload.ps1` | Simulated download | High |
| SHA-256 | `0000000000000000000000000000000000000000000000000000000000000000` | Placeholder, not a file hash | N/A |
| Email | `invoices@billing.corp.example` | Synthetic sender | High |
| Extension | `.training-locked` | Simulated encrypted files | High |

These values exist only to demonstrate report structure. They are not threat
intelligence and must not be operationalized.

---

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | Supporting evidence |
|--------|-----------|---------------------|
| Initial Access | T1566.001 — Spearphishing Attachment | Message and `.docm` attachment |
| Execution | T1059.001 — PowerShell | Sysmon Event ID 1 |
| Credential Access | T1003.001 — LSASS Memory | Attempted access; success unconfirmed |
| Lateral Movement | T1021.002 — SMB/Windows Admin Shares | Failed network logon attempt |
| Impact | T1486 — Data Encrypted for Impact | File changes and ransom note |

Techniques are mapped only when supported by evidence. Absence of evidence is
documented as a limitation, not mapped as attacker activity.

---

## 7. Recommendations

### Immediate

1. Reset credentials that were used or cached on the compromised workstation.
2. Preserve endpoint, identity, proxy, DNS, and email evidence.
3. Hunt for the documented behavior across the confirmed incident window.
4. Verify that backups are isolated, current, and restorable.

### Short Term

1. Review macro and attachment controls.
2. Enable and centralize PowerShell Script Block Logging where appropriate.
3. Tune endpoint detections for suspicious LSASS access using local baselines.
4. Restrict administrative shares and service-account logon rights.

### Long Term

1. Exercise ransomware and evidence-preservation playbooks.
2. Improve segmentation between workstations and critical servers.
3. Test restoration and business-continuity procedures regularly.
4. Track remediation owners, due dates, and validation evidence.

---

## 8. Evidence and Chain of Custody

| Evidence ID | Description | SHA-256 | Custodian | Status |
|-------------|-------------|---------|-----------|--------|
| EVID-001 | Disk image of `wkstn-023` | Recorded in case system | IR Team | Secured |
| EVID-002 | Memory image of `wkstn-023` | Recorded in case system | IR Team | Secured |
| EVID-003 | Original email and attachment | Recorded in case system | Email Team | Secured |
| EVID-004 | EDR and proxy exports | Recorded in case system | SOC | Secured |

Full cryptographic hashes belong in the evidence-management system and its
exported chain-of-custody record. Do not abbreviate hashes in an operational
report.

---

## 9. Limitations

- Endpoint telemetry does not prove successful credential extraction.
- Available network telemetry cannot establish that no exfiltration occurred;
  it supports only the narrower conclusion that none was identified.
- Malware-family attribution was not performed for this training scenario.

---

*Prepared by: Example DFIR Team*

*Date: 2026-07-28*

*Classification: Fictional training material*
