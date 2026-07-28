# Part 08: Incident Response / Threat Hunting / Reporting / Specialized Domains

> Final section — incident response, threat hunting, reporting,
> and specialized domains (credential theft, OT/ICS, IoT, mobile).
> Tools: Sigma, Splunk, Elastic, KQL, MITRE ATT&CK, Volatility 3,
> Velociraptor, and MVT.

---

## 8.1 Incident Response (NIST SP 800-61r3)

### Lifecycle

NIST SP 800-61r3 integrates incident response across the six concurrent and
continuous NIST Cybersecurity Framework 2.0 Functions instead of treating it as
an isolated, linear process.

| CSF 2.0 Function | Incident-response outcome |
|------------------|---------------------------|
| **Govern** | establish policy, authority, roles, risk criteria, and suppliers |
| **Identify** | understand assets, dependencies, vulnerabilities, and risk |
| **Protect** | apply safeguards and prepare resilient technology and people |
| **Detect** | monitor, analyze, validate, and scope adverse events |
| **Respond** | manage, contain, eradicate, communicate, and preserve evidence |
| **Recover** | restore safely, verify integrity, communicate, and improve |

Lessons should be captured and applied throughout response and recovery rather
than waiting for a final post-incident phase.

### Containment vs Evidence Preservation

Containment and evidence preservation are risk decisions, not a fixed sequence.
Network isolation usually preserves RAM, while shutdown destroys volatile
state. If continued compromise creates unacceptable harm, contain immediately.
When authorized and safe, capture volatile evidence before shutdown, preserve
disk or cloud snapshots before rebuild, and document the decision, timing, and
side effects.

### Communication & Legal Obligations

- **Breach notification**: consult qualified counsel; duties and deadlines
  depend on jurisdiction, data type, contracts, and the facts of the incident
- **Privilege**: let counsel define communications and workstreams intended to
  receive legal protection; labels alone do not create privilege
- **Law enforcement**: coordinate through counsel and approved leadership
- **Insurance**: follow the policy's notice, vendor, consent, and preservation
  requirements

## 8.2 Threat Hunting

### MITRE ATT&CK-Driven Hunting

```
1. Start from Tactic (e.g., TA0008 Lateral Movement)
2. Look at Technique (T1021 Remote Services)
3. Find telemetry indicating it (Event ID 4624 Type 3, 4672)
4. Form hypothesis: "Is there RDP lateral movement?"
5. Check logs
6. Found → analyze, not found → expand scope
```

### Pyramid of Pain

```
        TTPs ( hardest for attacker to change )
         Tools
       Infrastructure (domains, IPs)
         Network/Host artifacts
          Hash values ( easiest to change )

Rule: higher = more painful for attacker
```

### Sigma Rules

```yaml
title: PowerShell Encoded Command
id: 9bdc52b1-1f2c-4e85-9c33-ae4a0d842d6f
status: experimental
description: Detects PowerShell script content associated with encoded commands
references:
  - https://attack.mitre.org/techniques/T1059/001/
author: dfir-handbook
date: 2026-07-28
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - 'FromBase64String'
      - 'encodedcommand'
      - 'iex'
  condition: selection
falsepositives:
  - 'Legitimate admin scripts'
level: high
tags:
  - attack.execution
  - attack.t1059.001
```

### Converting Sigma → Query

```bash
# List and install the maintained pySigma backend for your SIEM
sigma plugin list -t backend
sigma plugin install splunk

# Convert a rule; select and test an environment-specific pipeline
sigma convert -t splunk rule.yml
```

### Detection Tuning

- **Baselining**: learn normal behavior first
- **False positive reduction**: whitelist known-good
- **Context enrichment**: correlate with threat intel
- **Iterative**: adjust rules per results

### Purple Teaming

```
Blue (defense) + Red (attack) work together:
1. Red simulates attack (per MITRE)
2. Blue checks if detected
3. Close gaps found
4. Repeat
```

## 8.3 Reporting

### Report Structure

```
1. EXECUTIVE SUMMARY (for executives)
   - What happened (2-3 sentences)
   - Business impact
   - Recommendation

2. INCIDENT OVERVIEW
   - Detection date/time
   - Severity
   - Affected systems/data

3. TIMELINE (most important)
   - Detection → Containment → Eradication → Recovery
   - ISO 8601 timestamps

4. TECHNICAL ANALYSIS
   - Attack vector
   - TTPs (MITRE mapping)
   - IOCs

5. IOC TABLE
   | Type | Value | Context |
   |------|-------|---------|
   | IP | 203.0.113.42 | simulated C2 server (documentation range) |
   | Hash | `<full SHA-256>` | Dropped malware |
   | Domain | evil.example.net | C2 domain |

6. MITRE ATT&CK MAP
   | Tactic | Technique | Evidence |
   |--------|-----------|----------|
   | TA0001 | T1190 Exploit Public App | Web logs |

7. RECOMMENDATIONS
   - Patch X
   - Enable Y logging
   - Reset credentials

8. APPENDIX
   - Full timeline
   - Chain of custody
   - Commands, tool versions, and validation records
```

### Expert Testimony

```
Principles (subject to the applicable jurisdiction and instructions of counsel):
1. Use understandable language (avoid excessive jargon)
2. Cite standards (NIST, ISO)
3. Explain methodology (Daubert: tested, error rate)
4. Show complete chain of custody
5. Acknowledge limitations of your method
6. Don't exceed available data
```

## 8.4 Specialized: Credential Theft & Lateral Movement

### LSASS Access

```
Event ID 4624 Type 3 + 4672 → logon
Event ID 4768/4769 → Kerberos

LSASS access indicators:
  - OpenProcess on lsass.exe with PROCESS_VM_READ
  - Sysmon Event ID 10 (ProcessAccess) → TargetImage: lsass.exe
  - API call: MiniDump / ReadProcessMemory
```

### Pass-the-Hash (PtH)

```
- Authentication uses an NTLM credential hash rather than the plaintext secret
- Possible telemetry includes 4624 Logon Type 3 with NtLmSsp
```

These fields also occur during legitimate NTLM authentication. Correlate source
host, account behavior, endpoint telemetry, administrative shares, services,
and normal authentication patterns.

### Pass-the-Ticket (PtT)

```
- Authentication reuses or injects a Kerberos ticket
- A 4769 service-ticket event without a nearby 4768 can be a lead
```

The TGT request may be outside the retained window or recorded by another
domain controller. Treat this sequence as a hypothesis, not proof.

### DCSync

```
- Attacker uses replication permission to copy AD database
- Event ID 4662 (Directory Service Access) with GUID DRSGetNCChanges
- dsaccess audit must be enabled
```

### Golden / Silver Ticket

```
Golden: forged TGT (using krbtgt hash)
Silver: forged service ticket (using service account hash)

Detection:
- unusual ticket encryption, lifetime, account, service, source, or domain
- service-ticket activity without supporting authentication telemetry
- endpoint evidence of ticket access or injection
```

### RDP / PsExec / WMI Artifacts

| Technique | Event IDs | Network |
|-----------|-----------|---------|
| **RDP** | 4624 Type 10, 21/24/25 (RDP) | TCP 3389 |
| **PsExec** | 7045 (service), 4624 Type 3 | TCP 445 |
| **WMI** | 4624 Type 3, 4688 (wmiprvse) | TCP 135/445 |

## 8.5 Anti-Forensics Detection

| Technique | Detectable from |
|-----------|-----------------|
| **Timestomping** | timestamp inconsistencies corroborated with journals and logs |
| **Log clearing** | Event ID 1102 plus service, process, and retention context |
| **Journal deletion** | journal reset or deletion evidence and filesystem metadata |
| **File wiping** | overwrite patterns, tool artifacts, filesystem and storage telemetry |
| **Process hiding** | cross-view memory discrepancies with structure validation |

Each item is an investigative lead. Normal maintenance, retention, corruption,
and acquisition limitations can produce similar observations.

## 8.6 OT/ICS Forensics

### Purdue Model

```
Level 5: Enterprise (business network)
Level 4: Site business & logistics
Level 3: Site operations (MES)
Level 2: Supervisory (SCADA/HMI)
Level 1: Basic control (PLC/RTU)
Level 0: Process (sensors/actuators)
```

### PLCs & Historians

```
PLC: Programmable Logic Controller — controls physical process
SCADA: Supervisory Control and Data Acquisition
Historian: stores time-series data (e.g., PI System)

Evidence collection:
- Coordinate with the control-system owner and safety authority
- Prefer passive network, historian, engineering-station, and existing backup data
- Use vendor-approved procedures before reading logic from a live controller
- Export historian data
- Capture network traffic only from an approved monitoring point
```

### OT Protocol Dissectors (Wireshark)

```
Modbus   — Function codes, register addresses
DNP3     — Objects, points
ENIP/CIP — Ethernet/IP
IEC 60870-5-104 — Telecontrol
```

## 8.7 IoT / Embedded Forensics

### Firmware Extraction

```bash
# Use binwalk
binwalk -e firmware.bin        # extract filesystems
binwalk -M firmware.bin        # recursive

# Find signatures
binwalk firmware.bin

# Extract with dd
dd if=firmware.bin of=rootfs.squashfs bs=1 skip=<offset>
```

Treat firmware and extractor helpers as untrusted. Run extraction in an
isolated, disposable environment and review the installed binwalk version and
extractor behavior before enabling recursive extraction.

### Hardware Interfaces

```
- UART (serial): GND, TX, RX, VCC
- SPI: flash chip read/write
- JTAG: debug interface
- NAND/NOR: raw flash
- SD card: easy extraction
```

### BusyBox / Embedded Linux

```bash
# Find busybox
strings firmware.bin | grep busybox

# View filesystem (after binwalk extract)
ls -la _firmware.bin.extracted/squashfs-root/
```

## 8.8 Mobile Forensics Primer

### iOS / Android Artifacts

| Platform | Possible sources | Key artifacts |
|----------|------------------|---------------|
| **iOS** | encrypted backup, filesystem acquisition, sysdiagnose | messages, calls, locations, app and system records |
| **Android** | vendor backup, filesystem acquisition, bugreport, AndroidQF | messages, calls, app data, accounts, Wi-Fi, system records |

Available acquisition methods depend on device model, OS build, lock state,
authorization, tooling, and current exploit support. Do not jailbreak, root,
unlock, or chip-off a device without an approved method and qualified examiner.

### Acquisition Types

```
AFU (After First Unlock) — more protected data may be available
BFU (Before First Unlock) — more protected data remains inaccessible
```

Preserving AFU state may increase evidence availability but also creates remote
wipe, network, power, and state-change risks. Follow the approved mobile
handling procedure and document isolation and power decisions.

### MVT (Mobile Verification Toolkit)

```bash
# Install in an isolated application environment
pipx install mvt

# Analyze an AndroidQF acquisition
mvt-android check-androidqf /evidence/androidqf-output/

# Analyze an iOS backup
mvt-ios check-backup --output /evidence/mvt/ /evidence/ios-backup/
```

MVT is a focused mobile-compromise triage toolkit, not a complete mobile
forensics suite. Public indicators alone can miss recent or unknown activity.

---

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 8 Summary

This chapter covers NIST SP 800-61r3-aligned incident response, threat hunting,
Sigma, reporting, credential theft, anti-forensics, OT/ICS, IoT, and mobile
forensics.
