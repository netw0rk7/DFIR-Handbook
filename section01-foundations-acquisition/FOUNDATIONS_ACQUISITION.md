# Part 01: Foundations & Evidence Handling + Acquisition

> Foundational principles of digital forensics, evidence handling, and acquisition techniques.
> References: NIST SP 800-86, RFC 3227, Locard's Exchange Principle.

---

## 1.1 Locard's Principle (Exchange of Evidence)

> "Every contact leaves a trace" — every interaction between attacker and machine leaves mutual traces.

In the digital realm, interactions often create traces on multiple systems, but
collection gaps, retention, encryption, and anti-forensics can destroy or hide
them.

- Malware may create traces in the Registry, event logs, Prefetch, or EDR data
- File deletion may leave MFT, journal, or unallocated-space artifacts
- Network activity may be recorded in endpoint, DNS, proxy, firewall, or flow data

**Reporting note:** distinguish “not identified in the examined sources” from
“did not occur,” and state the scope and limitations of the examination.

## 1.2 The Forensic Method

```
IDENTIFY → COLLECT → PRESERVE → EXAMINE → ANALYZE → REPORT
```

| Phase | Action | Tools/Technique |
|-------|--------|-----------------|
| **Identify** | Identify relevant data sources (machines, servers, network, cloud) | asset inventory, data flow diagram |
| **Collect** | Acquire evidence systematically | dd, dc3dd, FTK Imager, Velociraptor |
| **Preserve** | Prevent alteration — write-block, hash, chain of custody | write-blocker, sha256sum |
| **Examine** | Process evidence technically (automated + manual) | Sleuth Kit, RegRipper, Volatility |
| **Analyze** | Derive information answering investigative questions | timeline, correlation, ATT&CK mapping |
| **Report** | Produce a reproducible technical and business report | methods, limitations, timeline, findings |

**Important:** these steps are not always sequential — in IR we often do collect + examine + analyze in parallel.

## 1.3 Legal Authority & Admissibility

### Sources of Authority

| Source | When to use | What to do |
|--------|-------------|------------|
| **Legal process** | Access is compelled by an authorized authority | Coordinate with counsel and law enforcement |
| **Consent** | An authorized party voluntarily permits access | Document scope, authority, and any limits |
| **Corporate authority** | The organization investigates systems or accounts | Confirm ownership, policy, contracts, privacy, and local law |
| **Incident-response mandate** | Emergency action is authorized by an approved plan | Record the decision, scope, and approving authority |

### Court Admissibility

In the United States, Daubert or Frye may be relevant depending on the court
and type of testimony. Other jurisdictions use different rules. Tool choice
alone does not establish admissibility; legal authority, relevance,
authentication, method validation, examiner competence, and chain of custody
can all matter. Consult qualified counsel for the matter and jurisdiction.

**Tip:** use well-known tools (Sleuth Kit, Volatility, FTK) and record version + method in the report.

## 1.4 Chain of Custody

> Document every transfer, access, and analysis — never leave a gap.

### Transfer Log Format

```
Timestamp, Actor, Action, Target, SHA256, Notes
2026-07-28T06:00:00Z, analyst-01, ACQUIRED, host-01/disk.img, <full-sha256>, initial image
2026-07-28T06:05:00Z, analyst-01, VERIFIED, host-01/disk.img, <full-sha256>, verification passed
```

### Chain of Custody Form Template

```
CASE ID: IR-2026-07-28-001
EVIDENCE ID: host-01-disk-img-001
DESCRIPTION: Full raw disk image of host-01
COLLECTED BY: analyst-01
DATE/TIME: 2026-07-28T06:00:00Z
LOCATION: /evidence/host-01/disk.img
HASH (SHA256): <full-sha256>
STORAGE: encrypted NAS, access restricted to IR team
```

Use the hashing and acquisition commands below directly, and capture their
versions, command lines, timestamps, and output in the case record.

## 1.5 Hashing & Integrity

### Why Hash?

- Detects whether compared bytes changed between recorded verification points
- Acts as a fingerprint of a file (like DNA)
- Verifies two files are identical (e.g., same sample)

### Algorithms

| Algorithm | Size | When to use | Limitation |
|-----------|------|-------------|-----------|
| **MD5** | 128-bit | quick comparison (legacy) | collisions exist — not primary |
| **SHA-1** | 160-bit | legacy | collisions exist — not primary |
| **SHA-256** | 256-bit | **current standard** | secure |
| **SHA-3** | variable | newer | less supported |

### Real Commands

```bash
# hash a single file
sha256sum disk.img

# hash multiple files without hashing the manifest as it is written
(cd /evidence && find . -type f ! -name hashes.sha256 -print0 |
  sort -z | xargs -0 sha256sum > hashes.sha256)

# verify
sha256sum -c hashes.sha256

# MD5 (comparison only)
md5sum disk.img
```

### About salted hashes

- **Not** related to forensic hashing — we hash the entire file
- Salted hashes are for **password storage** (e.g., /etc/shadow) — unrelated to acquisition

## 1.6 Order of Volatility

> Reference: NIST SP 800-86 §3, RFC 3227

```
1. Memory (RAM) — lost immediately on power loss
2. Network (connections, ARP, routing) — lost on disconnect
3. Open files / handles — lost when process stops
4. Disk files — persist
5. Storage media (tape, optical) — persist longest
```

**Decision rule:** prioritize volatile collection when authorized, feasible,
and safe, but do not delay urgent containment when continued compromise creates
greater risk. Document the tradeoff and every state-changing action.

## 1.7 Acquisition

### Live vs. Dead Acquisition

| Type | When to use | Pros | Cons |
|------|-------------|------|------|
| **Live** | system still running | get RAM, network, processes | risk of alteration, incomplete |
| **Dead** | system off / disk removed | more stable, write-blockable source | volatile data lost; encryption and hardware errors may limit access |

**Approach:** choose live, dead, or both based on authority, encryption state,
business risk, volatility, evidence value, and the approved response plan.

### Disk Imaging Tools

| Tool | Platform | Features |
|------|----------|----------|
| **FTK Imager** | Windows | GUI, raw/E01 and logical AD1 collection, verification |
| **dc3dd** | Linux | improved dd, logging, error handling |
| **dcfldd** | Linux | forensic dd, hash during copy |
| **Guymager** | Linux | GUI, raw/EWF-family acquisition and verification |
| **dd** | Unix-like systems | basic fallback; error handling and logging require care |

### Real Commands (disk imaging)

```bash
# basic dd (use write-blocker)
dd if=/dev/sdb of=/evidence/disk.img bs=512 conv=noerror,sync

# dc3dd (better — logs, hashes)
dc3dd if=/dev/sdb of=/evidence/disk.img hash=sha256 log=/evidence/dc3dd.log

# Guymager (GUI) — good for beginners
# open program → select device → select output format (E01) → Start
```

### Memory Capture Tools

| Tool | Platform | Description |
|------|----------|-------------|
| **WinPmem** | Windows | memory acquisition; output support varies by release |
| **AVML** | Linux | from Microsoft, good for Linux |
| **LiME** | Linux | kernel module, also Android |

### Real Commands (memory capture)

```bash
# WinPmem (Windows)
winpmem.exe memory.raw

# AVML (Linux)
avml memory.raw

# LiME (Linux — must compile against kernel version)
insmod lime.ko "path=/evidence/memory.lime format=lime"
```

### Write Blockers

> Prevent writing to the original device during read.

| Type | Example | When to use |
|------|---------|-------------|
| **Hardware** | Tableau TD2u, CRU WiebeTech | safest, must purchase |
| **Software** | Linux `blockdev --setro`, platform controls | free, but has risk |

**Check command:**

```bash
# verify device is read-only
blockdev --getro /dev/sdb   # returns 1 if read-only

# set read-only (software write-block)
blockdev --setro /dev/sdb
```

### Image Formats

| Format | Description | Supported by |
|--------|-------------|--------------|
| **raw / dd** | bit-for-bit copy | dd, dc3dd, FTK (read) |
| **E01** | compression + metadata + hash | FTK Imager, Guymager, EWF tools |
| **AFF4** | extensible evidence container supporting sparse address spaces | compatible AFF4 implementations |
| **AD1** | proprietary logical evidence container, not a physical-disk image | FTK Imager and compatible Exterro tooling |

### Verification

For an exact raw acquisition with consistent reads and no source changes, the
source-device and image byte hashes should match. Container formats such as E01
have a different file hash; use the format's acquisition and verification
records to compare the imaged data stream. Document read errors and tool
behavior.

```bash
# 1. hash the stable, write-blocked source
sha256sum /dev/sdb | tee original.sha256

# 2. create image
dc3dd if=/dev/sdb of=/evidence/disk.img hash=sha256

# 3. hash image
sha256sum /evidence/disk.img | tee image.sha256

# 4. compare digest values (manifest filenames differ)
test "$(awk '{print $1}' original.sha256)" = \
     "$(awk '{print $1}' image.sha256)"
```

---

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 1 Summary

This chapter covers legal authority, chain of custody, hashing, order of
volatility, disk and memory acquisition, write blocking, image formats, and
post-acquisition verification.
