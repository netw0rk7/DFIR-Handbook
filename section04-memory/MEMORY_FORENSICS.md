# Part 04: Memory Forensics

> Memory (RAM) forensics — most important for detecting malicious activity
> not recorded on disk.
> Key tools: Volatility 3 (`vol.py`), WinPmem, AVML, and YARA.

---

## 4.1 Why RAM Matters

- **Volatile**: lost immediately on power off
- **Encryption keys**: reside in RAM (BitLocker, FileVault, LUKS)
- **Unlogged activity**: code injected into processes not on disk
- **Network state**: connections, sockets, pipes
- **Running malware**: not yet written to disk

**Rule:** when authorized and operationally safe, capture RAM before shutdown
or other actions that destroy volatile state. Do not delay urgent containment
when the risk of continued compromise outweighs the evidentiary benefit.

## 4.2 Kernel Structures

| Structure | Purpose |
|-----------|---------|
| **EPROCESS** | Process block — PID, PPID, image name, handles |
| **_PEB** | Process Environment Block — env vars, loaded modules |
| **_KPCR** | Kernel Processor Control Region — per-CPU state |
| **VADs** (Virtual Address Descriptors) | Process memory regions |
| **Handles** | Opened objects (files, keys, mutexes) |
| **Linked list** | ActiveProcessLinks — links all EPROCESS |

## 4.3 Volatility 3 Workflow

### Step 1: Image Identification

```bash
# View image info
vol.py -f memory.raw windows.info

# List available plugins
vol.py -f memory.raw --help
```

### Step 2: Process Enumeration

```bash
# All processes (from ActiveProcessLinks)
vol.py -f memory.raw windows.pslist

# Hidden processes (psscan scans pool tags)
vol.py -f memory.raw windows.psscan

# Compare pslist vs psscan (find hidden)
vol.py -f memory.raw windows.psxview

# Process tree
vol.py -f memory.raw windows.pstree

# Command lines
vol.py -f memory.raw windows.cmdline
```

### Step 3: Network Connections

```bash
# Network connections (TCP/UDP)
vol.py -f memory.raw windows.netscan
```

### Step 4: Malware Detection

```bash
# Malfind — suspicious memory regions
vol.py -f memory.raw windows.malfind

# YARA scan of process VADs (requires yara-python)
vol.py -f memory.raw windows.vadyarascan --yara-file rules.yar

# Process-hollowing indicators
vol.py -f memory.raw windows.malware.hollowprocesses

# SSDT hooks
vol.py -f memory.raw windows.ssdt
```

### Step 5: Drivers & Modules

```bash
# Loaded modules (DLLs)
vol.py -f memory.raw windows.modules

# Driver scan (rootkits)
vol.py -f memory.raw windows.driverscan

# Callback functions
vol.py -f memory.raw windows.callbacks
```

### Step 6: Credentials

Credential-related output is highly sensitive. Run these plugins only when
authorized, restrict access to their output, and follow the case handling plan.

```bash
# Hashdump (SAM hashes)
vol.py -f memory.raw windows.hashdump

# LSA secrets
vol.py -f memory.raw windows.lsadump

# Mimikatz in memory (scan signatures)
vol.py -f memory.raw windows.vadyarascan --yara-file reviewed_rules.yar
```

### Step 7: Registry in Memory

```bash
# Hivelist
vol.py -f memory.raw windows.registry.hivelist

# Print key
vol.py -f memory.raw windows.registry.printkey \
  --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

### Step 8: Files & Timelines

```bash
# Dump files from memory
vol.py -f memory.raw -o output/ windows.dumpfiles

# Memory timeline
vol.py -f memory.raw timeliner.Timeliner
```

## 4.4 Interpreting Results

### pslist vs psscan

```
pslist: from ActiveProcessLinks (linked list)
psscan: scans pool tags — finds processes removed from list

If psscan finds an entry that pslist does not, investigate whether it is a
terminated-process remnant, damaged structure, acquisition artifact, or
deliberately unlinked process. The mismatch alone does not prove a rootkit.
```

### malfind indicators

```
Suspicious malfind output:
- Page with PAGE_EXECUTE_READWRITE (writable + executable)
- MZ header (PE file) in memory region
- Size not matching normal module

Legitimate runtimes and security products can create similar regions.
Correlate with process ancestry, mapped files, signatures, threads, and
disassembly.
```

### netscan indicators

```
Suspicious connections:
- External unknown IP
- Unusual port (4444, 31337, 8443)
- State = ESTABLISHED to foreign IP

Ports and remote addresses are triage leads, not attribution. Validate them
against process ownership, DNS, proxy, firewall, and threat-intelligence data.
```

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 4 Summary

This chapter presents a staged Volatility 3 workflow for process, network,
malware, driver, credential, registry, file, and timeline examination.
