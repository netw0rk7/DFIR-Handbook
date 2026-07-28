# Part 02: Windows Forensics

> The deepest section of the handbook — covering registry, event logs, Sysmon, prefetch,
> amcache, shimcache, SRUM, LNK, jump lists, USB, recycle bin, scheduled tasks,
> PowerShell logging, and super-timelines.
> Key tools: RegRipper, MFTECmd, KAPE, Velociraptor, Eric Zimmerman's tools,
> Chainsaw, plaso/log2timeline, Timesketch, Sysmon.

---

## 2.1 Registry Hives

> The registry is Windows' central database — every action leaves a trace.

### Main Hive Files

| Hive | Location | Contents |
|------|----------|----------|
| **SAM** | `\Windows\System32\config\SAM` | user accounts (RIDs, hashes) |
| **SYSTEM** | `\Windows\System32\config\SYSTEM` | machine config, services, boot |
| **SECURITY** | `\Windows\System32\config\SECURITY` | audit/logon policies |
| **SOFTWARE** | `\Windows\System32\config\SOFTWARE` | programs, machine settings |
| **NTUSER.DAT** | `%USERPROFILE%\NTUSER.DAT` | user settings |
| **USRCLASS.DAT** | `%USERPROFILE%\AppData\Local\Classes\USRCLASS.DAT` | user-specific class settings |

### Parsing the Registry

```powershell
# PowerShell (built-in)
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# reg.exe (built-in)
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /s

# RegRipper (professional tool)
rip.exe -r SYSTEM --plugin userassist
rip.exe -r NTUSER.DAT --plugin shellbags
rip.exe -r SOFTWARE --plugin amcache

# Eric Zimmerman's Registry Explorer (GUI)
# Open program → open hive → search keys of interest
```

## 2.2 High-Value Registry Keys

### UserAssist (program execution)

```
Hive: NTUSER.DAT
Path: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Values
```

- Records GUI-launched items under the user profile; value names use ROT13
- Common fields include a run counter and last-execution timestamp
- Supports an execution hypothesis, but should be correlated with other artifacts

**Parsing:**

```bash
# RegRipper
rip.exe -r NTUSER.DAT --plugin userassist
```

Use a maintained UserAssist parser rather than treating the binary value data
or ROT13-encoded names as Base64.

### ShellBags (opened folders)

```
Hive: NTUSER.DAT + USRCLASS.DAT
Path: Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags
       Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
```

- Stores folders opened in Explorer
- Has folder name, date, window size
- Use ShellBagsExplorer or RegRipper plugin `shellbags`

### Run / RunOnce (auto-start)

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

- Common persistence used by attackers
- Use RegRipper plugin `run` or `autoruns`

### Services

```
Hive: SYSTEM
Path: ControlSet001\Services\
```

- Each service has a subkey in `Services\<service_name>`
- Has `ImagePath`, `Start` (2=auto, 3=demand, 4=disabled)
- Use `services` plugin of RegRipper

### Amcache (application inventory)

```
File: C:\Windows\AppCompat\Programs\Amcache.hve
```

- Fields vary by Windows version and can include path, publisher, version,
  timestamps, and hashes
- Presence is not, by itself, proof of execution
- Use AmcacheParser or another parser validated for the source OS version

### Shimcache (AppCompatCache)

```
Hive: SYSTEM
Path: ControlSet001\Control\Session Manager\AppCompat\AppCompatCache
```

- Stores application-compatibility entries, including paths and timestamps
- An entry is not, by itself, proof that the program executed
- Use ShimCacheParser or RegRipper plugin `shimcache`

### RecentDocs

```
Hive: NTUSER.DAT
Path: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
```

- Stores files opened (filename, date)
- Has subkeys per file type

### TypedPaths

```
Hive: NTUSER.DAT
Path: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
```

- Stores paths typed in Explorer address bar
- Useful when target file is deleted

### USBSTOR (connected USB devices)

```
Hive: SYSTEM
Path: ControlSet001\Enum\USBSTOR
       ControlSet001\Enum\USB
```

- Stores device name, serial number, install time
- Use USBDeviceForensics or RegRipper plugin `usbstor`

### BAM / DAM (Background Activity Moderator)

```
Hive: SYSTEM
Path: ControlSet001\Services\bam\State\ItemList
       ControlSet001\Services\dam\State\ItemList
```

- Windows 10/11 — stores files executed (even without prefetch)
- Has full timestamps

## 2.3 Event Logs (Key Events)

> Use wevtutil, PowerShell Get-WinEvent, or Chainsaw for hunting.

### Event IDs to Know

| Event ID | Log | Indicates | Use for |
|----------|-----|-----------|---------|
| **4624** | Security | Successful logon | check logon type (2=interactive, 3=network, 10=remote) |
| **4625** | Security | Failed logon | Brute force, password spray |
| **4648** | Security | Explicit credential logon | often suspicious |
| **4672** | Security | Special privileges assigned | admin privilege use |
| **4688** | Security | Process creation | has command line (audit must be on) |
| **4698** | Security | Scheduled task created | Persistence |
| **7045** | System | Service installed | malware as service |
| **1102** | Security | Event log cleared | anti-forensics |
| **4776** | Security | NTLM authentication | Pass-the-hash |
| **4768** | Security | Kerberos TGT request | Golden Ticket |
| **4769** | Security | Kerberos service ticket | Silver Ticket, DCSync |

### Example XML Event (Event ID 4624)

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4624</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-07-28T06:00:00Z"/>
    <Computer>web01</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="IpAddress">203.0.113.42</Data>
    <Data Name="ProcessId">0x3e4</Data>
    <Data Name="ProcessName">C:\Windows\System32\winlogon.exe</Data>
  </EventData>
</Event>
```

**Analysis:** LogonType 10 = RDP, IPAddress points to attacker.

### PowerShell Commands for Event Logs

```powershell
# Find logon events (4624) in time range
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624; StartTime=(Get-Date).AddDays(-1)} |
  Select-Object TimeCreated, Id, Message

# Find process creation (4688) with command line
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} |
  Where-Object { $_.Message -match "malware" }

# Export to CSV for analysis
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} |
  Export-Csv logon_events.csv -NoTypeInformation
```

### Chainsaw (Sigma-based hunting)

```bash
# Use Sigma rules against Windows Event Logs
chainsaw.exe hunt Security.evtx --sigma rules/ \
  --mapping mappings/sigma-event-logs-all.yml

# Example rule for RDP brute force
# file: rdp_brute_force.yml
title: RDP Brute Force
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 10
  condition: selection
fields:
  - TargetUserName
  - IpAddress
  - TimeCreated
level: high
```

## 2.4 Sysmon (System Monitor)

> Sysmon is a Microsoft Sysinternals tool providing detailed logging.

### Install + Configure

```powershell
# Install
sysmon.exe -accepteula -i sysmon-config.xml

# Recommended config: SwiftOnSecurity or @olafhartong
# Download from GitHub
```

### Key Sysmon Event IDs

| Event ID | Indicates |
|----------|-----------|
| **1** | Process creation (command line, parent process) |
| **2** | File creation time changed |
| **3** | Network connection |
| **7** | Image loaded (DLL) |
| **8** | CreateRemoteThread |
| **10** | Process access (OpenProcess) |
| **11** | File created or overwritten (`FileCreate`) |
| **13** | Registry value set |
| **17** | Pipe created |
| **22** | DNS query |

### Analysis

```bash
# PowerShell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 1 } |  # Process creation
  Select-Object TimeCreated, Message

# Chainsaw
chainsaw.exe hunt Sysmon.evtx --sigma rules/ \
  --mapping mappings/sigma-event-logs-all.yml

# Splunk
index=sysmon EventCode=1 Image="*powershell*"
```

## 2.5 Prefetch

> Prefetch can support program-execution analysis on supported Windows desktop
> versions, including Windows 11 when Prefetch is enabled. Server behavior and
> retention vary by version and configuration.

### Location

```
C:\Windows\Prefetch\
```

### File Format

- Filename: `<program_name>-<hash>.pf`
- Can contain recent run times, run count, referenced files, and volume data;
  the number of stored run times depends on the format version

### Parsing Tools

| Tool | Type | Command |
|------|------|---------|
| **PECmd** | Eric Zimmerman | `PECmd.exe -d C:\Windows\Prefetch --csv C:\output` |
| **KAPE** | collection and processing | use a reviewed target and module set |

### Real Usage

```cmd
REM Download PECmd from ericzimmerman.co
PECmd.exe -d C:\Windows\Prefetch --csv C:\output
REM Produces CSV with all details
```

## 2.6 Amcache.hve

> Stores data about installed programs (Windows 7+)

### Location

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

### Data Stored

- Filename, path, size, version, publisher, timestamps, and hashes, depending
  on the source Windows version
- Data persists even if file is deleted
- Presence does not prove execution; corroborate with Prefetch, UserAssist,
  BAM/DAM, event logs, or other case-relevant artifacts

### Parsing

```cmd
REM Use AmcacheParser
AmcacheParser.exe -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\output
```

## 2.7 Shimcache (AppCompatCache)

> Stores application-compatibility entries. Treat entries as evidence that a
> file was observed by the compatibility subsystem, not automatic proof of
> execution.

### Location

```
Registry: SYSTEM\ControlSet001\Control\Session Manager\AppCompat\AppCompatCache
```

### Parsing

```cmd
REM Use ShimCacheParser
ShimCacheParser.exe -r C:\Windows\System32\config\SYSTEM

REM Or RegRipper
rip.exe -r SYSTEM --plugin shimcache
```

## 2.8 SRUM (System Resource Usage Monitor)

> Stores resource usage per app (Windows 8+)

### Location

```
C:\Windows\System32\sru\
```

### Data Stored

- Time spent per app
- Network usage (bytes sent/received)
- Battery usage

### Parsing

```cmd
REM Use SrumECmd
SrumECmd.exe -f C:\Windows\System32\sru\SRUDB.dat --csv C:\output
```

## 2.9 LNK Files & Jump Lists

### LNK Files (shortcuts)

```
Locations:
- %USERPROFILE%\Desktop\*.lnk
- %APPDATA%\Microsoft\Windows\Recent\*.lnk
- %USERPROFILE%\Links\*.lnk
```

**Data stored:**

- Target file path
- Creation/modification time
- Open count
- Drive letter, volume serial

**Tools:**

- LECmd (Eric Zimmerman)
- JumpList Explorer

### Jump Lists

```
Locations:
- %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
- %APPDATA%\Microsoft\Windows\Recent\CustomDestinations\
```

- AutomaticDestinations: files opened in apps
- CustomDestinations: files added manually

## 2.10 USB Artifacts

> Critical in digital forensics — stores connected USB device history.

### Sources

| Source | Location | Data |
|--------|----------|------|
| **USBSTOR** | Registry: SYSTEM\Enum\USBSTOR | device name, serial, install time |
| **USB** | Registry: SYSTEM\Enum\USB | Vendor ID, Product ID |
| **setupapi.dev.log** | C:\Windows\INF\setupapi.dev.log | all connections |
| **ShellBags** | Registry: NTUSER.DAT | opened USB folders |
| **UserAssist** | Registry: NTUSER.DAT | programs run from USB |

### Investigation

```cmd
REM Use USBDeviceForensics
USBDeviceForensics.exe -r C:\Windows\System32\config\SYSTEM

REM Or RegRipper
rip.exe -r SYSTEM --plugin usbstor
rip.exe -r SYSTEM --plugin usb
```

## 2.11 Recycle Bin

> Stores files deleted via Explorer (not via command line).

### Structure

```
C:\$Recycle.Bin\
  SID\
    $I<original_filename>   # original file info
    $R<original_filename>   # file content
```

### Data in $I (Index file)

- Original path
- Original size
- Deletion time
- Drive letter

### Parsing

```cmd
REM Use WinRecycleBin
WinRecycleBin.exe -d C:\$Recycle.Bin

REM Or PowerShell
Get-ChildItem C:\$Recycle.Bin -Recurse -Force
```

## 2.12 Scheduled Tasks & Services

### Scheduled Tasks

```
Locations:
- C:\Windows\System32\Tasks\
- C:\Windows\Tasks\
- Registry: Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache
```

### Check

```cmd
REM List all tasks
schtasks /query /fo LIST /v

REM Recent tasks
schtasks /query /fo CSV | findstr "2026-07"

REM PowerShell
Get-ScheduledTask | Select-Object TaskName, State, LastRunTime
```

### Services

```cmd
REM List all services
sc query state= all

REM Auto-start services
sc query state= all | findstr "AUTO_START"

REM PowerShell
Get-WmiObject win32_service | Where-Object {$_.StartMode -eq "Auto"}
```

## 2.13 PowerShell Logging

> Critical for detecting PowerShell-based attacks.

### Logging Types

| Type | Location | Data |
|------|----------|------|
| **Module Logging** | Event ID 4103 | modules used |
| **ScriptBlock Logging** | Event ID 4104 | PowerShell code (most important) |
| **Transcription** | .txt file | full session |

### Enable

```powershell
# Enable ScriptBlock Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

# Enable Transcription
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1
```

### Analysis

```powershell
# Find suspicious PowerShell commands
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} |
  Where-Object { $_.Message -match "Invoke-Mimikatz|DownloadString|EncodedFromBase64" }
```

## 2.14 Super-Timelines

> Combine all events into a single timeline.

### Tools

| Tool | Usage |
|------|-------|
| **plaso/log2timeline** | `log2timeline.py case.plaso /evidence/disk.E01` |
| **Timesketch** | Web-based timeline analysis |
| **MFTECmd** | `MFTECmd.exe -f "C:\evidence\$MFT" --csv C:\output` |

### Steps

```bash
# 1. Create .plaso from multiple sources
log2timeline.py case.plaso /evidence/

# 2. Convert to CSV
psort.py -o csv case.plaso > timeline.csv

# 3. Analyze in Timesketch or Excel
```

---

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 2 Summary

This chapter covers Windows Registry artifacts, event logs, Sysmon, Prefetch,
Amcache, Shimcache, SRUM, LNK and Jump Lists, USB history, the Recycle Bin,
scheduled tasks, PowerShell logging, and super-timeline workflows.
