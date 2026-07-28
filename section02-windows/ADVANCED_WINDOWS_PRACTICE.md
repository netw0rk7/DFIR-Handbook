# Part 02 Field Practice: Windows Correlation and Interpretation

## 2.15 Establish the Windows Examination Context

Before interpreting an artifact, identify the Windows edition, build, install
and upgrade history, architecture, system role, timezone configuration,
language, volume layout, user profiles, domain or Entra relationship, logging
policy, EDR presence, and relevant application versions. Artifact availability
and meaning can differ across releases and configuration. A path documented for
one build is a hypothesis to verify, not a universal constant.

Acquire the registry hives with transaction logs, EVTX channels with channel
configuration, NTFS metadata files, user profiles, application databases with
WAL and shared-memory companions, Prefetch directory metadata, Amcache, SRUM,
scheduled-task files, WMI repository when relevant, PowerShell history and
logs, Defender and EDR records, and time-service events. Preserve ACLs,
alternate streams, reparse points, hard-link relationships, and timestamps when
the acquisition method supports them.

Record whether sources came from a live system, VSS snapshot, backup, mounted
image, triage package, or API. A live copy may be internally inconsistent;
locked databases copied without their journals may omit recent transactions.

## 2.16 Registry Reasoning

Registry evidence is a set of hives and logs, not one database. Determine which
control set was active using `HKLM\SYSTEM\Select`; do not assume
`ControlSet001`. Associate each per-user `NTUSER.DAT` and `UsrClass.dat` with
the correct SID and profile. Include `.LOG1`, `.LOG2`, and other transaction or
recovery material supported by the parser. Parser recovery can change the view,
so preserve both original bytes and recovery settings.

Key last-write time belongs to the key, not each value. A value may have changed
without a separately stored value timestamp. A last-write time shows that some
operation affected the key, but normally not which value or actor. Deleted and
unallocated registry data can be stale, partially overwritten, or detached
from current context.

Use explicit language:

- **Observed:** the value and key path in a named hive and control set.
- **Consistent with:** the configuration or activity the value normally
  represents on the examined build.
- **Corroborate with:** service/task files, process events, Prefetch, file
  metadata, account activity, or network data.
- **Limit:** missing logs, restore points, hive recovery, roaming profiles,
  policy refresh, installer behavior, and clock uncertainty.

## 2.17 Execution Evidence Matrix

No single artifact provides a universal execution ledger. Correlate independent
sources and understand what each actually records.

| Source | Strong observation | Do not overclaim |
|---|---|---|
| Security 4688 | A process-creation audit event, if enabled and retained | Parentage and command line may be absent; log can be incomplete |
| Sysmon 1 | Process creation under the deployed Sysmon configuration | No event means nothing if excluded, disabled, or outside retention |
| Prefetch | Windows application-launch optimization data for an executable | Availability depends on build, role, settings, storage, and cleanup |
| UserAssist | Explorer-mediated GUI interaction counters and timestamps | Does not cover all launch paths or establish user intent |
| BAM/DAM | Background activity records associated with SID/path | Semantics and retention are version-dependent |
| Amcache | Application inventory and compatibility-related metadata | Presence alone is not automatic proof of execution |
| Shimcache | Compatibility cache entries and ordering/metadata | Presence is not universal proof of execution |
| SRUM | Resource and network-usage records by application/SID | Aggregation and database state limit event-level precision |
| LNK/Jump List | Shell references to targets and user interaction context | A link may be created without target execution |
| Memory | Process structures, mapped images, commands, sockets at capture | Snapshot is incomplete and structures may be stale or tampered |

Execution confidence rises when process telemetry, executable metadata, user
interaction, resource usage, and follow-on behavior agree in time. Divergence
is investigative information: it may reflect collection gaps, cleanup,
alternate launch paths, clock error, or evasion.

## 2.18 Windows Event Log Method

Acquire complete EVTX files and record channel configuration, maximum size,
retention behavior, overwrite policy, and audit policy. Event IDs are scoped to
a provider and channel. The number `1` means different things for Sysmon and
other providers. Always identify provider, channel, event ID, version, level,
record ID, computer, time created, and event data fields.

For logon analysis, distinguish:

- 4624 successful logon from 4625 failed logon;
- account named in the event from the system that authenticated it;
- logon type from protocol and session behavior;
- source network address from the true origin behind NAT, proxy, jump host, or
  remote-desktop gateway;
- explicit credentials (4648), Kerberos/NTLM authentication events, share
  access, and session lifecycle;
- local time display from stored UTC-based timestamps and clock state.

Event 4688 is useful only when process creation auditing is enabled; command
line population requires the corresponding policy. Service installation may
appear in System provider event 7045 and Security event 4697 under appropriate
auditing. Event 1102 states that the Security audit log was cleared and
identifies context, but it does not by itself name an attacker or establish
malicious intent.

Build sequences using record IDs and timestamps, but do not assume record IDs
are globally continuous across files or clearing. Detect rollover, archived
logs, recovery, forwarding delay, collector normalization, and duplicated
events. Preserve raw XML for fields hidden by a viewer's friendly rendering.

## 2.19 Sysmon Interpretation and Coverage

Sysmon records only what its installed version and configuration select.
Preserve the Sysmon binary version, configuration hash or export, operational
log, service state, driver state, and configuration-change events. Community
configurations are starting points, not universal best settings.

Correlate process GUIDs within one boot and host. Do not treat them as portable
global identities. Image and parent paths may be attacker-controlled or affected
by rename and deletion. Hashes depend on configured algorithms and access.
Network event 3 is disabled by some configurations due to volume. DNS event 22
depends on supported versions and configuration. File-delete events may retain
archived content when configured, creating sensitive evidence that needs access
control.

A defensible coverage statement is:

> Sysmon version X with configuration digest Y was active on host Z during the
> stated interval. The relevant include/exclude rules covered these event
> classes. No matching event was found in the acquired records; retention and
> forwarding limitations are described separately.

It is not defensible to write "Sysmon proves the process never ran."

## 2.20 Prefetch, Amcache, and Shimcache

Prefetch filenames, internal run information, referenced resources, volume
data, and retained run timestamps should be parsed with a tool validated for
the exact format version. Filename hash behavior is not a cryptographic
integrity hash. The execution counter and timestamp array can roll or be
affected by format and parser behavior. Correlate with the executable path,
volume serial, MFT references, process events, and user session.

Amcache schemas have changed across Windows releases. Collect the hive and
transaction logs and identify parser support. File entries may include path,
size, hash-related values, publisher or program relationships, but availability
varies. Do not label an Amcache time as "execution time" unless the exact field
semantics and build support that statement.

Shimcache/AppCompatCache is written and maintained for compatibility purposes.
Entry order, presence, metadata, and persistence differ by version and
shutdown/state behavior. Use it to establish that Windows recorded an object in
the cache under known semantics, then correlate. Avoid converting a cached
entry into a precise execution claim.

## 2.21 SRUM and ESE Databases

SRUM is stored in an ESE database and depends on registry metadata for names and
identifiers. Acquire `SRUDB.dat`, relevant registry hives, and ESE transaction
files when available. Work from a copy and document whether recovery or replay
was performed. Rows represent usage recorded into tables and may be aggregated;
they are not packet captures.

Resolve application identifiers, user SIDs, interface types, and timestamps.
Compare network usage with DNS, firewall, proxy, flow, and process telemetry.
Unexpected bytes assigned to an application are a lead, not proof of content,
destination, or exfiltration. Database corruption or uncommitted transactions
can produce gaps.

## 2.22 Shell Interaction: LNK, Jump Lists, and ShellBags

LNK files can record target paths, volume identifiers, file identifiers,
working directory, arguments, icon path, network information, and embedded
timestamps. These fields describe different objects and moments. An embedded
target timestamp is not the filesystem timestamp of the LNK itself.

Automatic and Custom Destinations implement Jump Lists using structured
storage or related formats. Associate AppIDs with applications using validated
mappings and local corroboration. Entry access counts and times depend on
application and Windows behavior.

ShellBags preserve shell namespace navigation and view state, including folders
that no longer exist or were on removable/network volumes. BagMRU ordering and
node-slot relationships must be parsed with the corresponding user hives.
Existence indicates shell awareness or interaction under artifact-specific
semantics, not necessarily that a file inside the folder opened.

## 2.23 USB and Removable-Media Correlation

Use multiple sources: `USBSTOR`, device-enumeration keys, MountedDevices,
MountPoints2, setup logs, partition/volume identifiers, LNK files, Jump Lists,
ShellBags, Defender/EDR, and relevant event channels. Distinguish device serial,
container ID, volume serial, disk signature, friendly name, drive letter, and
user SID. These identifiers answer different questions.

Drive letters are reusable and session-dependent. A device "first install" time
is not necessarily its first physical connection to any computer. A setup-log
entry can reflect driver installation. Last-write times apply to keys and may
be changed by later enumeration. Build a connection interval only when arrival,
enumeration, mount, user interaction, and removal evidence can be correlated.

Report "the system recorded volume V mounted as E: during this interval" rather
than "the suspect copied file F" unless file-access or copy evidence supports
the latter.

## 2.24 Persistence: Tasks, Services, WMI, and Startup

Scheduled tasks have XML definitions, TaskCache registry entries, operational
events, and task-engine/process effects. Acquire both file and registry views.
Compare action, trigger, principal, hidden flag, author, security descriptor,
timestamps, and referenced binary. A legitimate updater can resemble malicious
persistence.

For services, correlate SYSTEM hive configuration, Service Control Manager
events, Security auditing, service binary, signature, file creation, process
tree, account, start type, and failure actions. A quoted-path weakness or
unusual service account is a risk indicator, not proof of exploitation.

WMI permanent event subscriptions involve filters, consumers, and bindings in
the repository. Correlate namespace objects with process creation, script
content, file artifacts, and WMI activity logs. Repository parsing is
version-sensitive; avoid modifying or rebuilding the original.

Startup folders, Run keys, Winlogon values, IFEO, AppInit mechanisms, browser
extensions, Office add-ins, COM hijacks, and cloud-managed startup mechanisms
have different triggers and privileges. Inventory is the beginning of
analysis; determine whether the trigger occurred and code executed.

## 2.25 PowerShell Evidence

PowerShell evidence may include engine and provider event channels, Script
Block Logging (4104), module logging, transcription, process command lines,
PSReadLine history, AMSI/EDR telemetry, Prefetch, console host artifacts, and
network records. Availability depends on PowerShell edition, host, policy,
version, user, and tampering.

Script blocks can be fragmented across events; preserve message numbering and
reassemble cautiously. Logging can expose secrets and personal data.
Transcripts record configured sessions, not all PowerShell execution.
PSReadLine history is user- and host-specific and can omit commands, be disabled,
or be edited. Encoded content may use UTF-16LE Base64 in common command-line
patterns, but decoding does not establish maliciousness.

Analyze parent process, host application, account, integrity level, command,
script origin, loaded modules, child processes, file/network effects, and
security-tool response. Preserve the raw event and decoded representation with
a recorded transformation.

## 2.26 Timeline Construction

Normalize copies of timestamps while retaining source value, source timezone,
conversion, precision, semantics, and provenance. A "super-timeline" is a
correlation dataset, not a single ground-truth clock.

Each event should contain:

- normalized time and original value;
- source artifact and evidence ID;
- host, user, process, and object identifiers;
- event description written at the observation level;
- parser and version;
- timestamp meaning and precision;
- confidence and limitations.

Sort order can imply causation that data does not support. Events sharing a
one-second timestamp may have unknown internal order. Filesystem tunneling,
copy semantics, archive extraction, synchronization, restore, and timestomping
can make timestamps diverge from human action. Use record sequence, process
relationships, transaction data, and independent telemetry to refine order.

The final timeline should distinguish observed events from analyst-created
milestones and inferred intervals. Preserve the query or filter used to produce
every report excerpt.
