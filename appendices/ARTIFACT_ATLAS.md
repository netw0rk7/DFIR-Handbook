# Appendix A: Artifact and Evidence Atlas

This atlas is a field index, not a substitute for the full chapters. Each sheet
states the question an artifact can help answer, the minimum collection
context, useful corroboration, and the limit that should appear in reporting.

## A.1 Chain-of-Custody Record

**Question:** Who controlled an evidence item, when, where, and for what
purpose? **Collect:** unique ID, item condition, seal, release/receipt
identities, authenticated times with timezone, locations, purpose, and
discrepancies. **Correlate:** access logs, manifests, transport records, storage
audit, photographs, and case authorization. **Limit:** custody documents
accountability; they do not validate acquisition completeness or parser
correctness.

## A.2 Acquisition Log

**Question:** Exactly how was evidence collected? **Collect:** source and
destination identifiers, tool/version, command/configuration, start/end,
operator, format, errors, unreadable ranges, size, and verification. **Correlate:**
scene notes, device inventory, image metadata, hashes, and destination audit.
**Limit:** a successful exit status does not prove all addressable data was
read or that a live source was temporally consistent.

## A.3 Cryptographic Digest

**Question:** Do two defined byte representations match? **Collect:** algorithm,
value, exact object/representation, size, tool/version, time, and operator.
**Correlate:** signed manifest, custody, storage and transfer logs, and internal
container verification. **Limit:** a matching hash does not establish source
identity, acquisition validity, or meaning of content. Use modern algorithms;
retain legacy values only for interoperability.

## A.4 Write-Blocker Record

**Question:** What control prevented writes to supported source media?
**Collect:** blocker make/model/serial/firmware, interface, validation date,
connection diagram, source/destination, and read/write test result.
**Correlate:** OS device flags, acquisition log, source hash where meaningful,
and post-collection inspection. **Limit:** software read-only settings and
hardware blockers protect only defined layers and protocols; neither prevents
every external or controller-mediated change.

## A.5 Windows SYSTEM Hive

**Question:** What system configuration, services, devices, timezone, and
control-set state were recorded? **Collect:** SYSTEM plus transaction logs and
identify active control set through `Select`. **Correlate:** SOFTWARE, event
logs, task/service files, setup logs, device artifacts, and process telemetry.
**Limit:** key last-write time applies to the key; configuration does not prove
the configured action occurred.

## A.6 Windows SOFTWARE Hive

**Question:** Which system-wide software, uninstall, policy, and application
configuration records existed? **Collect:** hive and transaction logs from the
same system state. **Correlate:** Amcache, package/install logs, Prefetch,
process events, file metadata, signatures, and user hives. **Limit:** registry
inventory can be stale, incomplete, vendor-specific, or changed by installers;
it is not a definitive installed-or-executed ledger.

## A.7 SAM and SECURITY Hives

**Question:** What local account and protected security material was recorded?
**Collect:** SAM, SECURITY, SYSTEM, logs, and acquisition authority under
restricted handling. **Correlate:** account-management and logon events,
profiles, group membership, LSA policy, endpoint identity, and domain records.
**Limit:** recovered hashes/secrets are password-equivalent sensitive data;
presence does not show use, and modern protections affect recovery.

## A.8 NTUSER.DAT

**Question:** What per-user shell, application, MRU, and configuration state was
recorded? **Collect:** map profile to SID and acquire NTUSER.DAT with transaction
logs. **Correlate:** UsrClass.dat, profile metadata, LNK/Jump Lists, browser,
event logs, and filesystem records. **Limit:** values may arise from policy,
sync, application behavior, or another process in the user's context; user
intent and physical identity require separate evidence.

## A.9 UsrClass.dat and ShellBags

**Question:** Which shell namespaces and folders were represented in a user's
shell state? **Collect:** UsrClass.dat and NTUSER.DAT with logs and profile/SID
mapping. **Correlate:** BagMRU relationships, LNK, Jump Lists, mounted volumes,
MFT, and removable-media identifiers. **Limit:** ShellBag presence supports
shell awareness/navigation under version-specific behavior, not opening every
file within a folder.

## A.10 UserAssist

**Question:** Which Explorer-mediated GUI entries were recorded for a user?
**Collect:** relevant NTUSER.DAT keys, ROT13-decoded names, counters,
timestamps, GUID context, and parser/version. **Correlate:** Prefetch, process
events, LNK, Jump Lists, application logs, and session activity. **Limit:**
UserAssist does not capture every launch path; counter and timestamp semantics
vary, and an entry does not establish purpose.

## A.11 Prefetch

**Question:** What application-launch optimization data did Windows retain?
**Collect:** complete Prefetch directory with metadata; parse format version,
run count/times, referenced files, and volume information. **Correlate:** process
telemetry, executable identity, MFT, registry, user session, and endpoint logs.
**Limit:** availability and retention depend on build, role, configuration,
storage, and cleanup; a filename hash is not an integrity hash.

## A.12 Amcache

**Question:** What application/file inventory and compatibility metadata was
recorded? **Collect:** Amcache hive and logs with OS build and validated parser.
**Correlate:** executable file, signature/hash, Prefetch, Shimcache, process
events, install logs, and registry. **Limit:** schema and field meanings change;
an Amcache entry or timestamp is not automatic proof or precise time of
execution.

## A.13 Shimcache

**Question:** Which executable-related paths and metadata were present in the
compatibility cache? **Collect:** active SYSTEM control set, cache value,
transaction context, OS build, and parser/version. **Correlate:** Prefetch,
Amcache, process events, filesystem, memory, and user interaction. **Limit:**
entry presence, order, and write behavior are version-dependent and do not form
a universal execution log.

## A.14 BAM and DAM

**Question:** Which user-associated executable paths were recorded by Windows
background activity components? **Collect:** relevant SYSTEM control-set keys,
SID mapping, timestamps, build, and power-state context. **Correlate:** process
events, Prefetch, UserAssist, SRUM, files, and sessions. **Limit:** retention and
semantics vary across versions; absence or a single entry cannot prove or
disprove execution.

## A.15 SRUM

**Question:** What application and user resource/network usage was accumulated?
**Collect:** `SRUDB.dat`, ESE logs, SOFTWARE/SYSTEM metadata, and acquisition
state. **Correlate:** process, DNS, firewall, proxy, flow, interface, and SID
records. **Limit:** rows can be aggregated and recovery-dependent; byte counts
do not identify content, destination, or maliciousness without other sources.

## A.16 Windows Security Event 4624

**Question:** What successful logon did the Security provider record?
**Collect:** raw XML, provider/channel/version, record ID, time, subject, target,
logon type, process, authentication package, source, workstation, and linked
logon identifiers. **Correlate:** 4634/4647, 4648, Kerberos/NTLM, VPN, RDP,
endpoint process, and identity-provider data. **Limit:** authentication does not
identify the human controller or guarantee subsequent activity.

## A.17 Windows Security Event 4625

**Question:** What failed logon attempt was audited? **Collect:** status and
substatus, logon type, account/domain, process, source/workstation, package,
raw XML, and audit policy. **Correlate:** successful logons, account lockout,
identity provider, VPN, source host, and threat telemetry. **Limit:** failures
can result from stale services, user error, scanning, policy, or attack; source
fields may reflect intermediaries.

## A.18 Windows Security Event 4688

**Question:** What process creation was audited? **Collect:** raw event,
creator/new process IDs, image, command line when enabled, token/elevation,
account, time, and audit-policy state. **Correlate:** Sysmon 1, Prefetch,
PowerShell, service/task events, file metadata, EDR, and memory. **Limit:**
command line may be absent; PID reuse and missing events require time and
process-object correlation.

## A.19 Service Installation Events

**Question:** What service installation or creation did Windows record?
**Collect:** System 7045, Security 4697 when audited, SCM context, service name,
image path, type/start/account, and raw event. **Correlate:** SYSTEM hive,
service binary, signature, file creation, process tree, network, and change
management. **Limit:** remote administration, software deployment, and security
products create legitimate services.

## A.20 Security Log Clear Event 1102

**Question:** Was the Security audit log cleared under a recorded context?
**Collect:** raw 1102 event, subject identifiers, record sequence, channel
configuration, archived/forwarded copies, and collector health. **Correlate:**
process/PowerShell/EDR activity, policy changes, backup logs, and other channel
gaps. **Limit:** the event does not alone attribute malicious intent; retention,
maintenance, restore, or authorized administration are alternatives.

## A.21 Sysmon Process Event 1

**Question:** What process creation did the deployed Sysmon configuration
record? **Collect:** raw XML, Sysmon/config version, process/parent GUIDs and
IDs, images, commands, hashes, signer, user, and time. **Correlate:** Security
4688, EDR, Prefetch, file, session, and follow-on events. **Limit:** excluded,
disabled, lost, or out-of-retention activity leaves no event; fields can be
attacker-influenced.

## A.22 Sysmon Network Event 3

**Question:** What network connection did Sysmon associate with a process?
**Collect:** raw event, configuration coverage, process GUID, protocol,
source/destination, ports, initiated flag, time, and image. **Correlate:** DNS
event 22, firewall, PCAP/flow, proxy, process event, and host routing/VPN.
**Limit:** configuration often excludes or disables high-volume network events;
an endpoint does not establish transferred content.

## A.23 PowerShell Script Block Event 4104

**Question:** What script block content did PowerShell logging capture?
**Collect:** all fragments with message number/total, script-block ID, provider,
host, user/session context, policy, and raw XML. **Correlate:** process command
line, module/transcription, AMSI/EDR, files, network, and child processes.
**Limit:** logging depends on edition/version/policy, can contain secrets, and
does not capture every host or action.

## A.24 Scheduled Tasks

**Question:** What task definition, trigger, action, and execution evidence
existed? **Collect:** task XML/files, TaskCache registry, ACLs, operational and
Security events, and referenced payload. **Correlate:** process creation,
service accounts, file metadata, network, and change management. **Limit:** a
definition does not prove a trigger fired; registry/file views can diverge.

## A.25 LNK Files

**Question:** What target and environment metadata did a Windows shortcut
record? **Collect:** original LNK, filesystem metadata, target IDs, volume and
network data, arguments, working directory, embedded timestamps, and parser.
**Correlate:** Jump Lists, ShellBags, MFT, mounted volumes, application/process
activity, and user session. **Limit:** LNK and target timestamps describe
different objects; creation can occur without target execution.

## A.26 Jump Lists

**Question:** Which application-associated destinations were recorded?
**Collect:** Automatic/Custom Destinations, AppID mapping, entries, access
metadata, embedded LNK data, and user profile/SID. **Correlate:** application
version, LNK, ShellBags, file metadata, process activity, and recent documents.
**Limit:** behavior differs by application and Windows version; an entry does
not prove file content was viewed.

## A.27 Recycle Bin

**Question:** Which objects were represented as deleted through the Windows
shell Recycle Bin? **Collect:** paired `$I` metadata and `$R` content, SID
directory, filesystem metadata, parser/version, and unmatched records.
**Correlate:** MFT/USN, original path, user session, LNK/Jump Lists, and backup.
**Limit:** bypass deletion, cleanup, removable/network behavior, overwriting,
and record loss create gaps; recovered content may be incomplete.

## A.28 USB Device Artifacts

**Question:** Which device/volume relationships did Windows enumerate?
**Collect:** USBSTOR/device keys, container IDs, MountedDevices, MountPoints2,
setup logs, volume serials, and user SID context. **Correlate:** LNK, Jump Lists,
ShellBags, file access, EDR, and physical inventory. **Limit:** drive letters
and identifiers are reusable; enumeration or installation does not prove a
file copy or identify the person.

## A.29 NTFS MFT Record

**Question:** What attributes and namespace state did NTFS record for an object?
**Collect:** full record and extensions, record/sequence number, attributes,
data runs, names, timestamps, flags, and parser. **Correlate:** USN, `$LogFile`,
directory indexes, bitmap, file content, and snapshots. **Limit:** records can
be reused or partially overwritten; SI/FN timestamps have different update
semantics.

## A.30 NTFS USN Change Journal

**Question:** What change reason flags were journaled for a file reference?
**Collect:** `$J`, `$Max`, volume ID, USN, record/sequence, reason flags,
filename/parent, timestamp, and wrap state. **Correlate:** MFT, `$LogFile`,
process/application telemetry, and snapshots. **Limit:** flags are categories,
not complete operations or actor identity; retention wrap and disable/delete
cause gaps.

## A.31 NTFS `$LogFile`

**Question:** What NTFS transaction/recovery records can help reconstruct
metadata change? **Collect:** raw metadata file with volume context, restart
areas, LSNs, operations, and validated parser. **Correlate:** MFT, USN, bitmap,
directory indexes, and known test behavior. **Limit:** it is finite, wraps, is
complex/version-sensitive, and is not a general user-action audit log.

## A.32 Mark-of-the-Web

**Question:** What origin-zone metadata was stored with a Windows file?
**Collect:** exact `Zone.Identifier` stream, parent MFT identity, timestamps,
origin/referrer fields, and copy/acquisition method preserving ADS. **Correlate:**
browser download, email, proxy, LNK, process, and archive provenance. **Limit:**
creation and propagation vary by application, policy, archive, and filesystem;
absence is not proof of local origin.

## A.33 Linux systemd Journal

**Question:** What structured events did journald retain? **Collect:** native
journal files, boot IDs, realtime/monotonic times, fields, storage/rotation,
sealing, forwarding, and exact export query. **Correlate:** traditional logs,
auditd, unit configuration, process/network, and centralized collector.
**Limit:** volatility, rate limiting, redaction, vacuuming, corruption, and
forwarding gaps affect completeness.

## A.34 Linux auditd

**Question:** What kernel audit records were produced under the active rules?
**Collect:** raw records, rule configuration, enabled/failure mode, backlog/lost
indicators, boot/session IDs, serial-linked multi-record events, and time.
**Correlate:** journald, process, package, authentication, filesystem, EDR, and
network data. **Limit:** coverage is rule-dependent; record assembly and path
resolution require care, and overload can lose events.

## A.35 Linux SSH Authorized Keys

**Question:** Which public keys and restrictions authorized SSH access?
**Collect:** file bytes, owner/ACL/mode, filesystem metadata, key type/blob
fingerprint, options, comments, sshd configuration, and account state.
**Correlate:** authentication logs, agent/known_hosts, shell/process history,
configuration management, and network. **Limit:** comments are labels, not
authenticated identities; configuration presence does not prove key use.

## A.36 Linux systemd Unit

**Question:** What effective service/timer/path persistence was configured?
**Collect:** vendor and administrator unit files, drop-ins, symlinks, generated
or transient state, environment files, ACLs, and journal. **Correlate:**
`systemctl show`, process tree, executable/package, audit, network, and change
management. **Limit:** inspecting one file misses precedence/overrides; enabled
or configured does not prove execution.

## A.37 `/proc/<pid>/exe` Deleted Object

**Question:** Can a running process expose an executable whose directory entry
was removed? **Collect:** PID/object context, start time, namespaces/cgroups,
symlink target, copied bytes, maps, descriptors, credentials, command, and
hashes. **Correlate:** memory, filesystem journal, package, audit/EDR, and
network. **Limit:** recovered bytes may omit metadata or runtime changes; PID
reuse and live-collection footprint matter.

## A.38 macOS Unified Logs

**Question:** What log entries did the Apple unified logging system retain?
**Collect:** log archive/store, macOS build, times, predicates, subsystem,
category, process/activity identifiers, and privacy/redaction context.
**Correlate:** filesystem, FSEvents, Endpoint Security/EDR, application logs,
and user/session data. **Limit:** retention, loss, private fields, disabled
categories, and rendered export affect completeness.

## A.39 macOS FSEvents

**Question:** What volume-level filesystem change events were recorded?
**Collect:** event stores, volume UUID, event IDs, flags, paths, rollover/gaps,
and parser/version. **Correlate:** APFS metadata/snapshots, Spotlight,
application logs, Unified Logs, and endpoint telemetry. **Limit:** events can be
coalesced and do not form a complete per-file actor audit trail.

## A.40 macOS TCC Database

**Question:** What privacy-control decisions were recorded for clients and
services? **Collect:** system/user databases plus WAL/SHM, schema/build, service,
client type/identity, decision, indirect object, and modification metadata.
**Correlate:** code signature, application bundle, Unified Logs, process and
file activity, and management policy. **Limit:** a grant does not prove use;
live access protections and schema changes affect collection/interpretation.

## A.41 macOS LaunchAgent or LaunchDaemon

**Question:** What launchd job was configured and what supports execution?
**Collect:** plist bytes and metadata, label, program/arguments, triggers,
environment, user/domain, associated executable, loaded state, and logs.
**Correlate:** code signature, quarantine, FSEvents, Unified Logs, process,
network, and management inventory. **Limit:** plist presence or loaded state
does not alone establish maliciousness or each execution.

## A.42 AWS CloudTrail Event

**Question:** What AWS API activity was logged under configured coverage?
**Collect:** raw event, account/region, event/source/name, event ID, principal
and session, source/user agent, request/response, resources, readOnly,
management/data category, and ingestion source. **Correlate:** trail
configuration/digests, identity, service data logs, flow/DNS, and resource
state. **Limit:** selectors, regions, retention, service behavior, and eventual
delivery limit coverage.

## A.43 Entra Sign-In

**Question:** What authentication attempt and policy context did Entra record?
**Collect:** sign-in type, correlation/request IDs, principal/app/resource,
client, IP/location, device, authentication details, Conditional Access, risk,
status, and raw record. **Correlate:** directory audit, endpoint, VPN/proxy,
M365 actions, token/session revocation, and application logs. **Limit:** IP
geolocation and risk are contextual; sign-in does not enumerate all token use.

## A.44 Microsoft 365 Audit Record

**Question:** What workload action did Purview Audit retain? **Collect:** raw
record, tenant, workload/record type, operation, user/session, object, client,
time, result, query/export job, pagination/count, license and retention.
**Correlate:** Entra, mailbox/SharePoint/OneDrive/Teams detail, endpoint, and
network. **Limit:** workload enablement, schema, licensing, delayed ingestion,
and retention prevent treating it as a complete universal ledger.

## A.45 Docker Container Metadata

**Question:** What runtime configuration and state existed for a container?
**Collect:** container/image digest, inspect output, creation/start/stop,
command/env with secret handling, mounts, networks, labels, restart, writable
layer, logs, runtime/node, and daemon audit. **Correlate:** orchestrator,
registry, host process/network, volumes, cloud, and application logs. **Limit:**
export omits some mounts/runtime state; live commands change evidence.

## A.46 Kubernetes Pod

**Question:** What desired and observed workload state did the API record?
**Collect:** YAML/JSON with UID/resourceVersion, owner references, namespace,
node, containers/images/digests, service account, volumes, status, events,
current/previous logs, audit, and times. **Correlate:** controller, node/runtime,
registry, cloud, network, and volume snapshots. **Limit:** objects and Events are
ephemeral; separate API calls are not one atomic snapshot.

## A.47 Windows Memory Process Object

**Question:** What process structure was recoverable from memory? **Collect:**
object offset, PID/PPID, create/exit, active-list and scan status, threads,
handles, token/session, command/environment, VADs, modules, and image layer.
**Correlate:** endpoint events, services/tasks, files, sockets, user session,
and known build ancestry. **Limit:** scanned objects can be stale/partial; PID
reuse and acquisition non-atomicity prevent simplistic joins.

## A.48 Memory VAD Candidate

**Question:** What mapped/private address range has properties relevant to
injection or unpacking? **Collect:** process/object, range, size, protection,
tag, backing file, bytes, disassembly, strings, YARA, thread starts, and dump
hash. **Correlate:** module lists, PE mapping, process behavior, telemetry, and
known JIT/security software. **Limit:** `malfind` and similar output is
heuristic; legitimate executable private memory is common.

## A.49 Memory Network Endpoint

**Question:** What socket/endpoint structure was recoverable and to which
process might it relate? **Collect:** object, protocol/family, addresses/ports,
state, owner PID/object, creation time, and structural validity. **Correlate:**
process lifetime, DNS, firewall, PCAP/flow, proxy, routing, VPN, and EDR.
**Limit:** structures may be stale or partial; an endpoint does not prove
successful communication or content.

## A.50 Chromium History

**Question:** What navigation/download records were stored in a Chromium
profile? **Collect:** History database with WAL/SHM, schema/browser version,
profile identity, URLs, visits, transitions, referrers, downloads, and exact
timestamp conversion. **Correlate:** sessions, cache, cookies under authority,
endpoint process/network, proxy, and sync metadata. **Limit:** redirects, sync,
restore, automated navigation, and database loss complicate human-intent claims.

## A.51 Firefox `places.sqlite`

**Question:** What history/bookmark relationships did Firefox store? **Collect:**
database plus WAL/SHM, profile/version, places, visits, transition types,
bookmarks, annotations, and timestamp units. **Correlate:** sessionstore,
downloads, cache, cookies under authority, network, endpoint, and sync.
**Limit:** schema and retention change; stored URL activity does not always
represent deliberate user navigation.

## A.52 Email `Received` Chain

**Question:** What route can be reconstructed from trusted mail-system headers?
**Collect:** original message bytes, all `Received` fields, Authentication-
Results, Message-ID, Date, DKIM fields, and receiving-system trust boundary.
**Correlate:** provider trace, gateway, DNS history, account audit, endpoint, and
network. **Limit:** sender-side headers can be forged; clocks, relays, forwarding,
and current DNS prevent naive top-to-bottom attribution.

## A.53 SPF Result

**Question:** Was the connecting IP authorized for the evaluated envelope
domain under the receiver's SPF evaluation? **Collect:** receiver result,
identity, IP, HELO/mail-from, DNS evidence, and time. **Correlate:** DKIM/DMARC,
route, provider trace, and message content. **Limit:** SPF does not authenticate
the visible From or message content; forwarding and historical DNS affect
interpretation.

## A.54 DKIM Signature

**Question:** Does a preserved message validate under a domain's DKIM signature
and key? **Collect:** raw bytes, `d`, `s`, `h`, canonicalization, body-length,
signature, receiver result, DNS key at relevant time, and validation tool.
**Correlate:** DMARC alignment, provider trace, account and sending platform.
**Limit:** pass authenticates a signing-domain assertion over selected content,
not the human sender, safety, or all unsigned headers.

## A.55 Packet Capture

**Question:** What frames/packets were observed at a defined sensor?
**Collect:** original PCAP/PCAPNG, sensor/interface, topology/direction, filter,
snap length, clock/precision, loss counters, offload, rotation, format, and
digest. **Correlate:** flow, firewall, DNS, proxy, endpoint, server, and routing.
**Limit:** capture-point visibility, asymmetry, loss, truncation, and encryption
bound conclusions.

## A.56 DNS Observation

**Question:** What query/response did a specific DNS vantage point observe?
**Collect:** client/resolver/server role, query name/type, response code,
answers, TTL, transaction/timing, transport, and policy. **Correlate:** endpoint
process/cache, network connection, passive DNS with time, proxy, and identity.
**Limit:** query does not prove answer use or connection; cache, encrypted DNS,
and aliases obscure paths.

## A.57 Network Flow Record

**Question:** What summarized conversation did a flow exporter record?
**Collect:** exporter, interfaces/direction, five-tuple, start/end, packets,
bytes, TCP flags, sampling, active/inactive timeout, NAT fields, and clock.
**Correlate:** PCAP, firewall, DNS, proxy, endpoint, and topology. **Limit:**
flows omit payload and can split/aggregate sessions; sampling and asymmetry
affect volume and direction.

## A.58 PE File

**Question:** What structure and static capabilities does a Windows PE sample
contain? **Collect:** original bytes/hash, headers, sections, directories,
entry point, imports/exports, resources, TLS, signature, debug, overlay,
strings, and parser. **Correlate:** disassembly, runtime behavior, memory,
delivery, endpoint telemetry, and trusted intelligence. **Limit:** timestamps,
imports, names, and signatures can mislead; capability is not observed
execution.

## A.59 YARA Match

**Question:** Which exact rule condition matched which scanned representation?
**Collect:** rule ID/version/digest, engine/version, command, scope, input hash,
namespace, matched offsets/strings where safe, and time. **Correlate:** file
structure, code/configuration, behavior, family corpus, and false-positive
tests. **Limit:** a match is not automatic attribution, execution, or
maliciousness; packed/memory/file views differ.

## A.60 Sigma Match

**Question:** Which normalized event selection matched a detection condition?
**Collect:** rule ID/version, backend and pipeline, generated query, data model,
time range, raw matching events, result counts, and exclusions. **Correlate:**
source-native records, endpoint behavior, related identities/hosts, and test
fixtures. **Limit:** portability requires mapping; syntax success does not prove
coverage, correctness, performance, or intent.

## A.61 LSASS Access Signal

**Question:** What process access or memory behavior suggests credential-target
interaction? **Collect:** source/target process identity, access rights/call
trace if available, signer, user/privilege, time, memory/file effects, and
security alerts. **Correlate:** process tree, driver/security product, follow-on
authentication, and host role. **Limit:** security, backup, and support tools
can legitimately access LSASS; an alert name is not proof of credential theft.

## A.62 Directory Replication Signal

**Question:** What account/system requested directory replication-like access?
**Collect:** directory-service auditing, object/GUID/access mask, principal,
DC, time, network/process/identity context, and privilege changes. **Correlate:**
replication topology, legitimate products, endpoint, account baseline, and
subsequent credential use. **Limit:** domain controllers and approved identity
systems replicate legitimately; missing auditing creates gaps.

## A.63 PLC Logic or Project

**Question:** What controller program/configuration and change context can be
safely acquired? **Collect:** authorization and safety plan, asset/firmware,
mode, project/logic version, checksum, upload method/tool, engineering baseline,
change/download logs, time, and process state. **Correlate:** HMI, historian,
engineering workstation, network, vendor management, and change control.
**Limit:** uploads can affect operations and may omit source symbols/comments;
vendor procedures govern safety.

## A.64 Mobile Backup

**Question:** What device/application data did a supported backup method export?
**Collect:** device/OS/build, lock/encryption, backup type/tool/version, start
and end, manifest, encryption/key handling, files/databases, errors, and hash.
**Correlate:** full-filesystem or cloud sources, paired computer, application
schemas, account audit, and device timeline. **Limit:** backups are selective
and can transform metadata; absence does not prove device absence.

## A.65 Firmware Image

**Question:** What code, filesystems, configuration, and trust metadata are
present in firmware? **Collect:** source hardware/package, acquisition method,
repeated-read hashes, headers/partitions, compression, checksums/signatures,
architecture, boot chain, filesystems, and extractor/version. **Correlate:**
vendor release, device/cloud/app behavior, debug logs, and known-good device.
**Limit:** heuristic extraction can create false boundaries; updates may be
encrypted, delta-based, or device-specific.

## A.66 MVT Finding

**Question:** Which MVT check or supplied indicator matched supported mobile
artifacts? **Collect:** MVT version, acquisition/input type, IOC source/date,
command, warnings, raw finding, artifact path/record, and device build.
**Correlate:** original database/log, independent parser, account/network data,
vendor research, and case timeline. **Limit:** MVT is not universal acquisition
or complete compromise detection; no match does not prove a clean device.
