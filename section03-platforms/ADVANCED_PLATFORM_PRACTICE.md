# Part 03 Field Practice: Linux, macOS, Cloud, and Containers

## 3.5 Linux Examination Model

Identify distribution, release, kernel, init system, filesystem, package
manager, security modules, audit configuration, container runtime, timezone,
and centralized logging. Do not assume `/var/log/auth.log`: Debian-family and
Red Hat-family systems differ, journald can be volatile or persistent, and
applications may log only remotely.

Acquire filesystem metadata and journals when possible, not only selected
files. Preserve `/etc`, account databases, sudo configuration and logs, PAM and
SSH configuration, cron and systemd definitions, package databases, shell
profiles and histories, audit records, journal directories, web/application
logs, cloud-agent state, kernel messages, temporary directories, user homes,
and relevant `/proc` data during live response.

Linux timestamps do not include a universal creation time across all
filesystems and tools. `ctime` is inode status-change time, not creation time.
Birth time may exist but is not guaranteed to be exposed or preserved. Mount
options, overlay filesystems, snapshots, and backup/restore affect semantics.

## 3.6 journald and Traditional Logs

Journald records structured fields, boot identifiers, monotonic and realtime
timestamps, transport, unit, executable, PID, UID, and other metadata depending
on source. Exporting only rendered text discards structure. Acquire journal
files and record whether storage was volatile, persistent, forwarded, rotated,
vacuumed, sealed, or corrupted.

Use a forensic copy where possible. A live `journalctl` query creates access
effects and renders according to installed system libraries. Preserve JSON or
journal-native data plus the exact query. A PID can be reused; correlate
`_BOOT_ID`, unit, executable, audit session, and process start.

Traditional syslog files can be rotated, compressed, forwarded, duplicated, or
delayed. Record rotation configuration and collect numbered/compressed
siblings. Timestamps may omit year or offset. Infer missing context only when
supported by filename sequence, surrounding records, system uptime, and an
explicit limitation.

## 3.7 Linux Persistence and Identity

Review system and user crontabs, `/etc/cron.*`, `anacron`, `at` spools, systemd
services/timers/path units, generators, environment files, init scripts,
desktop autostart, shell profiles, dynamic-loader configuration, kernel
modules, udev rules, package hooks, and cloud-init. A file's presence does not
show its trigger fired.

For systemd, collect unit files from all precedence paths, enabled symlinks,
drop-ins, transient units, journal records, and `systemctl show` output during
authorized live response. Determine the effective merged unit; inspecting only
the vendor file can miss an override.

Identity analysis should cover local accounts, directory services, SSH keys,
certificates, sudo, PAM, polkit, login sessions, namespaces, and service
accounts. An `authorized_keys` line requires parsing of options and key
fingerprint. Comments are not authenticated identities. Compare against
configuration management and known-good inventories.

## 3.8 Recovering Deleted Running Objects

On a live Linux system, `/proc/<pid>/exe` can reference a deleted executable and
`/proc/<pid>/fd` can expose open deleted files. Acquisition is time-sensitive.
Record PID, start time, namespace/cgroup, mount view, maps, command line,
environment handling, open descriptors, credentials, and hashes before copying.

Reading `/proc` changes system state and can expose secrets. A copied
`/proc/<pid>/exe` representation may not reproduce on-disk metadata, extended
attributes, capabilities, deleted mappings, injected pages, or runtime
modifications. Acquire memory when justified and correlate executable mappings,
package databases, filesystem journal, audit/EDR, and network activity.

## 3.9 macOS Examination Model

Record hardware model, architecture, macOS build, APFS containers and volumes,
FileVault state, Secure Enclave implications, logged-in users, timezone,
System/Data volume relationships, snapshots, and privacy protections. Modern
macOS uses signed/sealed system concepts and firmlinks; a simple directory copy
does not represent the full storage model.

Collect APFS metadata through validated tools, Data volume user and system
artifacts, Unified Logs, FSEvents, Spotlight metadata where authorized, plists
and binary plists, launchd configuration, quarantine and extended attributes,
TCC databases, knowledge databases, browser and application containers,
Keychain-related evidence under proper authority, and relevant snapshots.

Full Disk Access, SIP, TCC, sandboxing, and FileVault affect live acquisition.
Do not disable protections casually; doing so changes the system and may not be
authorized. Prefer approved endpoint, recovery, backup, or snapshot methods.

## 3.10 APFS, Unified Logs, FSEvents, and TCC

APFS snapshots are volume-specific point-in-time references with copy-on-write
semantics. Record volume UUID, snapshot transaction identifier/name, creation
time, role, mount/export method, and parent/container context. Snapshot
existence and retention change; a mounted snapshot can still be examined
through tools that alter access metadata outside the snapshot.

Unified Logging can contain public, private, redacted, signposted, and
loss-affected data. Preserve log archives or store files rather than only
`log show` text. Record predicate, times, timezone, host build, and command.
Absence may result from retention, privacy redaction, disabled categories, or
collection gaps.

FSEvents describes filesystem-change events at a coarse level and can coalesce
operations. It is not a complete per-file audit trail and does not necessarily
identify the actor. Correlate event IDs, paths, flags, volumes, Spotlight,
filesystem metadata, application logs, and endpoint telemetry.

TCC databases record privacy decisions and related metadata under
version-dependent schemas. A granted row does not prove the capability was
used. System and user databases differ; acquire associated WAL/SHM files and
identify code-signing identity, client type, service, decision, and modification
context.

## 3.11 Cloud Evidence Architecture

Cloud forensics begins with control-plane identity and provenance. Record
organization/account/tenant/subscription/project, region, resource IDs,
collector identity, role and session, API version, query, pagination,
start/end, timezone, export job ID, retention tier, and digest of downloaded
results.

Preserve:

- identity sign-in, risk, directory, and application-consent events;
- control-plane audit and policy changes;
- data-plane access where enabled;
- network flow, DNS, load-balancer, WAF, and proxy records;
- storage object versions, access logs, and retention settings;
- workload snapshots, images, serverless code/configuration, and secrets
  metadata under authority;
- security-product alerts plus raw supporting events;
- billing and resource-inventory history.

Provider consoles often summarize or limit data. Prefer documented APIs or
export jobs and prove pagination completeness. Record throttling, partial
failure, late-arriving events, schema changes, and timestamp semantics. Cloud
logs can be eventually consistent; collection time is not event time.

## 3.12 AWS CloudTrail, Entra, and Microsoft 365

CloudTrail management events, data events, Insights, network activity events,
and service-specific logs have different enablement and cost. Event history is
not equivalent to a complete configured trail or Lake. Validate trail scope,
regions, organization coverage, selectors, destinations, digest validation,
and retention. `sourceIPAddress` may identify an AWS service, proxy, or shared
egress rather than a person's device.

For Entra, separate interactive and non-interactive sign-ins, service
principals, managed identities, workload identity, risky-user/risk detections,
directory audit, and provisioning. Conditional Access status, device context,
authentication requirement, token/session behavior, and correlation IDs help,
but sign-in data does not reveal every action performed with a token.

Microsoft Purview Audit availability, retention, workloads, record types, and
search/export interfaces depend on licensing and configuration. Preserve the
query, job identity, result count, session/pagination behavior, and raw records.
Correlate mailbox, SharePoint, OneDrive, Teams, Entra, endpoint, and network
sources rather than treating Unified Audit as a perfect universal ledger.

## 3.13 Container and Kubernetes Evidence

Containers are processes using namespaces, cgroups, layered filesystems, and
runtime metadata; they are not automatically isolated evidence boxes. Identify
runtime, orchestrator, node, pod, namespace, container ID, image digest,
deployment owner, service account, volumes, secrets references, network policy,
and restart history.

Prioritize ephemeral evidence:

1. orchestrator API metadata and audit records;
2. current and previous container logs;
3. runtime and node process/network state;
4. writable layers and mounted volumes;
5. image manifests, signatures, SBOM/provenance, and registry audit;
6. control-plane and cloud-provider logs;
7. memory or node snapshot when risk and authority justify it.

`kubectl exec`, `cp`, debug containers, scaling, deletion, and cordon/drain
operations change state and create audit evidence. Prefer read-only API
retrieval and provider snapshot functions first. Record resource versions so
objects collected at different times are not misrepresented as one consistent
snapshot.

Kubernetes Events are best-effort and short-lived, not an audit substitute.
Container stdout/stderr may be rotated on nodes. A deleted pod may leave logs,
runtime state, volumes, registry activity, and control-plane audit records, but
retention varies. Establish collection automation before incidents.

## 3.14 Platform Reporting Controls

For every Linux, macOS, cloud, or container conclusion, state the observed
source and platform version, acquisition view, relevant enablement/retention,
parser/tool version, clock limitations, and corroborating source. Explicitly
identify data that could not be collected.

Avoid statements such as "the cloud logs show everything," "the container was
immutable," or "no journal entry means the command did not run." Prefer bounded
language: the acquired records for named sources and intervals contained or did
not contain defined observations under documented query and retention limits.
