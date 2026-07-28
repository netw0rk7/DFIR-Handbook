# Part 01 Field Practice: Scoping, Collection, and Quality Control

## 1.8 Case Triage and Scope Control

The first decision is usually not which tool to run. It is what question the
examination is authorized and able to answer. An unbounded request such as
"find everything the attacker did" is not a defensible scope. Translate it into
testable questions:

- Which identities, systems, tenants, and locations are potentially involved?
- What is the earliest and latest relevant time?
- Which business, safety, privacy, privilege, and legal constraints apply?
- Which sources could answer each question, and how long are they retained?
- Which decisions must the investigation support?
- What observation would falsify the leading explanation?

Record inclusions and exclusions. A mailbox collection may be limited to
specific custodians, dates, folders, and message classes. Endpoint collection
may be constrained by geography, employee status, encryption, criticality, or
privileged data. Cloud tenants may contain data governed by different contracts
and jurisdictions. Scope changes should be approved and logged rather than
allowed to grow informally.

### Investigation Question Matrix

| Question | Candidate sources | Important limitation |
|---|---|---|
| Was an account used interactively? | Identity sign-ins, endpoint logons, VPN, EDR | Authentication does not establish who controlled the credential |
| Did a file execute? | Process telemetry, Prefetch, UserAssist, memory, application logs | Inventory and compatibility artifacts are not proof of execution |
| Was data exfiltrated? | Proxy, DNS, flow, PCAP, endpoint access, cloud audit | Encrypted traffic and incomplete egress visibility may hide content |
| Was persistence established? | Services, tasks, autoruns, startup items, cloud credentials | Legitimate administration can create similar artifacts |
| Was evidence altered? | Audit gaps, metadata divergence, clearing and policy events | Retention and normal maintenance are alternative explanations |

The matrix prevents artifact tourism: collecting interesting facts that do not
answer the case questions. It also exposes negative evidence. If a source was
not enabled, was outside retention, or was never acquired, absence of a record
cannot be interpreted as absence of an event.

### Hypotheses and Competing Explanations

A useful hypothesis predicts evidence:

> H1: An external actor used a phished employee session to download files from
> a cloud repository between 08:00 and 11:00 UTC.

Predictions might include a new sign-in context, token or application activity,
repository access, abnormal download volume, endpoint browser artifacts, and
network egress. A competing explanation could be authorized travel through a
consumer VPN. Seek observations that discriminate between explanations instead
of collecting only evidence that confirms H1.

Preserve hypothesis revisions in the case notes. The revision history shows
that conclusions developed from evidence rather than hindsight.

## 1.9 First-Responder Scene Management

Digital scenes include more than a visible computer. Consider connected
storage, docking stations, tokens, mobile devices, displays, printers, network
equipment, removable media, handwritten credentials, cameras, access-control
systems, cloud consoles, hypervisors, and remote sessions. Coordinate physical
and cyber scene control so one team does not destroy evidence another needs.

Before touching a device, when safety and authority permit:

1. identify the response lead and legal authority;
2. record date, time, timezone, location, responder, and scene condition;
3. photograph the scene and cable relationships;
4. record what is displayed without navigating through the system;
5. note power, network, encryption, logged-in users, visible applications, and
   attached media;
6. identify volatile and remotely destructible evidence;
7. decide whether isolation, live collection, or shutdown is justified;
8. document every interaction and observed change.

Photographs provide context but do not replace acquisition. Avoid unnecessarily
staging sensitive content in a photograph. Apply organizational handling rules
to biometric data, personal information, privileged communications, and
classified material.

### Isolation and Shutdown

Isolation can stop command-and-control, movement, exfiltration, and remote
destruction. It can also terminate sessions, lose volatile keys, trigger
malware, interrupt safety-critical processes, and remove access to cloud-only
evidence. Options include EDR containment, switch-port or wireless isolation,
firewall policy, a controlled forensic network, or physical disconnection.
Confirm effectiveness: a console showing a requested action is not the same as
verified containment.

A graceful shutdown invokes application and operating-system code, changes
files, flushes caches, writes logs, and may run attacker-controlled tasks.
Removing power avoids those shutdown writes but loses volatile data and can
damage active storage or applications. Hibernation is not a lossless universal
memory-acquisition method. Choose based on volatility, encryption, active risk,
system role, live-collection footprint, snapshot capability, authority, and
policy. Record the alternatives and rationale.

## 1.10 Evidence Inventory and Time

Assign every item a unique identifier that is never reused. An evidence item is
not merely "the laptop"; it may include the physical device, storage media,
memory image, logical export, photographs, logs, tool output, and working copy.
Relationships between parent and derived items must be explicit.

At minimum, record:

- case and evidence identifiers;
- description, manufacturer, model, serial, asset tag, and condition;
- source person, system, tenant, account, path, volume, or API;
- location and system timezone;
- acquisition type and scope;
- collection start and end with timezone;
- collector and witness when required;
- tool, version, configuration, and command;
- destination and byte size;
- cryptographic digest and verification result;
- packaging, seal, storage, and transfer history;
- errors, retries, bad sectors, inaccessible content, and deviations.

Do not expose secrets in filenames or issue titles. Evidence manifests can
themselves reveal identities, paths, case subjects, and infrastructure.

Record time in an unambiguous form such as
`2026-07-28T14:05:09+07:00`. Preserve source-native values and document
conversion. Measure clock offset rather than silently correcting evidence.
Record the trusted source, its uncertainty, observed target time, signed
difference, and measurement time. A present-day offset may not correct historic
events because of manual changes, virtualization, NTP steps, suspend/resume,
daylight-saving transitions, or drift.

## 1.11 Chain of Custody Beyond Physical Media

Chain of custody demonstrates control and accountability from identification
through disposition. It does not, by itself, prove that acquisition was
technically correct. Integrity records, validated methods, access controls, and
examiner testimony work together.

Each transfer should identify the evidence, time and timezone, releasing and
receiving parties, purpose, locations, packaging and seal condition, approval,
and discrepancy. For digital transfers, also record repositories,
authenticated identities, access-control changes, transport encryption,
manifest digest, verification, and audit-log reference.

Evidence storage should provide least privilege, strong authentication,
encryption, audit logging, retention control, environmental protection,
capacity monitoring, tested recovery, and documented disposition. Immutable
storage reduces some risks but does not remove administrator, retention,
encryption-key, replication, or account-compromise risks.

Analysts normally examine a verified working copy and preserve the master under
policy. Derived files need hashes and a recorded relationship to the source and
producing process.

## 1.12 Integrity and Manifests

A cryptographic digest shows that two byte sequences match under an algorithm.
It does not prove that bytes came from the claimed device, that a tool
interpreted them correctly, or that the source was unaltered before collection.
Those propositions require provenance, procedure, validation, and
corroboration.

Use SHA-256 or SHA-512 for integrity. MD5 and SHA-1 may remain in legacy image
formats or duplicate workflows; if interoperability requires them, pair them
with a modern digest and do not rely on their collision resistance.

Hash the acquired image or container, exported files where bytes are stable,
manifests, logs, important derived artifacts, report exhibits, and final
archives. For segmented images, preserve segment hashes and a tool-supported
verification of the logical image. Hashing a compressed E01 container is not
the same as verifying logical media content stored inside it.

A manifest should include evidence ID, relative path or object ID, size,
algorithm, digest, acquisition time, tool, and encoding. Define handling for
symlinks, sparse files, streams, extended attributes, hard links, case-sensitive
names, and cloud versions. A signed manifest can add authentication, but key
custody then joins the evidence trust model.

Verify after acquisition, transfer, working-copy creation, storage transition,
exhibit preparation, and authorized disposition. An unexplained mismatch is
not fixed by recomputing the expected value. Preserve both versions, stop
uncontrolled handling, investigate, and report the discrepancy.

## 1.13 Tool Validation and Method Verification

Tool validation asks whether a method is fit for an intended purpose under
defined conditions. A command completing without error is not validation.

A minimum validation record contains:

- tool, version, trusted source, package digest, and dependencies;
- platform and relevant configuration;
- intended function and limitations;
- known test dataset and expected result;
- observed result, including errors and false results;
- treatment of damaged, malformed, encrypted, sparse, or unsupported data;
- repeatability and independent reproduction;
- reviewer, date, and approval status.

Use published test images when they match the function, plus internal fixtures
for environment-specific artifacts. A parser tested against one schema version
is not automatically valid for later versions.

Agreement between two programs matters only if they are independent enough to
fail differently. Two interfaces may use the same library. Compare raw
structures, specifications, source code, alternative parsers, and known ground
truth. Investigate disagreements rather than selecting the output that best
fits the hypothesis.

Record exact versions and preserve installers or container images when policy
and licensing permit. Preserve rules, symbols, plugins, timezone data, and
configuration. Results from live reputation services or changing threat feeds
require provider, query time, response, and available snapshot or export.

## 1.14 Physical Disk Acquisition Playbook

For a powered-off physical device:

1. confirm authority, identity, and destination capacity;
2. photograph and label the device and interfaces;
3. connect through a tested hardware write blocker when supported;
4. verify blocker behavior and identify the source without a read-write mount;
5. record geometry, sector sizes, partitions, health, and anomalies;
6. acquire with an appropriate format and documented error policy;
7. capture logs, bad-sector handling, and identifiers;
8. verify logical image content and compute a modern digest;
9. secure the master and create a verified working copy.

The log must distinguish unreadable sectors from tool-filled sectors. A
completed image with errors is not a complete image. Report what could not be
read and how retries, timeouts, and substitutions were configured.

Live disk acquisition may be necessary for encryption, availability, remote
systems, or irremovable storage. The source changes while it is read, so a
whole-image hash does not establish an ordinary active filesystem as a single
point-in-time state. Prefer an application-consistent or storage/hypervisor
snapshot when justified. Record mounts, encryption, open files, processes,
network state, time, users, and collector footprint.

### SSD and RAID Caveats

TRIM, garbage collection, controller behavior, over-provisioning, encryption,
and wear leveling mean magnetic-media assumptions about deleted data may not
apply to SSDs. No universal power-state procedure guarantees recovery. Record
model, interface, controller, encryption, and issued commands.

For RAID, record controller and firmware, member order and slots, serials,
reported state, level, stripe, parity layout, offsets, sector size, and vendor
metadata. Photograph bays and cabling. Do not initialize, rebuild, or import a
foreign configuration without an approved plan. Acquire members and
configuration/log exports where feasible; reconstruct on working copies.

## 1.15 Acquisition Representations

Raw images are simple and interoperable but provide no inherent case metadata,
segmentation, compression, or internal integrity records. Expert Witness Format
variants provide metadata, compression, segmentation, and checks, but features
vary by implementation. AFF4 can represent sparse and complex address spaces,
but interoperability must be tested.

A logical acquisition collects selected objects through an OS, API, backup, or
application view. It can preserve rich metadata but may omit unallocated space,
slack, inaccessible objects, unsupported streams, or lower storage layers. A
targeted acquisition collects selected physical ranges. Fitness depends on the
question, authority, time, storage, and technical constraints.

Always record acquisition level, included and excluded namespaces, treatment of
deleted data, metadata preservation, compression, segmentation, encryption,
deduplication, verification semantics, and dependencies needed for future
reading.

## 1.16 Memory Acquisition Playbook

Memory acquisition executes code on the target and changes memory. The objective
is a proportionate capture with a known footprint, not zero alteration.

Before collection:

- pre-stage a trusted, hashed collector;
- verify support for the exact OS and architecture;
- estimate size and choose a safe destination;
- compare the risks of local and network output;
- preserve endpoint-security alerts and authorize any exclusion;
- record target time offset;
- plan for failure or instability.

Record start/end, command, console output, exit status, size, digest,
destination, and visible effects. Near the same time, preserve process,
service, connection, session, routing, neighbor, mount, encryption, system
time, container, and VM context. Native listings do not replace a memory image,
but they corroborate it.

Do not discard a partial image. Hash and preserve it, record failure and assess
what remains usable. A second attempt changes the target further and requires a
rationale. Crash dumps, hibernation files, and VM memory states are separate
sources with different semantics.

RAM may contain passwords, tokens, messages, private keys, plaintext documents,
and unrelated personal or tenant data. Restrict access, encrypt transfer and
storage, avoid public analysis services, and apply authorized minimization and
retention.

## 1.17 Virtual, Cloud, and Remote Acquisition

Hypervisor snapshots can acquire disks and memory with little guest tooling,
but can stun a VM, affect consistency, create delta disks, and change
infrastructure logs. Record snapshot ID, host and hypervisor, guest identity,
included disks, memory inclusion, quiescing, parent relationships, times, and
export method. Preserve management-plane audit logs.

Cloud disk workflows often snapshot, copy to a forensic account, export, and
verify. Understand consistency, keys, account and region boundaries,
incremental semantics, API pagination, retention, and audit events created. A
dedicated evidence account or project should use restricted roles and logging.

For remote collection, document authentication and delivery of the collector,
execution identity, endpoint identity, transport security, completeness and
ordering controls, retries, temporary copies, and interruption behavior. Hash
at the endpoint when feasible and verify after transport. Matching transport
digests detect change; they do not prove that a compromised endpoint supplied
truthful bytes.

## 1.18 Acquisition Quality Gate

Before analysis, a second person or automated control should verify:

- authority and scope are recorded;
- evidence and destination IDs agree with the case record;
- serials, paths, accounts, regions, and tenant IDs agree;
- start/end and timezone are present;
- tool and version are recorded;
- source state, isolation, write blocking, and encryption are described;
- acquisition level and omissions are explicit;
- no fatal error remains unresolved;
- output size is plausible;
- digest and internal verification passed;
- master and working copies are distinguished;
- access, encryption, backup, and retention are applied;
- deviations and limitations are ready to report.

Quality control is not a ceremonial signature. A reviewer should be able to
reconstruct the acquisition and identify every unsupported assumption.
