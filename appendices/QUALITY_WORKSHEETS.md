# Appendix B: Professional Quality Worksheets

These worksheets are designed to be copied into an authorized case-management
system. Replace documentation examples with case-specific values and apply
local legal, privacy, retention, and security requirements.

## B.1 Investigation Plan

Record the case identifier, requestor, incident commander, evidence lead,
technical lead, legal/privacy contacts, business owner, safety contact, and
communication channels. State the authority and the exact questions to answer.
Define included and excluded people, systems, accounts, tenants, regions, data
types, and time intervals.

For each question, list predicted observations, candidate sources, source owner,
retention, collection method, priority, and known limitation. Identify
alternative explanations and what would discriminate between them. Record
urgent preservation actions and their deadlines.

Define handling classification, storage, access group, encryption, transfer,
review, disclosure, retention, and disposition. Identify whether secrets,
privileged material, health data, payment data, regulated records, or
cross-border data may be encountered.

Define decision points: isolation, shutdown, account action, key rotation,
external notification, law enforcement, eradication, restoration, and public
communication. Name the person authorized to decide each and the evidence/risk
threshold.

The plan is versioned. For every revision record time, author, approval,
reason, added/removed scope, and effect on already collected evidence. Closing
review confirms which questions were answered, which remain unresolved, and
which could not be answered from available sources.

## B.2 Evidence Collection Worksheet

Create one worksheet per source. Record case/evidence ID, source description,
owner/custodian, physical or logical location, hardware/account/resource
identifiers, system role, platform/build, timezone, clock offset, power and
network state, encryption, and photographs or screenshots.

Record authority, approved scope, collection method and representation,
included/excluded namespaces, source consistency model, collector identity,
tool/version/digest, configuration, exact command or API request, start/end
with timezone, destination, byte size, errors, retries, warnings, and created
audit events.

For physical media, add blocker details, interfaces, sector sizes, partitions,
health, unreadable ranges, and error substitution. For cloud/API collection,
add tenant/account/region, role/session, API version, query, pagination,
throttling, export job, result count, retention/license, and eventual-delivery
limitations. For live collection, list each known footprint.

Record digest algorithm/value for every stable representation, internal image
verification, manifest identity, transfer verification, master/working-copy
designation, storage path, access control, backup, and retention.

Reviewer checks source/destination identity, scope, time, errors, plausible
size, digest, readable format, and documentation completeness. Deviations are
not hidden: describe cause, affected data, mitigation, approval, and reporting
impact.

## B.3 Artifact Interpretation Worksheet

Identify the exact proposition being evaluated. Name evidence ID, artifact,
path/table/record/object/offset, acquisition view, parser/tool/version,
configuration, source-native timestamp, normalized timestamp, timezone
conversion, and raw-output location.

Write the **observation** using only values directly supported by the source.
Write the artifact's documented **semantics** for the relevant platform and
version. List validation evidence: specification, official documentation,
known-action test, alternate parser, or raw-structure inspection.

Write the **interpretation** and confidence. Then list at least one plausible
alternative explanation. Record **corroboration** from an independent source
and explain why it supports or contradicts the interpretation. Independence
matters: two interfaces using one parser are not two methods.

List limitations: enablement, retention, rollover, schema, clock, acquisition
consistency, parser support, corruption, encryption, missing companion files,
normal administrative behavior, attacker control, and unavailable sources.

Draft the exact report sentence. Replace absolute language with bounded claims
unless logic truly requires the conclusion. A reviewer should be able to move
from report sentence to worksheet, raw record, acquisition, and source item
without undocumented steps.

## B.4 Timeline Event Schema

Each normalized event retains `event_time`, original time text/value,
timezone/offset, precision, timestamp meaning, ingestion or collection time,
evidence ID, source type, source path/object, parser/version, host/resource,
account/SID, process/object IDs, action, target, source/destination network
values, and raw-record reference.

Add `observation` in source-level language, `interpretation` separately,
confidence, alternative explanation, corroborating event IDs, ATT&CK mapping
only when behavior supports it, and limitations. Preserve null as unknown; do
not replace it with zero, false, or an invented default.

Record clock-offset measurement, correction method if a derived corrected time
is created, and uncertainty. Keep original values immutable. Precision controls
ordering: events recorded only to a second cannot be confidently ordered within
that second without another sequence source.

Maintain stable event IDs so annotations do not change when sorting. Record
deduplication logic and never delete a source record merely because another
looks similar. Distinguish a provider duplicate, forwarded copy, analyst
milestone, inferred interval, and directly observed event.

Every published timeline view stores its query/filter, sort keys, timezone,
columns, generation tool/version, output digest, author, and date. Review
apparently causal sequences for clock error, batching, delayed delivery, record
rollover, restore, and parser normalization.

## B.5 Detection Validation Worksheet

Identify detection ID, version, owner, purpose, threat hypothesis, ATT&CK
version/technique where appropriate, platforms, required log source, source
enablement, expected fields, data model, and retention. For Sigma, record rule,
sigma-cli/pySigma versions, backend, processing pipeline, and generated query.

Define positive fixtures from authorized simulations or sanitized known data,
near-neighbor cases, expected benign cases, malformed/missing-field cases, and
a representative performance dataset. Record expected and observed matches,
false positives, false negatives, query errors, runtime, scan volume, and
resource use.

Validate the chain: behavior occurred; sensor produced the source event;
transport delivered it; parser normalized it; storage retained it; query
matched; alert enriched and routed; analyst received enough context; response
was safe and authorized.

Document every suppression and exception with rationale, owner, scope,
approval, expiration, match volume, and attacker-abuse risk. Broad exclusions
for administrative tools, directories, accounts, or signed binaries require
special scrutiny.

After deployment, define telemetry-health monitors, expected alert rate,
severity, triage steps, escalation, success measures, review date, and
retirement criteria. A period with no alerts is not evidence the rule works;
continuous fixture or controlled validation is required.

## B.6 Report Technical and Editorial Review

The technical reviewer checks that authority and scope match the examination;
every material claim traces to identified evidence; methods and exact tool
versions are present; transformations are reproducible; timestamps are
unambiguous; findings separate observation and interpretation; alternative
explanations were considered; and limitations are prominent.

The reviewer samples evidence paths from report to raw source, re-runs material
queries, verifies hashes, checks tables and timeline ordering, validates
indicator type/value/context, and confirms ATT&CK mappings describe behavior
rather than tool names. Recommendations must follow from findings and separate
containment, recovery, and long-term improvement.

The editorial reviewer checks audience, executive-summary accuracy, defined
terms, consistent names, captions, table units, accessibility, cross-references,
citations, spelling, and restrained language. Remove credentials, personal data,
real public IP addresses, internal names, operational tokens, and unnecessary
victim detail from public versions.

The release reviewer builds the PDF, verifies the enforced page threshold,
confirms zero blank pages, renders title, contents, representative dense/table/
code pages and final pages, checks bookmarks and searchable text, runs Markdown
and link checks, scans secrets and public addresses, and records the commit.

All reviewers record identity, date, review scope, findings, resolution, and
approval. Approval means the report is fit for its stated purpose under known
limitations; it is not a guarantee that every future source or interpretation
will remain unchanged.

## B.7 Cloud Collection Worksheet

Record provider, organization/account/tenant/subscription/project, region,
resource IDs, workload owner, collector identity, role, session identifier,
authentication method, and authority. Identify management-plane, data-plane,
identity, network, storage, security, and application sources separately.

For each API or export, record service and API version, exact query/body,
start/end boundaries, timezone semantics, selected fields, pagination token
handling, page and result counts, throttling/retry, partial errors, export job
ID, output format, compression, and digest. Preserve raw provider output before
normalization.

Record licensing, enabled event categories, selectors, region/organization
coverage, retention, delivery destination, immutability controls, and known
latency. Test whether the chosen query includes boundary timestamps and all
pages. Console totals and search previews are not sufficient completeness
evidence.

Document state-changing collection actions: snapshots, role grants, key access,
object copy/share, legal hold, retention change, instance isolation, token
revocation, and audit notifications. Capture before/after resource state and
the provider events created.

Reviewer confirms least privilege, dedicated evidence location, encryption and
keys, cross-region/jurisdiction handling, audit logging, export readability,
manifest, reproducible query, result count, and limitations from eventual
consistency or unavailable data-plane logging.

## B.8 Malware Laboratory Worksheet

Record case/sample IDs, original filename and source, size and hashes, container
relationship, classification, storage, authorization, and intake operator.
Identify laboratory host/hypervisor, guest image digest, OS/build, snapshots,
accounts, shared features, network mode, simulated services, monitoring,
egress policy, DNS, clock, and emergency isolation.

State analysis questions and planned triggers. Inventory static and dynamic
tools with versions/configuration. Record digital-signature validation time and
policy, file structure, imports, resources, strings, entropy scope, packer
indicators, and derived configuration. Hash every unpacked, decoded, patched,
or dumped derivative and link it to the producing action.

For execution, record start/stop, user interaction, arguments, privilege,
dwell, reboots, environment changes, network responses, and anti-analysis
bypasses. Collect process/thread/module, file/registry, packet/service,
memory/dump, and sensor evidence. Separate directly observed behavior from
static capability and external intelligence.

Reviewer checks that no production credentials or unrestricted harmful egress
were present; original evidence stayed unchanged; transformations are
reproducible; public services did not receive confidential samples without
approval; detections were tested against benign and related sets; and reporting
does not distribute live malware or secrets.

## B.9 OT/ICS Safety and Evidence Worksheet

Name incident command, operations authority, control engineer, safety lead,
vendor contact, site, process unit, maintenance window, and stop-work authority.
Describe current physical process, safety constraints, redundancy, manual
fallback, prohibited actions, and approved passive/active methods.

Inventory zones/conduits from actual architecture: enterprise/DMZ, remote
access, jump hosts, engineering workstations, HMI, historians, domain/time
services, switches/firewalls, controllers, safety systems, field devices,
wireless, and vendor cloud. Record asset/firmware, protocols, addressing with
non-public handling, time source, and configuration baseline.

For every collection action record expected operational effect, approval,
tool/version, connection point, commands, start/end, observed process effect,
alarms, network load, output, digest, and rollback. Treat port scanning,
firmware/logic upload, controller-mode change, reboot, packet injection,
portable media, cable movement, and switch mirroring as potential state or
safety changes requiring procedure-specific approval.

Correlate controller/project checksums, logic/configuration, engineering change
logs, HMI/historian, workstation, authentication, remote access, and passive
network evidence. Reviewer confirms evidence goals did not override human or
process safety and that conclusions respect proprietary protocol/tool
limitations.

## B.10 Mobile Collection Worksheet

Record device make/model/hardware ID under restricted handling, OS/build,
storage, lock and power state, battery, radios/network, SIM/eSIM, paired
systems, management, displayed time/offset, visible notifications, accounts
under authority, and photographs. State legal authority, device owner/custodian,
jurisdiction, biometric/passcode constraints, and minimization.

Document isolation and power decision with remote-change, encryption, cloud,
session, and battery risks. Record acquisition label and exact technical
meaning, tool/version, exploit or agent when applicable, cable/adapter,
start/end, prompts and user actions, reboots, trust pairing, errors, output,
manifest, encryption/key handling, size, and digest.

For backups/logical exports, list included domains and known exclusions. For
filesystem or physical methods, document privileges, exploit footprint,
decryption state, unsupported partitions, and parser/schema support. For cloud
collection, record account/session, provider, query/export, notification, audit,
region, retention, and result count.

Reviewer confirms device state changes and limitations are reported, secrets
are access-controlled, source databases retain companion journals, timestamps
are field-specific, application artifacts are validated against the exact
version, and indicator-scanning results such as MVT findings are corroborated
rather than treated as a complete compromise verdict.
