# Part 08 Field Practice: Response, Hunting, Reporting, and Special Systems

## 8.9 Incident Command and Decision Records

Incident response integrates governance, identification, protection,
detection, response, and recovery rather than existing only as a linear
technical cycle. Define incident commander, technical lead, evidence lead,
communications, legal/privacy, business owner, safety/OT, vendors, and executive
decision authority. Roles can be combined in small organizations but decisions
must remain attributable.

Maintain a decision log containing time, decision, owner, information available,
alternatives, risk, authority, action, result, and review. This is especially
important for isolation, shutdown, credential resets, disclosure, destructive
eradication, restoration, and law-enforcement engagement.

Keep operational coordination separate from evidence records when appropriate,
but preserve both under retention policy. Chat is convenient and incomplete:
export authorized channels, record participants/timezone, and avoid putting
secrets or unnecessary personal data in broad rooms.

## 8.10 Containment and Evidence Preservation

Containment is risk management, not an absolute rule to collect everything
first. When active harm, safety, human life, legal duty, or widespread
compromise demands action, contain promptly and document lost evidence
opportunities. When risk permits, collect the most volatile high-value evidence
before disruptive action.

Evaluate scope, attacker access, persistence, identity/session risk, encryption
keys, destructive capability, business/safety criticality, collection time,
remote wipe, and restoration readiness. Possible actions include token
revocation, account disablement, key rotation, EDR isolation, firewall/DNS
control, application feature disablement, workload quarantine, or segmentation.
Each changes telemetry and attacker behavior.

Verify containment from independent signals. Disabling one account does not
invalidate existing sessions, application credentials, cloud access keys,
delegated permissions, or persistence. Record before/after state and residual
risk.

## 8.11 Scoping and Eradication

Scope from behaviors and access paths, not only known hashes or IPs. Build a
campaign model covering initial access, identities, privileges, persistence,
execution, discovery, movement, collection, command-and-control, exfiltration,
impact, and anti-forensics. For each behavior, identify telemetry and hunt
across the maximum defensible interval.

Eradication criteria should be observable: unauthorized identities removed,
sessions/tokens revoked, persistence eliminated, vulnerable entry path fixed,
secrets rotated in dependency order, malicious code/configuration removed or
systems rebuilt, and monitoring deployed. "Antivirus clean" is insufficient.

Rebuilding from a trusted source can reduce uncertainty but does not repair
compromised identity, management plane, firmware, backups, SaaS rules, or
upstream dependencies. Validate golden images, automation, packages, secrets,
and management infrastructure.

## 8.12 Recovery and Lessons Learned

Recovery has entry criteria, staged restoration, heightened monitoring,
business validation, rollback plans, and exit criteria. Restore in dependency
order and prevent old credentials or persistence from returning through
backups. Test integrity and functionality.

Track recurrence indicators, authentication, privileged actions, outbound
traffic, detection health, backup behavior, and business errors. Define who can
declare recovery and when temporary controls can be removed.

Lessons learned should produce assigned, funded, time-bound changes. Separate
root conditions from individual blame. Preserve useful telemetry and detection
logic, update playbooks, and measure whether actions reduce time to detect,
contain, investigate, and recover.

## 8.13 ATT&CK-Driven Hunting

ATT&CK is a knowledge base and common language, not a checklist proving
coverage. Define a hypothesis from threat, environment, exposure, or incident
evidence. Map expected behavior to techniques, then to platform-specific data
components and actual local sources.

A hunt plan includes hypothesis, rationale, scope, interval, required data,
query, assumptions, false-positive expectations, triage, escalation, and
stopping condition. Preserve query versions and counts.

Technique mapping should follow observed behavior. Do not select a technique
because a tool name appears. Record version of ATT&CK, platform, tactic context,
sub-technique when supported, evidence, and confidence.

## 8.14 Sigma Lifecycle

Sigma is a portable detection-rule format, but backend conversion requires a
processing pipeline and environment-specific field/index mapping. A syntactically
valid rule is not a working production detection.

Each rule needs:

- stable title and ID;
- status and dates;
- logsource matching actual telemetry;
- detection selections and explicit condition;
- meaningful fields and tags;
- references and author/reviewer;
- tested positives, benign cases, and false positives;
- backend, pipeline, converter version, and generated query;
- performance and volume assessment;
- deployment owner and review/retirement date.

Test at three levels: rule/schema validation, unit fixtures, and backend
integration on representative data. Then shadow/deploy, tune through documented
changes, and measure expected telemetry health. A no-alert state can mean no
attack, broken collection, mapping failure, suppression, or rule error.

## 8.15 Detection Tuning and Purple Teaming

Tune by adding stable context rather than excluding broad executables, users, or
paths. Separate expected administration by signer, parent, management system,
account, host group, command shape, and time only where those properties are
hard for an attacker to inherit. Expire exceptions and review their match
volume.

Purple-team tests require authorization, safety controls, cleanup, monitoring,
and explicit objectives. Record test ID, behavior, tool/version, host/user,
times, expected data, expected detection, observed result, and gaps. A tool
emulating one implementation does not validate every variant of an ATT&CK
technique.

Validate the entire chain: endpoint behavior, sensor event, transport,
normalization, storage, query, alert enrichment, routing, analyst triage, and
response. Detection engineering ends with an operational outcome, not a query.

## 8.16 Professional Forensic Reporting

Write for the decision maker while preserving technical reproducibility. A
report normally includes authority and scope, executive summary, systems and
identities, evidence, methods/tools, findings, timeline, impact, ATT&CK mapping
when useful, conclusions, limitations, recommendations, and appendices.

The executive summary answers what happened, affected scope, material impact,
current status, confidence, and urgent decisions without unsupported jargon.
Technical findings link every material statement to an evidence ID and artifact
or query.

Distinguish observation, interpretation, alternative explanation, and
limitation. Use calibrated language:

- "The Security log contains Event 4688..."
- "This is consistent with process creation under the recorded audit policy..."
- "Prefetch and EDR telemetry independently corroborate execution..."
- "The available evidence does not identify the human controlling the account."

Do not write "no evidence" without naming acquired sources, interval, search,
and limitations. Do not put unverified live indicators directly into blocking
recommendations. Separate immediate containment from long-term prevention.

## 8.17 Expert Testimony

An expert should explain qualifications, authority, evidence provenance,
methods, validation, findings, alternative explanations, limitations, and
opinions within expertise. Prepare to reproduce commands and trace exhibits to
source evidence.

Do not advocate beyond the evidence. Acknowledge errors and uncertainty.
Jurisdictions differ in admissibility and expert rules; qualified counsel must
guide legal requirements. Technical reliability is strengthened by known
methods, validation, peer/technical review, transparent limitations, and
preservation of materials another competent examiner can assess.

## 8.18 Credential Theft and Lateral Movement

Potential LSASS access requires process-access telemetry, handle/call context,
source image/signature, privilege, memory behavior, file creation, security-tool
alerts, and follow-on authentication. Legitimate security and support tools may
access LSASS. Credential Guard and protected-process controls alter behavior and
visibility.

Pass-the-hash is authentication using password-derived material rather than a
plaintext password. Investigate NTLM/Kerberos events, logon types, source and
destination, privileged logon, share/service/task/WMI activity, endpoint
processes, and account baseline. An NTLM logon alone is not proof of PtH.

DCSync abuses directory replication rights. Investigate directory-service
access auditing, relevant replication GUID access, account privileges and
changes, domain-controller network connections, process/identity context, and
subsequent credential use. Legitimate controllers and identity products also
replicate.

For RDP, PsExec-like service execution, WMI, WinRM, SMB, and scheduled-task
movement, build source-to-destination sequences using authentication, process,
service/task, network, share, terminal-services, WMI/PowerShell, and EDR data.
Tool-name artifacts are less reliable than behavior correlation.

## 8.19 Anti-Forensics

Potential anti-forensics includes log clearing or policy changes, timestomping,
secure deletion, artifact cleanup, history disabling, alternate storage,
encryption, obfuscation, trail manipulation, and sensor impairment. Normal
retention, privacy tools, cleanup, deployment, restore, and administration can
look similar.

Look for secondary effects: clearing events, gaps inconsistent with policy,
service/config changes, collector health loss, sequence discontinuity,
filesystem journal evidence, backup divergence, command/process telemetry, and
cross-source mismatches. State what was observed and why benign explanations
are less or more likely.

## 8.20 OT/ICS Forensics

Safety and process continuity govern OT response. Coordinate with incident
command, control engineers, operators, safety, vendors, and asset owners.
Passive-first collection is preferred; active scanning, rebooting, connecting
USB, changing switch configuration, or querying a PLC can affect physical
processes and warranties.

Understand the actual architecture rather than assuming a Purdue diagram.
Collect engineering workstations, HMIs, historians, domain/identity services,
jump hosts, remote-access systems, network captures/flows, firewalls, managed
switches, time sources, safety systems, controller logic/configuration, and
vendor management platforms under approved procedures.

For PLC/controller evidence, record hardware/firmware, project/logic version,
checksums where available, operating mode, change/download logs, controller
time, I/O/process state, and acquisition tool/version. A logic upload can have
side effects and may not recover source comments/symbols. Compare with the
controlled engineering baseline and change-management records.

## 8.21 IoT and Embedded Systems

Identify board, SoC, storage, boot chain, firmware version, interfaces, cloud
dependency, companion apps, and update mechanism. Potential sources include
removable flash, eMMC/UFS/NAND, UART, JTAG/SWD, SPI, filesystem, firmware
packages, mobile apps, gateways, and vendor cloud logs.

Chip-off, in-system programming, debug access, and desoldering require
specialized equipment and can destroy evidence. Record voltage, pinout,
adapter, read parameters, bad blocks, ECC/OOB handling, repeated-read
comparison, and physical changes.

Firmware extraction tools identify signatures heuristically. Validate partition
tables, headers, compression, checksums, signatures, CPU architecture, and
filesystem boundaries. Analyze extracted code in isolation. Do not connect
unknown firmware or credentials to production services.

## 8.22 Mobile Forensics

Acquisition capability depends on device, OS/build, lock state, encryption,
hardware security, management, account access, legal authority, and tool
support. Describe acquisition as manual, backup/logical, full-filesystem,
filesystem, physical, cloud, or vendor-specific only with exact method and
scope; labels are not perfectly standardized.

Preserve device condition, radios/network decision, SIM/eSIM, paired systems,
notifications, power, lock state, time, identifiers, and visible applications.
Isolation can prevent remote change but may affect cloud/session evidence and
device behavior. Keep powered-state decisions device-specific.

Backups and logical exports omit data and can transform timestamps/metadata.
Full-filesystem methods may exploit vulnerabilities and change state. Physical
images can remain encrypted. Cloud collection introduces account, token,
notification, jurisdiction, and provider-audit considerations.

MVT supports defined AndroidQF and iOS backup/filesystem workflows and
indicator-based checks; it is not a universal commercial acquisition suite and
a clean result does not prove a device is uncompromised. Record MVT version,
input type, IOC bundle source/date, command, warnings, and matches, then validate
findings against original artifacts and current official documentation.

## 8.23 Global Practice and Legal Boundaries

A globally usable handbook cannot prescribe one law. Authority, consent,
warrants/orders, employee monitoring, data protection, breach notification,
privilege, labor law, export controls, sector rules, cross-border transfer, and
evidence admissibility differ.

At case opening, document jurisdictions, data subjects, custodians/controllers,
purpose and lawful authority, minimization, access, retention, transfer,
notification, privilege, and disposition. Engage qualified counsel and privacy
professionals. Technical teams should supply accurate scope, dates, data types,
systems, and risk without making unsupported legal conclusions.

Professional neutrality also requires accessibility, respectful language,
conflict disclosure, separation of investigative fact from intelligence, and
protection of victims and uninvolved people. Publication should sanitize public
addresses, credentials, internal identifiers, personal data, and live
operational indicators.
