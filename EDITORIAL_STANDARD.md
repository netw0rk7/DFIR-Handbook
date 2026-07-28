# Editorial and Technical Standard

This project is a practitioner handbook, not a substitute for legal advice,
vendor support, laboratory accreditation, or an organization's approved
incident-response procedures. The following rules apply to every chapter.

## Evidence Language

Findings must distinguish:

- **Observation**: data directly present in an identified source.
- **Interpretation**: what the observation is consistent with.
- **Corroboration**: an independent artifact supporting the interpretation.
- **Alternative explanation**: another plausible cause that has not been
  excluded.
- **Limitation**: missing data, uncertain clock state, parser limitations,
  retention gaps, encryption, unsupported versions, or acquisition effects.
- **Conclusion**: an opinion whose confidence is explicitly stated.

An artifact is not called "proof" of an action unless the action follows
necessarily from that artifact and the acquisition and parsing assumptions
have been tested. Most forensic artifacts are evidence *consistent with* an
event and require corroboration.

## Command Standard

Every operational command must be read as an example, not as a universal
recipe. Before using it in a case, an examiner must:

1. verify the installed tool's version and built-in help;
2. test the command against known data;
3. record the exact command, version, configuration, input, output, time, and
   operator;
4. work from a verified forensic copy unless live response requires otherwise;
5. understand whether the command reads, writes, mounts, executes, decrypts,
   transmits, or changes evidence;
6. obtain the necessary legal and organizational authority.

Commands use documentation-only names, addresses, hashes, domains, tenant IDs,
and account identifiers. They must be replaced deliberately in a real case.

## Version and Platform Scope

Artifact behavior can change with operating-system releases, application
updates, configuration, locale, licensing, retention policy, and deployment
model. Chapters therefore describe stable investigative concepts first and
identify version-sensitive details explicitly. Readers must validate locations,
schemas, event availability, and parser support for the exact system examined.

## Source Hierarchy

Technical review favors sources in this order:

1. laws, court rules, regulators, and authoritative standards;
2. official product, format, API, and tool documentation;
3. original source code and release notes;
4. peer-reviewed research and recognized standards bodies;
5. reproducible practitioner research;
6. secondary summaries, used only for orientation.

Legal statements are jurisdiction-dependent and require qualified counsel.
Product documentation is authoritative about intended behavior but does not
replace empirical validation of actual artifacts.

## Safety and Ethics

- Malware work belongs in an authorized, isolated environment.
- Credential material, tokens, cookies, private keys, and personal data are
  evidence and high-risk secrets.
- Cloud and SaaS collection can trigger notifications, create audit records,
  consume retention capacity, or alter state.
- OT/ICS response is safety-led and coordinated with operations, engineering,
  vendors, and incident command.
- Mobile acquisition may change device state and can be restricted by platform
  security, licensing, law, or policy.
- Public analysis services can disclose samples, filenames, metadata, and
  indicators to third parties.

## Review Cadence

The handbook records a `last_reviewed` date in its release metadata. A release
must not claim current tool compatibility unless commands were checked against
the referenced release or official current documentation. High-change areas
such as cloud APIs, Volatility plugins, mobile tooling, and event schemas should
be reviewed before each tagged release.

## Page-Count Policy

The 250-page requirement is measured from the reproducible PDF build, excluding
blank pages. Page count is not a quality proxy. A release must also pass the
repository validator, Markdown linting, link checking, source-citation checks,
secret/public-address checks, and visual PDF inspection.
