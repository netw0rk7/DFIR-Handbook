# Part 05 Field Practice: Filesystem Interpretation and Recovery

## 5.9 Identify the Storage Stack

Do not begin at the file view. Identify physical media, sector sizes, partition
tables, RAID/storage virtualization, encryption, volume manager, filesystem,
snapshots, deduplication, compression, sparse allocation, case sensitivity,
mount options, and application containers. A byte offset is meaningful only
within a defined layer.

Record tool/version and the offset or layer supplied to every filesystem
command. Validate partition start and sector unit. A common failure is treating
a sector count as a byte offset or analyzing a logical volume as if it began at
the image start.

Mounting can replay journals, update metadata, or invoke indexing and
automounting. Prefer forensic parsers or an explicitly read-only environment
whose behavior has been tested. "Read-only" at one layer does not guarantee
that every lower or upper layer is unchanged.

## 5.10 NTFS Metadata Model

NTFS represents files through MFT records containing attributes. A file can
have multiple names, multiple data streams, resident or non-resident data,
extension records, hard links, sparse/compressed runs, and reparse behavior.
Record number reuse and sequence numbers help distinguish references to earlier
record incarnations.

`$STANDARD_INFORMATION` and `$FILE_NAME` timestamps arise from different update
paths and can diverge legitimately through copy, move, rename, restore, archive
extraction, tunneling, or application behavior. Comparing them is useful, but a
particular inequality is not a universal timestomping signature.

Important metadata files include `$MFT`, `$MFTMirr`, `$LogFile`, `$Bitmap`,
`$Boot`, `$Secure`, `$Extend\$UsnJrnl`, and others. `$LogFile` contains NTFS
transaction/recovery records and is not a general text audit log. `$UsnJrnl`
records change-journal reasons under retention and wraparound limits; reason
flags describe categories of change, not human intent.

## 5.11 Deleted-File Recovery

Deletion usually changes allocation and namespace metadata; it does not promise
that content remains. Recovery probability depends on filesystem, media,
TRIM/garbage collection, reuse, encryption, snapshots, application storage,
and time.

A defensible workflow:

1. enumerate deleted metadata entries and validate record/sequence context;
2. recover through metadata when runs remain reliable;
3. check named streams and attributes;
4. compare allocation bitmap and journal/change records;
5. validate recovered format, internal structure, size, and digest;
6. carve unallocated data as a separate method;
7. search snapshots, backups, sync stores, caches, email, and cloud versions;
8. report completeness and reconstruction assumptions.

A recovered filename and recovered content may not belong together when
metadata is stale or reused. Carved content commonly loses path, name, original
timestamps, and fragmentation. Never invent those properties.

## 5.12 Slack and Unallocated Space

File slack is the allocated cluster remainder beyond logical end-of-file. It
can include prior data, padding, zeros, filesystem structures, or content
written by the current file/application. Memory or RAM slack concepts described
in older literature do not map uniformly to modern operating-system writes and
storage stacks.

Unallocated space is not synonymous with deleted files. It may contain old
content, filesystem metadata, encrypted or compressed fragments, never-used
zeros, overprovisioning-inaccessible data, or remnants unrelated to the case.
Record extraction method and address ranges so a result can be traced back.

Search hits require context. Preserve offset, surrounding bytes, encoding,
allocation status, containing partition, and any metadata relationship. A
string fragment is an observation, not automatically a complete message,
command, URL, or attribution.

## 5.13 File Carving and Validation

Header/footer carving works best for contiguous formats with reliable
terminators. Fragmentation, embedded files, missing footers, variable length,
compression, and encryption produce missed or false results. Structure-aware
carvers can use format fields but still need validation.

For every carved object:

- record image and byte range(s);
- record carver, version, configuration, signature, and maximum size;
- hash the output;
- validate magic, declared lengths, checksums, parsability, and internal
  consistency;
- detect overlap and duplicates;
- distinguish complete, partial, corrupted, and false objects;
- seek metadata or application correlation.

Do not report a file extension assigned by a carver as the original filename or
prove source application. Nested and embedded objects should maintain a parent
relationship in provenance.

## 5.14 ADS, Extended Attributes, and Reparse Data

NTFS alternate data streams are named `$DATA` attributes. Enumerate streams
through a parser that operates on the forensic image and preserves raw names,
sizes, allocation, and parent record. Windows APIs, backup programs, archives,
and copy destinations differ in stream preservation.

`Zone.Identifier` commonly implements Mark-of-the-Web information, but browser,
archive, filesystem, policy, and transfer path affect creation and propagation.
Presence supports an origin-related observation; absence is not proof of local
origin or anti-forensics. Preserve exact stream text and parent-file identity.

Other filesystems use extended attributes, resource forks, ACLs, capabilities,
and reparse/symlink metadata for different purposes. A logical export that
captures only ordinary file content can silently destroy this evidence.

## 5.15 Timestomping and Temporal Anomalies

Detect temporal manipulation by combining:

- SI/FN and other filesystem timestamp differences;
- USN and transaction metadata;
- Prefetch, LNK, Jump Lists, registry, event, and application records;
- file version, signature, compile/link metadata, and package installation;
- backup, snapshot, sync, archive, and download metadata;
- sequence/record reuse and parent-directory changes;
- known clock offset and system-time-change events.

Future dates, dates before volume creation, identical timestamp clusters, or
impossible event ordering are leads. Legitimate deployment, restore, copy
utilities, installers, reproducible builds, VM rollback, and faulty clocks can
produce them.

Report the discrepancy and competing causes. "The timestamps were modified" is
stronger than "timestamp fields are inconsistent with independently recorded
activity." Reserve conclusions for cases with corroborating tool, command,
telemetry, or transaction evidence.

## 5.16 Cross-Filesystem Considerations

FAT/exFAT timestamp resolution, timezone storage, naming, and allocation differ
from NTFS. ext4 uses inodes, extents, journals, and optional birth time; inode
reuse complicates deleted references. XFS, Btrfs, ZFS, and APFS have their own
copy-on-write, snapshot, checksum, compression, and metadata semantics. Network
and object storage may not expose a traditional filesystem at all.

Never transfer an interpretive rule merely because two tools label a column
"Created." Read format specifications and parser documentation, validate with
known actions, and state the exact timestamp or object property represented.

## 5.17 Filesystem Reporting

Every reported recovered file should include evidence source, layer/volume,
metadata address or byte range, method, output hash, validation result, known
name/path basis, allocation state at acquisition, and limitations. Keep original
parser output and query.

Use confidence appropriate to provenance:

- **High:** metadata-backed recovery with consistent structure and independent
  corroboration.
- **Moderate:** structurally valid content with incomplete metadata or
  fragmentation uncertainty.
- **Low:** signature/string fragment with ambiguous boundaries or ownership.

Confidence describes support for a proposition, not analyst certainty in
general.
