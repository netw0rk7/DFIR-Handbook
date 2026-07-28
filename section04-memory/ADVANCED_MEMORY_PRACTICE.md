# Part 04 Field Practice: Memory Forensics

## 4.5 Acquisition Semantics and Image Fitness

A memory image is a non-atomic observation collected over time while the system
continues changing. Pages can change during capture, device-mapped regions may
be unavailable, acquisition tools can omit ranges, and virtualization or crash
formats may represent memory differently. Record collector/version, OS/build,
architecture, start/end, output format, size, digest, errors, missing ranges,
system load, security-tool response, and concurrent volatile collection.

Before analysis, preserve the original, verify its digest, work from a copy,
identify format, and test whether the framework constructs the expected layers
and symbols. A plugin producing rows does not prove the image is complete.
Compare reported physical ranges with system inventory and acquisition logs.

Windows symbols can often be obtained from Microsoft PDB information by
Volatility 3, but network availability and symbol caching affect
reproducibility. Preserve relevant cached symbols and record Volatility version
and plugin list. Linux and macOS symbol requirements are tied closely to exact
kernel builds and configurations.

## 4.6 Process Enumeration Is a Correlation Problem

`windows.pslist` walks the active process list; `windows.psscan` scans for
process objects. A process found only by scanning may be terminated, partially
overwritten, unlinked, or a false candidate. It is not automatically a hidden
rootkit process. Compare:

- process object offset, PID/PPID, create and exit times;
- active-list membership and scan result;
- threads, handles, token, session, command line, environment;
- executable sections, VADs, loaded modules, and mapped paths;
- parent lifetime and expected Windows process ancestry;
- sockets, named objects, services, jobs, and user activity.

PID reuse and stale objects make PID-only joins unsafe. Parent PID can refer to
a process that exited or to a later process reusing the identifier. Use object
offsets, times, process GUIDs from external telemetry, and multiple structures.

`pstree` visualizes recorded parent relationships; it does not reconstruct
every injection, token theft, brokered launch, or terminated ancestor. An
unusual parent is a lead requiring build-, role-, and application-aware
baseline comparison.

## 4.7 Network State

`windows.netscan` scans network structures and can return active, closed, stale,
or partially overwritten endpoints. Validate address family, local/remote
address, port, state, owning process, creation time when available, and object
integrity. A listener is not proof of malicious access; an external address is
not proof that data transferred.

Correlate with process lifetime, DNS cache and telemetry, firewall events,
packet/flow/proxy logs, EDR, routing, VPN, NAT, and threat intelligence captured
at a stated time. A public reputation result is contextual intelligence, not a
forensic fact about the historical connection.

## 4.8 VADs, Injection, and `malfind`

Virtual Address Descriptors describe process address ranges and properties.
Suspicious combinations include executable private memory, protection changes,
PE-like content in unusual mappings, threads beginning in unbacked regions,
inconsistent module lists, and code whose behavior correlates with other
evidence. Legitimate JIT runtimes, browsers, security products, packers, and
application frameworks can look similar.

`malfind` identifies candidate regions; it does not declare malware. For each
candidate, record process/object, address, size, protection, tags, entropy only
as context, initial bytes, disassembly, strings, YARA results, mapped-file
relationship, threads, and external behavior. Dumped memory is not necessarily
a valid standalone executable and can contain relocated, decrypted, or partial
content.

Process-hollowing and injection plugins implement heuristics with version and
plugin-specific requirements. Confirm with PE header/mapping inconsistencies,
thread start, image path, section objects, memory protections, and event
telemetry. Report the observed inconsistency, not only the heuristic label.

## 4.9 Modules, Drivers, Hooks, and Kernel Objects

Compare loaded-module lists, scans, process VADs, loader structures, signatures,
paths, hashes, and known build baselines. An unlinked DLL may reflect manual
mapping, loader behavior, corruption, or termination. A missing path can result
from deletion or inaccessible structures.

For drivers, correlate service configuration, driver objects, loaded modules,
device objects, callbacks, IRP handlers, signatures, file content, and
code-memory ownership. Kernel callbacks and hooks can be legitimate security or
hardware software. Symbol or structure mismatch can produce apparently
impossible addresses.

Before labeling a kernel compromise, reproduce with the exact image and symbols,
validate address translation, inspect ownership of target code, compare a
known-good system of the same build, and seek endpoint/boot/persistence
corroboration.

## 4.10 Credential Material

Memory can contain password-equivalent hashes, tickets, tokens, DPAPI-related
material, keys, cookies, and plaintext fragments. Collection and extraction
require explicit authority, restricted access, encryption, audit logging,
minimal distribution, and retention controls. Do not place recovered material
in ordinary case notes or command histories.

Volatility plugins that recover registry-backed secrets depend on correct hive
layers and supported structures. Output may represent password hashes or
encrypted secrets, not plaintext. Modern Windows security features such as
Credential Guard, protected processes, virtualization-based security, and
authentication changes affect availability.

Do not execute offensive credential-dumping tools on evidence merely because a
forensic question involves credentials. Prefer read-only analysis of an
acquired image with validated tooling. Report the type of credential material,
source, account mapping, and risk without reproducing full secrets.

## 4.11 File and Registry Recovery

Memory-resident file objects and cached pages may permit partial recovery even
after disk deletion. `dumpfiles` results can be sparse, duplicated, or
incomplete. Record the source object, offsets, layer, output hash, size, and
plugin options. Validate file structure and compare against disk, cache, and
network copies.

Registry hives in memory may represent different moments and dirty state.
Identify hive path and layer, recover with a supported method, and compare with
disk hive plus transaction logs. A memory view can preserve keys absent from a
later disk acquisition, but reconstruction limitations must be stated.

## 4.12 Memory Timeline and Reproducible Workflow

A memory timeline combines plugin-specific timestamp generators whose semantics
differ: process creation/exit, socket creation, file-object metadata, registry
key last write, and other structures. It is not a chronological recording of
all memory activity. Preserve source plugin, object address, native time,
normalized time, and semantic label.

A reproducible case directory should contain:

- immutable input and digest manifest;
- Volatility version/commit, Python version, plugins, symbols, and config;
- one command log with UTC execution times and exit status;
- raw structured output where supported;
- dumped objects with hashes and provenance;
- analyst transformations and queries;
- interpretation notes separating facts, hypotheses, and limitations.

Run `vol.py --help` and `<plugin> --help` for the installed release. Plugin names
and options evolve. Treat examples in the handbook as version-scoped starting
points and record the command that actually ran.
