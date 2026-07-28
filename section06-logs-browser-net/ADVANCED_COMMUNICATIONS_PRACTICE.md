# Part 06 Field Practice: Logs, Browsers, Email, and Networks

## 6.5 Log Source Qualification

For each source, document producer, collector, transport, parser, schema,
timezone, clock state, retention, rotation, filtering, sampling, normalization,
deduplication, access control, and known loss. A SIEM event is often a
transformed representation, not the original record.

Preserve raw records when possible and record queries with time boundaries and
result counts. Validate pagination and export completeness. Compare endpoint,
collector, and archive counts. Late arrival means ingestion time cannot replace
event time. A normalized username, IP, or action can hide source-specific
detail.

Build a log-source matrix identifying the proposition each source can support,
coverage interval, gaps, and owner. Explicitly state whether "no result" means
no matching record within acquired data, not that the activity did not occur.

## 6.6 Web, Proxy, DNS, DHCP, VPN, and Firewall

Web access logs can record client or proxy address, request line, status, bytes,
referrer, user agent, host, TLS metadata, and upstream timing depending on
format. Preserve configuration and virtual-host context. Parse quoted fields
and escaping correctly; naive whitespace splitting corrupts requests.

Behind reverse proxies, client-address headers are trustworthy only across a
defined proxy trust boundary. Attackers can supply `X-Forwarded-For` when a
front end does not replace it. Correlate load balancer, CDN, WAF, proxy, server,
application, and identity session identifiers.

DNS logs show different views: client query, resolver recursion, authoritative
response, passive observation, or cached result. A query is not proof the
response was used or a connection occurred. Encrypted DNS and caching create
gaps. Preserve query type, response code, answers, TTL, client, resolver, and
transaction context.

DHCP maps leases, not people. Consider reservation, relay, client identifier,
MAC randomization, NAT, VPN, static addressing, and lease reuse. Firewall
accept/deny records describe policy evaluation under a ruleset and interface;
they may not contain application outcome or payload. VPN assignment, device
posture, authentication, tunnel times, and gateway NAT must be correlated.

## 6.7 Browser Data Acquisition

Acquire complete browser profiles, not isolated databases. Include SQLite
databases with `-wal` and `-shm`, preferences, local state, session/tabs,
history, downloads, cookies under explicit authority, cache, extensions,
storage APIs, service workers, favicons, sync metadata, and crash data.

Do not open the original profile in a browser. Startup can checkpoint WALs,
migrate schemas, sync, expire records, update sessions, and execute extensions.
Work on a verified copy with network disabled where appropriate.

Chromium timestamps commonly use microseconds since 1601-01-01 UTC for specific
fields, while other components use Unix or application-specific time. Firefox
fields vary in unit and epoch. Verify each column and schema version. A history
visit can be generated through redirects, embedded/navigation behavior, sync,
or restoration; it does not alone establish deliberate human entry.

## 6.8 Browser Credentials and Privacy

Cookies, login databases, tokens, autofill, local storage, and session files can
provide account and activity context but are high-risk secrets. Decryption may
depend on OS-protected keys, user context, browser version, hardware-backed
protection, or enterprise policy. Obtain explicit authority and avoid
operational use of recovered sessions.

Report cookie domain/path, creation/expiry/access values, security flags, and
source profile without printing the full value unless strictly required.
Invalidate exposed sessions through the incident-response process after
evidence preservation and authorization.

Browser sync can introduce artifacts from other devices. Device and sync
metadata, local profile creation, first/last use, and endpoint telemetry help
distinguish local activity from synchronized state.

## 6.9 Email Stores and Message Provenance

Preserve original message bytes when available. PST, OST, MBOX, EML, MSG,
server-side export, journaling, and eDiscovery exports have different
completeness and metadata. Record export job, scope, tool, timezone, folder
mapping, deduplication, and errors. OST is a cache, not guaranteed complete
mailbox truth.

Message headers are appended by systems along a route but not uniformly
trustworthy. Start from a trusted receiving system and work backward through
`Received` fields while defining the trust boundary. Sender-controlled headers
can be forged. Date headers reflect claimed sender context and are not the same
as server receipt time.

Preserve MIME structure, transfer encoding, character sets, attachment names,
content IDs, digital signatures, authentication results, and original line
endings where material. Decode into a derived file, hash both representation
and output, and prevent active content from executing.

## 6.10 SPF, DKIM, and DMARC

SPF evaluates whether a connecting IP is authorized for the envelope domain at
evaluation time; it does not authenticate visible message content. Forwarding
can affect results. DKIM verifies a signature over selected canonicalized
headers/body using a domain key; a pass does not prove the human sender or
benign content. DMARC evaluates alignment and policy using SPF and/or DKIM;
receivers may apply local policy.

Prefer the receiving provider's recorded authentication results, then validate
carefully using preserved message bytes and DNS evidence when historical keys
are available. Current DNS records may differ from records at receipt time.
Record selector, signing domain, aligned domain, canonicalization, signed
headers, body-length tag if present, result, and validation time.

## 6.11 Phishing Triage

Use an isolated workflow:

1. preserve original message and acquisition provenance;
2. identify trusted receiving boundary and account context;
3. parse MIME without rendering active content;
4. extract URLs and attachments as derived evidence;
5. normalize but retain exact original strings;
6. inspect authentication and route;
7. analyze redirects and domains with time-stamped passive data;
8. perform static attachment triage;
9. use a controlled sandbox only when authorized;
10. correlate delivery, click, process, network, identity, and mailbox actions;
11. scope other recipients and related campaigns;
12. contain accounts/sessions and remove messages through approved response.

Public URL or sample services can disclose confidential messages and indicators
to third parties. Use organizational services and contractual controls.

## 6.12 Packet Capture Integrity and Scope

Document capture point, interfaces, direction, VLAN/tunnel visibility, snap
length, filters, timestamp source/precision, dropped packets, offloading,
rotation, file format, sensor clock, and network topology. A PCAP from one point
does not show traffic outside that path, and asymmetric routing can expose only
one direction.

Capture filters discard traffic before storage; display filters do not. Preserve
the original capture and record both. NIC offload and capture location can make
checksums appear invalid or packets appear aggregated. Packet loss and snap
length can prevent reliable stream reconstruction.

## 6.13 Protocol and Stream Analysis

Wireshark "Follow Stream" is a derived reassembly. Preserve stream identifiers,
filter, tool version, direction, gaps, retransmission handling, and exported
bytes. TCP sequence behavior, overlap, middleboxes, and dissector preferences
affect results.

TLS normally hides application content. Handshake metadata, certificates,
SNI where visible, ALPN, versions, ciphers, sizes, timing, endpoints, and
fingerprints can still support analysis. Decryption requires authorized keys or
session secrets and changes privacy exposure. QUIC and encrypted DNS alter
traditional visibility.

Protocol dissectors are parsers and can be wrong or vulnerable to malformed
input. Confirm important fields against bytes and specifications. Disable name
resolution during controlled analysis when it could leak indicators or change
labels over time.

## 6.14 File Extraction from Network Data

Object export depends on complete supported protocol reassembly. Record capture,
stream, request/response, content encoding, transfer encoding, declared and
actual size, extraction method, and output hash. Validate file structure.

Content may be compressed, chunked, partial, cached, range-requested, encrypted,
or reconstructed from multiple sessions. Do not call an exported object the
exact transmitted file without accounting for transformations. Compare
endpoint, proxy, server, and malware-analysis copies.

## 6.15 Beacon and Exfiltration Analysis

Regular timing alone is not malicious. Updaters, telemetry, health checks, NTP,
and application polling beacon. Measure interval distribution, jitter, duration,
bytes, direction, destination stability, DNS behavior, TLS/application
fingerprints, process ownership, and host baseline.

Exfiltration hypotheses should predict staging, file access, compression or
encryption, destination resolution, connection, transferred volume, server or
cloud access, and subsequent cleanup. Network bytes alone may not identify
content; endpoint access alone does not prove transmission. Corroborate both.

Threat intelligence is time-sensitive and can be wrong. Record provider, query
time, indicator type, first/last seen, confidence, and how the result affects
the case. Shared hosting, CDN, Tor, VPN, and compromised infrastructure prevent
simple IP-to-actor attribution.
