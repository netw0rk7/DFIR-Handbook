# Part 06: Logs / Browser / Email / Network Forensics

> Section covering log analysis, browser artifacts, email headers,
> and network packet capture.
> Tools: tshark, tcpdump, Wireshark, readpst, msgtool, sqlite3, Chainsaw.

---

## 6.1 Logs

### Windows Event Log + Sysmon

> See Part 02 for details.

```powershell
# Investigate Event Logs
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} |
  Export-Csv logon_events.csv

# Sysmon
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 1 }  # Process creation
```

### Linux /var/log & journald

```bash
# Apache/Nginx access logs
grep "POST" /var/log/nginx/access.log | grep -v "200"  # suspicious POSTs
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head  # top IPs

# Firewall logs (iptables)
iptables -L -n -v

# VPN logs (OpenVPN)
tail -f /var/log/openvpn.log

# DNS logs (bind)
grep "query" /var/log/named/query.log
```

### Apache/Nginx Forensic Value

```
Access log format:
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent

What to look for:
- Suspicious URIs: /admin, /wp-admin, /.env, /phpmyadmin
- SQL injection: ' OR '1'='1
- Path traversal: ../../../../etc/passwd
- Weird user-agents: sqlmap, nikto, masscan
- Bursts of errors or unusual status transitions
```

These are triage leads. Administrative paths, scanning user agents, and HTTP
errors are not proof of exploitation without request, response, application,
and host evidence.

### DHCP Logs (IP-to-Host Mapping)

```bash
# DHCP lease file
cat /var/lib/dhcp/dhcpd.leases | grep -E "lease|hardware|client-hostname"

# Windows DHCP
# C:\Windows\System32\dhcp\dhcpd.txt
```

## 6.2 Browser Forensics

### Chrome / Edge (Chromium)

| File | Location | Contents |
|------|----------|----------|
| **History** | `AppData\Local\Google\Chrome\User Data\Default\History` | URLs visited |
| **Cookies** | `...\Network\Cookies` or version-specific profile path | Session cookies |
| **Web Data** | `...\Web Data` | Autofill, payment |
| **Login Data** | `...\Login Data` | Saved passwords (DPAPI) |
| **Downloads** | tables in `History` | Download paths, URLs, and metadata |
| **Cache** | `...\Cache\` | Cached pages, images |
| **Local Storage** | `...\Local Storage\` | localStorage, IndexedDB |
| **Bookmarks** | `...\Bookmarks` | JSON format |

**Parsing:**

Work from a copy of the database and collect related `-wal` and `-shm` files
when present. Chromium timestamps are microseconds since 1601-01-01 UTC.

```bash
# SQLite queries
sqlite3 -readonly History "
SELECT url, title, visit_count,
       datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') AS last_visit_utc
FROM urls ORDER BY last_visit_time DESC;"
```

Saved credentials and cookies are sensitive authentication material. Decrypt
them only when specifically authorized and use a validated tool that supports
the source browser and operating-system version. Browser-history suites such
as Hindsight can parse multiple related Chromium artifacts.

### Firefox

```bash
# places.sqlite
sqlite3 places.sqlite "SELECT url, visit_count FROM moz_places ORDER BY visit_count DESC;"

# formhistory.sqlite
sqlite3 formhistory.sqlite "SELECT fieldname, value FROM moz_formhistory;"

# cookies.sqlite
sqlite3 cookies.sqlite "SELECT name, value, host FROM moz_cookies;"
```

## 6.3 Email Forensics

### Outlook Stores (PST/OST)

```bash
# Convert PST to mbox/CSV
readpst -r mailbox.pst -o output/

# Read .msg
msgtool --read message.msg
```

### Email Header Analysis

```
Received: from mail.example.com (mail.example.com [192.0.2.1])
        by mx.corp.example (Postfix) with ESMTP id ABC123
        for <user@corp.example>; Mon, 28 Jul 2026 06:00:00 +0000
Received: from unknown (HELO localhost) (10.0.0.5)
        by mail.example.com with SMTP; Mon, 28 Jul 2026 05:59:30 +0000
X-Originating-IP: 203.0.113.42
Authentication-Results: mx.corp.example; dmarc=pass (p=reject)
```

**What to look at:**

- Chain of `Received:` (from bottom up)
- `X-Originating-IP` (starting point)
- `Authentication-Results` (SPF/DKIM/DMARC)

Header fields can be forged. Establish the organization's trusted mail-gateway
boundary and give evidentiary weight only to fields added by trusted systems or
corroborated by provider logs.

### SPF / DKIM / DMARC

```bash
# Check SPF
dig +short TXT example.com | grep spf

# Check DMARC
dig +short TXT _dmarc.example.com

# Check DKIM (need selector)
dig +short TXT selector._domainkey.example.com

# In header
Authentication-Results: mx.corp.example;
  spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=example.com;
  dkim=pass (signature verified) header.d=example.com;
  dmarc=pass (p=reject)
```

### Phishing Triage Workflow

```
1. Read header → find X-Originating-IP, Return-Path
2. Verify SPF/DKIM/DMARC
3. Find suspicious links (URLs in body)
4. Analyze attachments → malware analysis (Part 07)
5. Check sender domain (typosquatting?)
6. After validation and scoping, contain confirmed malicious indicators
```

## 6.4 Network Forensics

### Packet Capture

```bash
# tcpdump
tcpdump -i eth0 -w capture.pcap -G 3600 -W 1   # rotate hourly
tcpdump -i eth0 'host 203.0.113.42' -w suspicious.pcap

# tshark
tshark -i eth0 -w capture.pcap
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host
```

### Wireshark Filters

```
# Display filters
ip.addr == 203.0.113.42
tcp.port == 4444
http.request.method == "POST"
dns.qry.name contains "evil"
tls.handshake.type == 1

# Follow TCP Stream
# Right-click packet → Follow → TCP Stream

# IO Graph
# Statistics → IO Graph (see traffic spikes)
```

### File Carving from PCAPs

```bash
# Extract files from PCAP
tshark -r capture.pcap --export-objects "http,output_dir"
foremost -i capture.pcap -o carved_files/

# View HTTP objects
tshark -r capture.pcap -Y "http.response" -T fields -e http.content_type -e http.file_data
```

### Beacon Detection

> C2 traffic often has specific patterns.

**Indicators:**

1. **JA3 / JA3S**: TLS fingerprint of client/server
2. **Periodicity**: repeated intervals, often with jitter
3. **Domain generation**: DGA domains (random names)
4. **Size regularity**: repeated request or response sizes
5. **Tools**: Zeek, RITA, Wireshark, and tshark

```bash
# JA3 field availability depends on the tshark/Wireshark version
tshark -r capture.pcap -Y "tls.handshake" -T fields -e tls.handshake.ja3

# Review periodicity and connection statistics with RITA or Zeek
```

---

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 6 Summary

This chapter covers log, browser, email, and network evidence, including
authentication analysis, packet inspection, file extraction, and beacon
indicators using maintained parsers and network-analysis tools.
