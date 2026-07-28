# Part 03: Linux / macOS / Cloud / Containers Forensics

> Deep reference covering multiple platforms — Linux logs, macOS artifacts, CloudTrail,
> Entra, M365, and Docker/Kubernetes evidence.
> Tools: journalctl, ausearch, plutil, tmutil, mac_apt, AWS CLI, Azure CLI,
> kubectl, and Docker.

---

## 3.1 Linux Forensics

### /var/log (main log files)

| File | Contents |
|------|----------|
| `/var/log/auth.log` (Debian) / `/var/log/secure` (RHEL) | Authentication, SSH logins, sudo |
| `/var/log/syslog` / `/var/log/messages` | System events |
| `/var/log/wtmp` | Login/logout history (binary) |
| `/var/log/btmp` | Failed logins (binary) |
| `/var/log/utmp` | Current logins (binary) |
| `/var/log/faillog` | Failed login counts |
| `/var/log/lastlog` | Last login per user |
| `/var/log/dmesg` | Kernel ring buffer |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/cron` | Cron job execution |
| `/var/log/audit/audit.log` | Auditd events |

### Reading binary logs

```bash
# wtmp / btmp / utmp
last -f /var/log/wtmp          # login history
lastb -f /var/log/btmp         # failed logins
who /var/log/utmp              # current users

# faillog
faillog -u <username>          # failed login count

# lastlog
lastlog                        # last login per user
```

### journald (Systemd Journal)

> journald stores logs in binary format — use `journalctl` only.

```bash
# View all
journalctl

# Time range
journalctl --since "2026-07-28 00:00:00" --until "2026-07-28 06:00:00"

# Specific service
journalctl -u ssh.service

# Specific priority (0=emerg, 3=err)
journalctl -p err

# By UID
journalctl _UID=1000

# Search string
journalctl | grep "authentication failure"

# Export as JSON
journalctl -o json-pretty > journal.json

# Export as syslog
journalctl -o short > journal.syslog
```

### cron & at (scheduled tasks)

```bash
# System cron
/etc/cron.d/
/etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
/var/spool/cron/crontabs/   # user crontabs

# View user crontab
crontab -l -u <username>

# at jobs
/var/spool/at/

# systemd timers (modern replacement)
systemctl list-timers --all
```

### systemd Persistence

```bash
# Unit files
/etc/systemd/system/
/lib/systemd/system/

# View all services
systemctl list-units --type=service

# View unit file
systemctl cat <service_name>

# Timers
systemctl list-timers --all
```

### SSH Keys & Related Files

```bash
# Authorized keys (server side)
~/.ssh/authorized_keys

# Known hosts (client side)
~/.ssh/known_hosts

# Private/public keys
~/.ssh/id_rsa, id_ed25519, id_ecdsa

# SSH config
~/.ssh/config
/etc/ssh/ssh_config
/etc/ssh/sshd_config

# SSH logs
/var/log/auth.log | grep "ssh"
```

### /proc Recovery of deleted running binaries

> If a program is running but its file on disk is deleted — recover from /proc.

```bash
# List processes
ps aux

# Recover binary of PID 1234
cp /proc/1234/exe /evidence/recovered_binary_1234

# View memory map
cat /proc/1234/maps

# View open files (file descriptors)
ls -la /proc/1234/fd/

# View environment variables
cat /proc/1234/environ | tr '\0' '\n'

# View command line
cat /proc/1234/cmdline | tr '\0' ' '
```

### auditd (Linux Audit Framework)

```bash
# Search events
ausearch -m LOGIN          # login events
ausearch -m USER_AUTH      # authentication
ausearch -k key_name       # events with label
ausearch -ts today         # today's events
ausearch -ui 1000          # events for UID 1000

# Summaries
aureport -u                # user events
aureport -m                # MAC (login) events
aureport -f                # file events
aureport -x                # executable events
```

### Bash History & Hidden Files

```bash
# Bash history
~/.bash_history
/root/.bash_history

# Hidden files (dotfiles)
ls -la ~/

# Bashrc / profile
~/.bashrc
~/.profile
/etc/bash.bashrc
/etc/profile
```

## 3.2 macOS Forensics

### APFS Snapshots

```bash
# List snapshots
tmutil listlocalsnapshots /

# Mount snapshot
mount -t apfs -s <snapshot_uuid> /dev/disk1s1 /mnt/snapshot

# List with diskutil
diskutil apfs listSnapshots /Volumes/Macintosh\ HD
```

### Unified Logs

```bash
# View all (live)
log show

# Time range
log show --start "2026-07-28 00:00:00" --end "2026-07-28 06:00:00"

# Predicate filter
log show --predicate 'process == "sshd"' --info

# Export for analysis
log collect --output /evidence/unified.logarchive
log show --style syslog /evidence/unified.logarchive
```

### plists (Property Lists)

```bash
# Read plist
plutil -p /path/to/file.plist

# Convert to XML
plutil -convert xml1 file.plist

# Read value
defaults read /path/to/file HostName
```

### FSEvents

Parse FSEvents from a forensic image or verified copy with a maintained
macOS-forensics suite such as `mac_apt`. Do not use the Python `fsevents`
package as an artifact parser; it is intended to monitor live filesystem
events.

### TCC.db (Transparency, Consent, and Control)

```bash
# Location
/Library/Application Support/com.apple.TCC/TCC.db

# Read a forensic copy; live access requires appropriate Full Disk Access
sqlite3 TCC.db "SELECT * FROM access;"
```

### LaunchAgents / LaunchDaemons

```bash
# User agents
~/Library/LaunchAgents/

# System agents
/Library/LaunchAgents/
/Library/LaunchDaemons/

# System (hidden)
/System/Library/LaunchAgents/
/System/Library/LaunchDaemons/

# View loaded jobs
launchctl list
```

### Quarantine (Mark-of-the-Web on macOS)

```bash
# View xattr
xattr -l /path/to/file

# Quarantine attribute
xattr -p com.apple.quarantine /path/to/file

```

Do not delete or modify quarantine attributes on evidence. If a test requires
mutation, work only on a disposable, verified copy and document the action.

### knowledgeC.db & powerlog

```bash
# Location, app usage
~/Library/Application Support/Knowledge/knowledgeC.db

# Power events
/private/var/db/powerlog/
```

## 3.3 Cloud Forensics

### AWS CloudTrail

```bash
# Query events
aws cloudtrail lookup-events \
  --start-time 2026-07-28T00:00:00Z \
  --end-time 2026-07-28T06:00:00Z \
  --query 'Events[*].{Time:EventTime,Name:EventName,User:Username,Source:EventSource}'

# ConsoleLogin events
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin

# AssumeRole (credential theft)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole

# RunInstances (crypto mining)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances

# PutBucketPolicy (S3 exfiltration)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketPolicy
```

### Entra ID (Azure AD) Sign-ins

```powershell
# Install module
Install-Module Microsoft.Graph

# Sign-in logs
Get-MgAuditLogSignIn -Filter "createdDateTime ge 2026-07-28T00:00:00Z"

# Risky sign-ins
Get-MgRiskDetection | Where-Object { $_.RiskState -eq "atRisk" }

# Audit logs
Get-MgAuditLogDirectoryAudit
```

### M365 Unified Audit Log

```powershell
$Start = [datetime]"2026-07-28T00:00:00Z"
$End = [datetime]"2026-07-29T00:00:00Z"

# Search unified audit log
Search-UnifiedAuditLog -StartDate $Start -EndDate $End -RecordType ExchangeAdmin

# Mailbox access (suspicious)
Search-UnifiedAuditLog -StartDate $Start -EndDate $End -Operations MailItemsAccessed

# File downloads (SharePoint/OneDrive)
Search-UnifiedAuditLog -StartDate $Start -EndDate $End -Operations FileDownloaded
```

## 3.4 Container Forensics (Docker / Kubernetes)

> Principle: capture evidence before the container/pod disappears.

### Docker

```bash
# Data location
/var/lib/docker/
/var/lib/docker/containers/<container_id>/

# Inspect container
docker inspect <container_id>

# Show changes (diff)
docker diff <container_id>

# Export container (before it disappears)
docker export <container_id> > /evidence/container.tar

# Export image
docker save <image_id> > /evidence/image.tar

# Container logs
docker logs <container_id> > /evidence/container.log

# Process list in container
docker top <container_id>
```

### Kubernetes

Live Kubernetes commands can change cluster state and generate new telemetry.
Prefer provider snapshots, audit logs, runtime evidence, and API exports.
Use `kubectl debug`, `kubectl cp`, or an `etcd` snapshot only with explicit
authorization and record their side effects.

```bash
# Export workload and node metadata through the API
kubectl get pods,nodes -A -o yaml > /evidence/kubernetes-inventory.yaml

# Export events
kubectl get events -A -o yaml > /evidence/kubernetes-events.yaml

# Pod logs with timestamps
kubectl logs <pod_name> -n <namespace> --timestamps > /evidence/pod.log

# Provider or self-managed control-plane audit logs should be acquired separately

# Authorized self-managed control plane only
ETCDCTL_API=3 etcdctl snapshot save /evidence/etcd.db
```

---

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 3 Summary

This chapter covers Linux, macOS, cloud, container, and Kubernetes evidence
sources with collection and triage commands for their maintained native tools.
