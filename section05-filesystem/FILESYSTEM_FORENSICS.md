# Part 05: Filesystem Deep-Dive

> Deep filesystem analysis — MFT, deleted-file recovery, slack space,
> file carving, ADS, Mark-of-the-Web, timestomping.
> Tools: Sleuth Kit (fls, icat, istat, mactime, hfind), MFTECmd, analyzeMFT,
> foremost, scalpel, photorec, binwalk, lads.

---

## 5.1 The MFT ($MFT)

> Master File Table — the heart of NTFS.

### Structure

```
$MFT = table storing FILE records for every file/folder in volume
Each FILE record = 1KB (usually) or more
FILE record contains attributes:
  $STANDARD_INFORMATION ($SI) — timestamps, flags, owner/security identifiers
  $FILE_NAME ($FN)            — name and namespace timestamps; may repeat
  $DATA                       — file content (resident or non-resident)
  $OBJECT_ID                  — optional object identifier
  $ATTRIBUTE_LIST             — attributes stored in extension records
```

`$LogFile`, `$Bitmap`, and `$Extend\$UsnJrnl` are NTFS metadata files with
their own MFT records; they are not attributes embedded in every file record.

### Attribute Residency

- **Resident**: data small enough to fit in FILE record
- **Non-resident**: data large → points to clusters on disk

### Parsing MFT

```bash
# Use MFTECmd (Eric Zimmerman)
MFTECmd.exe -f "C:\evidence\$MFT" --csv C:\output

# Use analyzeMFT (Python)
analyzeMFT.py -f \$MFT -o mft.csv

# Use Sleuth Kit
fls -r -m / image.dd > file_list.txt
istat image.dd <inode>    # details of a file
```

## 5.2 MAC Times

> Modified, Accessed, Created — file timestamps.

### $SI vs $FN

`$STANDARD_INFORMATION` and `$FILE_NAME` timestamps have different update
semantics. `$FILE_NAME` timestamps are commonly updated during namespace
operations and may be stale after content changes; neither set is inherently
trustworthy in isolation.

**Timestomping detection:**

- compare all four timestamps with filesystem activity and the source OS;
- investigate implausible ordering, timestamp clustering, and resolution
  artifacts; and
- corroborate with `$UsnJrnl`, `$LogFile`, event logs, application records, and
  external timestamps before concluding manipulation.

## 5.3 Slack & Unallocated Space

### Definitions

- **Slack space**: unused space at end of cluster not used by file
- **Unallocated space**: space not allocated to any file (deleted files)

### Extraction

```bash
# Use Sleuth Kit
blkls image.dd > unallocated.dd    # unallocated space

# Include file slack after confirming the installed version's flags
blkls -s image.dd > slack.dd

# View all MAC times
mactime -b bodyfile.txt > timeline.txt

# Create bodyfile
fls -r -m / image.dd > bodyfile.txt
```

## 5.4 Deleted-File Recovery

```bash
# Find deleted files
fls -r -d -p image.dd

# Recover one file by metadata address
icat image.dd 12345 > recovered_file.bin

# Map a metadata address back to known names
ffind -a image.dd 12345

# Recover unallocated files while preserving the image
tsk_recover image.dd recovered/
```

## 5.5 File Carving

> Extract files from unallocated/slack space using signatures (magic bytes).

### Tools

| Tool | Usage |
|------|-------|
| **foremost** | `foremost -i image.dd -o output/` |
| **scalpel** | `scalpel -c scalpel.conf image.dd -o output/` |
| **photorec** | `photorec image.dd` (interactive; use an image, not evidence media) |
| **binwalk** | `binwalk -e firmware.bin` (firmware) |

### Custom Signatures (Scalpel)

```config
# scalpel.conf
png     y       200000  \x89\x50\x4e\x47\x0d\x0a\x1a\x0a  \x00\x00\x00\x00\x49\x45\x4e\x44
jpg     y       200000  \xff\xd8\xff\xe0\x00\x10\x4a\x46  \xff\xd9
pdf     y       500000  \x25\x50\x44\x46\x2d\x31\x2e       \x25\x25\x45\x4f\x46
```

### Header/Footer Signatures

| Type | Header (magic bytes) | Footer |
|------|---------------------|--------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `00 00 00 00 49 45 4E 44` |
| JPG | `FF D8 FF E0` | `FF D9` |
| PDF | `25 50 44 46 2D 31` | `25 25 45 4F 46` |
| ZIP | `50 4B 03 04` | `50 4B 05 06` |
| GIF | `47 49 46 38` | `00 3B` |
| DOCX | `50 4B 03 04` (zip) | — |

## 5.6 Alternate Data Streams (ADS)

> NTFS allows files to have multiple streams — malware hides code here.

### Detection

```powershell
# PowerShell
Get-Item -Path "C:\path\to\file.txt" -Stream *

# CMD
dir /r C:\path\to\

# Use a dedicated Windows ADS enumeration tool
lads.exe C:\path\to\dir\
```

### Extraction

```powershell
# View stream
Get-Content -Path "file.txt" -Stream "hidden"

# For binary extraction, use a validated forensic parser on a verified copy
```

## 5.7 Mark-of-the-Web (MOTW)

> Tag indicating a file came from the internet (Zone.Identifier).

### Location

```
Downloaded file → has ADS named Zone.Identifier
```

### Check

```powershell
# View MOTW
Get-Item "file.exe" -Stream Zone.Identifier

# View content
Get-Content "file.exe:Zone.Identifier"

# Result:
# [ZoneTransfer]
# ZoneId=3           # 3 = Internet
# ReferrerUrl=https://evil.example.com/
# HostUrl=https://evil.example.com/malware.exe
```

### Why It Matters

- Can support an internet-origin hypothesis
- May contain optional source and referrer URLs
- Absence does not prove anti-forensics: the stream may never have been added,
  or it may have been lost during archive extraction, transfer, or copying to a
  filesystem without NTFS alternate data streams

## 5.8 Timestomping Detection

> Altering MAC times to hide actions.

### Detection Methods

1. **$SI vs $FN mismatch**:
   - Use MFTECmd → compare SI/MFT (STDINFO vs FILENAME)
   - investigate ordering that conflicts with the source OS and case timeline

2. **Invalid or boundary timestamps**:
   - zero, epoch, or format-boundary values may indicate corruption, parser
     limitations, application behavior, or manipulation

3. **$USNJRNL / $LogFile correlation**:
   - use independent activity records to test the timestamp hypothesis

4. **Clustering**:
   - Multiple files with same time → batch timestomp

### Recommended Workflow

Parse `$MFT`, `$UsnJrnl`, and `$LogFile` with maintained tools such as
MFTECmd, Sleuth Kit, or Autopsy. Correlate timestamp anomalies with independent
event sources before concluding that timestomping occurred; an `$SI`/`$FN`
mismatch alone is an indicator, not proof.

---

## Recommended Tooling

Use the maintained tools described in this chapter instead of unreviewed custom wrappers. Pin tool versions, preserve original evidence, record command lines and hashes, and validate the workflow on representative test data before casework.

## Part 5 Summary

This chapter covers MFT structure, MAC timestamps, slack and unallocated space,
deleted-file recovery, carving, alternate data streams, Mark-of-the-Web, and
correlated timestomping analysis.
