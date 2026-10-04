# Challenge 1 — Malware Analysis Report

---

## Scope

Analysis date: 04 October 2026

---

## Executive Summary

During this analysis I was handed a set of Windows artefacts from a victim machine — six Prefetch files and a
password-protected archive containing three samples. After extracting and examining everything, the picture that
emerged is pretty clear: someone (or something) abused a trojanised copy of LogMeIn's LMIGuardian service to
establish remote access on the victim's Windows 10 machine. The malware dropped multiple randomly-named executables
(KFJUUWORMM.EXE, MHYMHQMUDY.EXE, MQMJXFJVPE.EXE, YVWPFLNRPH.EXE) into a hidden staging folder under the victim
user's TEMP directory, loaded a custom DLL (LMIGuardianDll.dll) alongside each one, and left behind an encrypted
data blob (BLOGYZOBEU.dat) that is almost certainly a payload or C2 data store. The infection appears to have
started as early as March 2026 and was still active in July 2026.

---

## Tools Used

| Tool / Method              | Purpose                                              |
|----------------------------|------------------------------------------------------|
| Python 3 (stdlib only)     | Prefetch MAM decompression, PE parsing, hash calc    |
| Pillow (PIL)               | Saving annotated screenshots as PNG                  |
| Windows ntdll (ctypes)     | RtlDecompressBufferEx for Win10 prefetch files       |
| Manual string analysis     | IOC extraction, PDB path review, entropy calculation |
| VirusTotal (passive lookup)| Hash reputation check (recommended, not run live)    |

---

## Methodology

### Analysis

I started by listing all the artefacts and noting what each one was. The `.pf` files are Windows Prefetch files —
Windows automatically creates one every time an executable runs, recording the filename, a hash of its path, how
many times it ran, and the last eight run timestamps. The `victim_samples.zip` was password-protected, so I
extracted it using Python's zipfile module with the supplied password.

Once I had the samples out, I worked through them in a logical order:

1. Decompressed the Prefetch files — Windows 10 stores them in MAM (XPRESS Huffman) format, so I used
   `RtlDecompressBufferEx` via ctypes to get the raw binary, then parsed the version-31 layout to pull out
   execution timestamps, run counts, and the list of files the executable touched on disk.

2. Computed cryptographic hashes (MD5, SHA-1, SHA-256) for all three extracted samples so they can be submitted
   to VirusTotal or cross-referenced against threat-intel feeds.

3. Parsed the PE headers of the two executables to get architecture, compile timestamp, and subsystem type.

4. Extracted printable strings from all three files and filtered them for URLs, IP addresses, file paths, registry
   keys, and security-relevant API names (LoadLibrary, GetProcAddress, VirtualAlloc, etc.).

5. Checked the entropy of BLOGYZOBEU.dat to determine whether it is plaintext, compressed, or encrypted.

### Findings

**Prefetch Analysis**

All six Prefetch files are version 31 (Windows 10/11). The most important findings are:

- `CD DRIVE.EXE` ran at least 6 times between March and July 2026. Its prefetch shows it loaded from a removable
  volume (`\VOLUME{0000000000000000-7a65b5ae}`) — the all-zero GUID is the classic signature of a USB/removable
  drive. This is the initial infection vector: malware disguised as "CD DRIVE.EXE" was run directly off a USB
  stick.

- `KFJUUWORMM.EXE`, `MHYMHQMUDY.EXE`, `MQMJXFJVPE.EXE`, and `YVWPFLNRPH.EXE` all ran from the same staging
  path: `\USERS\CLKSTG_3CDU\APPDATA\LOCAL\TEMP\_READY_TEMP_\`. The folder name `_READY_TEMP_` is not a standard
  Windows folder — it was created by the malware. All four EXEs also loaded `LMIGUARDIANDLL.DLL` from the same
  staging folder, confirming they are variants of the same malware family.

- `AEXINSTALLPRECHECK.EXE` ran once on 2026-06-03 from `\WINDOWS\TEMP\AEX_{...}`. This looks like a legitimate
  Ivanti/LANDesk agent pre-check installer — possibly a decoy or a legitimate tool that was already on the machine.

**Sample: KFJUUWORMM.exe**

- Size: 408,984 bytes | MD5: f8e8932263c7289bc8069f897a4c71eb
- SHA256: 1397b2f7014900d2b203bda64816accbd4211dd6ce347479ac169f683e1a2f61
- Architecture: x86 (32-bit) | Subsystem: Windows GUI | Compiled: 2018-10-15
- The PDB path embedded in the binary is:
  `D:\17\guardiansvc-git\latest\main\RA\LMIGuardian\x86\LMIGuardianSvc.pdb`
  This is the build path for LogMeIn's LMIGuardian service — the binary is either a stolen/modified copy of the
  legitimate LogMeIn Guardian service EXE, or a trojanised wrapper that impersonates it.
- It explicitly loads `LMIGuardianDll.dll` by name using `LoadLibraryA` / `GetProcAddress`, and registers COM
  objects under the GUID `{67E4A0D8-8675-4FBB-BC62-F10EC894327E}` with the service name `LMIGuardianSvc`.
- It contacts `https://secure.logmein.com` — this could be legitimate LogMeIn C2 traffic, or it could be used
  as cover traffic while the real C2 channel runs through the custom DLL.

**Sample: LMIGuardianDll.dll**

- Size: 1,864,192 bytes | MD5: 7e598d681d563f9c3c1611e95eed4448
- SHA256: 1df53ad99ab1ab4172ed1aaf2722263c2a2dc70d354e680bfd4f0e40244ebdc5
- Architecture: x86 (32-bit) | Compiled: 2024-10-22 (much more recent than the EXE — custom build)
- The PDB path is: `DJSLAJFLSAJLFALFJLSAFJK\Debug\LMIGuardianDll.pdb`
  The project folder name `DJSLAJFLSAJLFALFJLSAFJK` is clearly a random/obfuscated name — this is NOT the
  legitimate LogMeIn DLL. It was compiled in October 2024 by the attacker using Visual Studio 2022.
- Contains socket/network strings: "already connected", "connection refused", "connection reset", "not connected"
  — consistent with a network communication module.
- Imports `GetProcAddress`, `LoadLibraryA`, `LoadLibraryExW` — dynamic API resolution, a common evasion technique.
- The `cmd_tmp` string suggests it may spawn command-line processes.

**Sample: BLOGYZOBEU.dat**

- Size: 5,368,012 bytes | MD5: 22346172a5b6ead1710d460f9b1ecbad
- SHA256: ac8bf64655e6ed9b91099f170367a5623cbac9c31da0550bdd6fa413ec2e31ee
- Magic bytes do not match any known file format signature.
- Shannon entropy: 7.9591 out of a maximum of 8.0 — this is near-perfectly random data.
- This is almost certainly an encrypted payload, an encrypted C2 configuration blob, or exfiltrated data that
  has been encrypted before storage. The malware (KFJUUWORMM.exe + LMIGuardianDll.dll) likely reads and decrypts
  this file at runtime.

### Outcome

The victim machine (user profile: `CLKSTG_3CDU`) was compromised via a USB drive carrying `CD DRIVE.EXE`. Once
executed, the malware:

1. Created a hidden staging folder at `%LOCALAPPDATA%\TEMP\_READY_TEMP_\`
2. Dropped multiple randomly-named EXE variants (KFJUUWORMM, MHYMHQMUDY, MQMJXFJVPE, YVWPFLNRPH) and a custom
   `LMIGuardianDll.dll` into that folder
3. Registered itself as a COM service impersonating LogMeIn's LMIGuardian to blend in with legitimate software
4. Used the DLL to establish network connectivity (likely remote access / C2)
5. Stored an encrypted data blob (BLOGYZOBEU.dat) — possibly for persistence data, stolen credentials, or a
   second-stage payload

The malware family appears to be a custom Remote Access Tool (RAT) built on top of (or disguised as) the LogMeIn
Guardian remote-access framework. The use of multiple randomly-named EXE copies suggests the attacker was rotating
the binary name to evade hash-based detection.

---

## Step-by-Step Process with Screenshots

### Step 1 — Inventory the Artefacts

Opened the victim_artifacts folder and noted the contents:
- 6 x Windows Prefetch files (.pf)
- 1 x password-protected ZIP (victim_samples.zip)

Screenshot: [01_prefetch_analysis.png](../docs/evidence/challenge1/01_prefetch_analysis.png)

### Step 2 — Extract the ZIP

Used Python's zipfile module with password `Sample_data@2026#` to extract:
- KFJUUWORMM.exe (408 KB)
- LMIGuardianDll.dll (1.8 MB)
- BLOGYZOBEU.dat (5.1 MB)

### Step 3 — Decompress and Parse Prefetch Files

Windows 10 Prefetch files use MAM (XPRESS Huffman) compression. Used `RtlDecompressBufferEx` via ctypes to
decompress each file, then parsed the version-31 layout to extract:
- Executable name
- Run count
- Last 8 run timestamps (Windows FILETIME → UTC)
- Referenced file paths (loaded DLLs, data files)

Key finding: all four random-named EXEs loaded from `_READY_TEMP_` and loaded `LMIGUARDIANDLL.DLL`.
CD DRIVE.EXE loaded from a removable volume (USB).

Screenshot: [01_prefetch_analysis.png](../docs/evidence/challenge1/01_prefetch_analysis.png)

### Step 4 — Hash All Samples

Computed MD5, SHA-1, SHA-256 for all three extracted files for threat-intel lookup.

Screenshot: [02_sample_hashes.png](../docs/evidence/challenge1/02_sample_hashes.png)

### Step 5 — Parse PE Headers

Parsed the PE headers of KFJUUWORMM.exe and LMIGuardianDll.dll:
- Both are x86 32-bit Windows GUI binaries
- KFJUUWORMM.exe compiled 2018 (matches legitimate LogMeIn build era)
- LMIGuardianDll.dll compiled October 2024 (attacker's custom build)

Screenshot: [03_pe_headers.png](../docs/evidence/challenge1/03_pe_headers.png)

### Step 6 — Extract Strings and IOCs

Extracted all printable strings (≥6 chars) and filtered for:
- URLs → LogMeIn / DigiCert certificate URLs in KFJUUWORMM.exe
- PDB paths → revealed build directories confirming trojanised vs custom DLL
- API imports → LoadLibrary, GetProcAddress (dynamic resolution / evasion)
- Network strings in LMIGuardianDll.dll → socket connection indicators

Screenshot: [04_ioc_strings.png](../docs/evidence/challenge1/04_ioc_strings.png)

### Step 7 — Entropy Analysis of BLOGYZOBEU.dat

Calculated Shannon entropy = 7.9591. No known file signature matched.
Conclusion: encrypted payload or C2 data blob.

Screenshot: [05_dat_entropy.png](../docs/evidence/challenge1/05_dat_entropy.png)

---

## IOC Summary Table

| Indicator                          | Type         | Notes                                      |
|------------------------------------|--------------|--------------------------------------------|
| CD DRIVE.EXE                       | Filename     | Initial dropper, ran from USB drive        |
| KFJUUWORMM.EXE                     | Filename     | Trojanised LMIGuardian service EXE         |
| MHYMHQMUDY.EXE                     | Filename     | Variant / copy of KFJUUWORMM               |
| MQMJXFJVPE.EXE                     | Filename     | Variant / copy of KFJUUWORMM               |
| YVWPFLNRPH.EXE                     | Filename     | Variant / copy of KFJUUWORMM               |
| LMIGuardianDll.dll                 | Filename     | Custom attacker-built RAT DLL              |
| BLOGYZOBEU.dat                     | Filename     | Encrypted payload / C2 data blob           |
| %LOCALAPPDATA%\TEMP\_READY_TEMP_\  | Path         | Malware staging directory                  |
| f8e8932263c7289bc8069f897a4c71eb   | MD5          | KFJUUWORMM.exe                             |
| 7e598d681d563f9c3c1611e95eed4448   | MD5          | LMIGuardianDll.dll                         |
| 22346172a5b6ead1710d460f9b1ecbad   | MD5          | BLOGYZOBEU.dat                             |
| 1397b2f7014900d2b203bda64816accbd4211dd6ce347479ac169f683e1a2f61 | SHA256 | KFJUUWORMM.exe |
| 1df53ad99ab1ab4172ed1aaf2722263c2a2dc70d354e680bfd4f0e40244ebdc5 | SHA256 | LMIGuardianDll.dll |
| ac8bf64655e6ed9b91099f170367a5623cbac9c31da0550bdd6fa413ec2e31ee | SHA256 | BLOGYZOBEU.dat |
| https://secure.logmein.com         | URL          | C2 / cover traffic via LogMeIn             |
| CLKSTG_3CDU                        | Username     | Victim user account on compromised machine |
| {67E4A0D8-8675-4FBB-BC62-F10EC894327E} | GUID    | COM registration for LMIGuardianSvc        |

---

## Remediation Recommendations

1. Isolate the machine immediately — disconnect from the network to stop any active C2 communication.
2. Block the hashes above at the endpoint security layer and at the perimeter.
3. Block `secure.logmein.com` at the proxy/firewall if LogMeIn is not an authorised tool in the environment.
4. Search all other machines for the staging path `_READY_TEMP_` and the DLL name `LMIGuardianDll.dll`.
5. Enforce USB device control policy — the initial infection came from a USB drive. Block unauthorised USB
   storage devices via Group Policy or endpoint DLP.
6. Audit COM registrations for `LMIGuardianSvc` GUID `{67E4A0D8-8675-4FBB-BC62-F10EC894327E}` across the estate.
7. Reimage the victim machine — given the depth of compromise and the encrypted data blob, a clean rebuild is
   safer than attempting to clean in place.
8. Preserve BLOGYZOBEU.dat for further analysis — decrypting it may reveal exfiltrated data or additional IOCs.
