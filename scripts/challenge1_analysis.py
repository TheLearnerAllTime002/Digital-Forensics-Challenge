import struct, datetime, hashlib, os, re, string

BASE = os.environ.get(
    "CHALLENGE1_DATA",
    os.path.join(os.path.dirname(__file__), "..", "data", "challenge1"),
)
EXT  = os.path.join(BASE, "extracted")

# ── helpers ──────────────────────────────────────────────────────────────────

def hashes(path):
    data = open(path, "rb").read()
    return data, {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size":   len(data),
    }

def pe_info(data):
    try:
        if data[:2] != b"MZ":
            return {}
        pe_off = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_off:pe_off+4] != b"PE\x00\x00":
            return {}
        machine   = struct.unpack_from("<H", data, pe_off+4)[0]
        ts        = struct.unpack_from("<I", data, pe_off+8)[0]
        subsystem = struct.unpack_from("<H", data, pe_off+0x5C)[0]
        arch_map  = {0x14c: "x86 (32-bit)", 0x8664: "x64 (64-bit)", 0x1c0: "ARM"}
        sub_map   = {1: "Native", 2: "Windows GUI", 3: "Windows Console"}
        return {
            "arch":      arch_map.get(machine, hex(machine)),
            "compile":   datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "subsystem": sub_map.get(subsystem, str(subsystem)),
        }
    except Exception as e:
        return {"error": str(e)}

def extract_strings(data, min_len=6):
    pat = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.decode() for m in re.findall(pat, data)]

def ioc_strings(strings):
    iocs = {"urls": [], "ips": [], "paths": [], "registry": [], "interesting": []}
    ip_re   = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    url_re  = re.compile(r"https?://[^\s\"'<>]+", re.I)
    path_re = re.compile(r"[A-Za-z]:\\[^\s\"'<>]{4,}", re.I)
    reg_re  = re.compile(r"(HKEY_|HKLM|HKCU|SOFTWARE\\)[^\s\"'<>]{4,}", re.I)
    keywords = ["cmd", "powershell", "wscript", "cscript", "rundll32", "regsvr32",
                "schtask", "startup", "inject", "shellcode", "download", "upload",
                "socket", "connect", "bind", "listen", "payload", "encrypt", "decrypt",
                "base64", "xor", "mutex", "CreateRemoteThread", "VirtualAlloc",
                "WriteProcessMemory", "LoadLibrary", "GetProcAddress", "WinExec",
                "ShellExecute", "InternetOpen", "HttpSendRequest", "WSAStartup",
                "keylog", "screenshot", "clipboard", "password", "credential",
                "LogMeIn", "LMI", "Guardian", "remote", "tunnel", "proxy"]
    for s in strings:
        if url_re.search(s):
            iocs["urls"].append(s)
        elif ip_re.search(s):
            iocs["ips"].append(s)
        elif path_re.search(s):
            iocs["paths"].append(s)
        elif reg_re.search(s):
            iocs["registry"].append(s)
        for kw in keywords:
            if kw.lower() in s.lower() and s not in iocs["interesting"]:
                iocs["interesting"].append(s)
    # deduplicate
    for k in iocs:
        iocs[k] = list(dict.fromkeys(iocs[k]))[:30]
    return iocs

def parse_prefetch(path):
    """Parse basic info from a Windows Prefetch file (MAM compressed or raw)."""
    data = open(path, "rb").read()
    info = {"file": os.path.basename(path)}
    # Version at offset 0
    ver = struct.unpack_from("<I", data, 0)[0] if len(data) > 4 else 0
    info["pf_version"] = ver  # 17=XP, 23=Vista/7, 26=Win8, 30=Win10
    # Run count and last run time differ by version
    try:
        if ver == 30:  # Win10 – may be MAM compressed; try raw offsets
            info["run_count"] = struct.unpack_from("<I", data, 208)[0]
            raw_ts = struct.unpack_from("<Q", data, 128)[0]
        elif ver == 26:
            info["run_count"] = struct.unpack_from("<I", data, 208)[0]
            raw_ts = struct.unpack_from("<Q", data, 128)[0]
        elif ver == 23:
            info["run_count"] = struct.unpack_from("<I", data, 152)[0]
            raw_ts = struct.unpack_from("<Q", data, 100)[0]
        else:
            info["run_count"] = "unknown version"
            raw_ts = 0
        if raw_ts:
            # Windows FILETIME → Unix
            unix_ts = (raw_ts - 116444736000000000) / 10000000
            info["last_run"] = datetime.datetime.utcfromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception as e:
        info["parse_error"] = str(e)
    # Extract readable strings (file paths referenced)
    strs = [m.decode("utf-16-le", errors="ignore").strip("\x00")
            for m in re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)]
    info["referenced_paths"] = [s for s in strs if "\\" in s][:20]
    return info

# ── SECTION 1: Prefetch Analysis ─────────────────────────────────────────────

print("=" * 70)
print("SECTION 1 — PREFETCH FILE ANALYSIS")
print("=" * 70)

pf_files = [f for f in os.listdir(BASE) if f.endswith(".pf")]
for pf in sorted(pf_files):
    info = parse_prefetch(os.path.join(BASE, pf))
    print(f"\n[PF] {pf}")
    print(f"     PF Version : {info.get('pf_version')} (30=Win10, 26=Win8, 23=Win7)")
    print(f"     Last Run   : {info.get('last_run', 'N/A')}")
    print(f"     Run Count  : {info.get('run_count', 'N/A')}")
    if info.get("referenced_paths"):
        print("     Referenced paths (sample):")
        for p in info["referenced_paths"][:8]:
            print(f"       {p}")

# ── SECTION 2: Sample Hashes ─────────────────────────────────────────────────

print("\n" + "=" * 70)
print("SECTION 2 — SAMPLE HASHES")
print("=" * 70)

samples = ["KFJUUWORMM.exe", "LMIGuardianDll.dll", "BLOGYZOBEU.dat"]
sample_data = {}
for name in samples:
    path = os.path.join(EXT, name)
    data, h = hashes(path)
    sample_data[name] = data
    print(f"\n[{name}]")
    print(f"  Size   : {h['size']:,} bytes")
    print(f"  MD5    : {h['md5']}")
    print(f"  SHA1   : {h['sha1']}")
    print(f"  SHA256 : {h['sha256']}")

# ── SECTION 3: PE Header Analysis ────────────────────────────────────────────

print("\n" + "=" * 70)
print("SECTION 3 — PE HEADER ANALYSIS")
print("=" * 70)

for name in ["KFJUUWORMM.exe", "LMIGuardianDll.dll"]:
    info = pe_info(sample_data[name])
    print(f"\n[{name}]")
    for k, v in info.items():
        print(f"  {k:12}: {v}")

# ── SECTION 4: String / IOC Extraction ───────────────────────────────────────

print("\n" + "=" * 70)
print("SECTION 4 — IOC / STRING EXTRACTION")
print("=" * 70)

for name in samples:
    strs = extract_strings(sample_data[name])
    iocs = ioc_strings(strs)
    print(f"\n[{name}]  ({len(strs)} printable strings found)")
    for cat, items in iocs.items():
        if items:
            print(f"  -- {cat.upper()} --")
            for i in items:
                print(f"     {i}")

# ── SECTION 5: BLOGYZOBEU.dat entropy / type check ───────────────────────────

print("\n" + "=" * 70)
print("SECTION 5 — BLOGYZOBEU.dat FILE TYPE & ENTROPY")
print("=" * 70)

dat = sample_data["BLOGYZOBEU.dat"]
print(f"  Magic bytes (hex) : {dat[:16].hex()}")
print(f"  Magic bytes (raw) : {dat[:8]}")

import math
from collections import Counter
counts = Counter(dat)
entropy = -sum((c/len(dat)) * math.log2(c/len(dat)) for c in counts.values() if c)
print(f"  Shannon entropy   : {entropy:.4f}  (7.0+ = likely encrypted/compressed)")

# Check for common file signatures
sigs = {
    b"MZ":       "PE Executable",
    b"PK":       "ZIP archive",
    b"\x7fELF":  "ELF binary",
    b"Rar!":     "RAR archive",
    b"\x1f\x8b": "GZIP",
    b"7z\xbc\xaf": "7-Zip",
    b"MSCF":     "CAB archive",
    b"\xd0\xcf": "OLE2 / MS Office",
}
matched = "Unknown"
for sig, label in sigs.items():
    if dat[:len(sig)] == sig:
        matched = label
        break
print(f"  File type match   : {matched}")

print("\n" + "=" * 70)
print("ANALYSIS COMPLETE")
print("=" * 70)
