"""
Challenge 1 - Malware Analysis
Output display + screenshot saver
"""

import ctypes, struct, datetime, hashlib, os, re, math
from collections import Counter
from PIL import Image, ImageDraw, ImageFont

BASE   = os.environ.get(
    "CHALLENGE1_DATA",
    os.path.join(os.path.dirname(__file__), "..", "data", "challenge1"),
)
EXT    = os.path.join(BASE, "extracted")
OUTDIR = os.environ.get(
    "CHALLENGE1_OUTPUT",
    os.path.join(os.path.dirname(__file__), "..", "data", "generated", "challenge1"),
)
os.makedirs(OUTDIR, exist_ok=True)

# ── helpers ───────────────────────────────────────────────────────────────────

def hashes(path):
    data = open(path, "rb").read()
    return data, hashlib.md5(data).hexdigest(), hashlib.sha1(data).hexdigest(), hashlib.sha256(data).hexdigest()

def pe_info(data):
    if data[:2] != b"MZ": return {}
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off+4] != b"PE\x00\x00": return {}
    machine   = struct.unpack_from("<H", data, pe_off+4)[0]
    ts        = struct.unpack_from("<I", data, pe_off+8)[0]
    subsystem = struct.unpack_from("<H", data, pe_off+0x5C)[0]
    return {
        "arch":      {0x14c:"x86 (32-bit)", 0x8664:"x64 (64-bit)"}.get(machine, hex(machine)),
        "compile":   datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "subsystem": {2:"Windows GUI", 3:"Windows Console"}.get(subsystem, str(subsystem)),
    }

def decompress_mam(data):
    if data[:3] != b"MAM": return data
    uncompressed_size = struct.unpack_from("<I", data, 4)[0]
    buf = ctypes.create_string_buffer(uncompressed_size)
    final_size = ctypes.c_ulong(0)
    workspace  = ctypes.create_string_buffer(0x10000)
    status = ctypes.windll.ntdll.RtlDecompressBufferEx(
        4, buf, uncompressed_size,
        (ctypes.c_char * (len(data)-8)).from_buffer_copy(data[8:]),
        len(data)-8, ctypes.byref(final_size), workspace)
    return buf.raw[:final_size.value] if status == 0 else None

def parse_pf(path):
    raw  = open(path, "rb").read()
    data = decompress_mam(raw)
    if not data: return {}
    ver      = struct.unpack_from("<I", data, 0)[0]
    exe_name = data[16:76].decode("utf-16-le", errors="ignore").rstrip("\x00")
    run_count= struct.unpack_from("<I", data, 208)[0]
    runs = []
    for i in range(8):
        raw_ts = struct.unpack_from("<Q", data, 128 + i*8)[0]
        if raw_ts:
            unix_ts = (raw_ts - 116444736000000000) / 10000000
            if 0 < unix_ts < 2e9:
                runs.append(datetime.datetime.fromtimestamp(unix_ts, datetime.UTC).strftime("%Y-%m-%d %H:%M:%S UTC"))
    strs  = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)
    paths = list(dict.fromkeys(
        s.decode("utf-16-le", errors="ignore").strip()
        for s in strs
        if "\\" in s.decode("utf-16-le", errors="ignore")
    ))[:20]
    return {"exe": exe_name, "ver": ver, "run_count": run_count, "runs": runs, "paths": paths}

def ioc_extract(data):
    strs   = [m.decode() for m in re.findall(rb"[\x20-\x7e]{6,}", data)]
    urls   = [s for s in strs if re.search(r"https?://", s, re.I)]
    ips    = [s for s in strs if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", s)
              and not re.search(r"https?://", s, re.I)]
    paths  = [s for s in strs if re.search(r"[A-Za-z]:\\", s)]
    kws    = ["LoadLibrary","GetProcAddress","VirtualAlloc","WriteProcessMemory",
              "CreateRemoteThread","ShellExecute","WinExec","InternetOpen",
              "WSAStartup","LogMeIn","LMI","Guardian","LMIGuardian","pdb",
              "BLOGYZOBEU","_READY_TEMP_","CLKSTG_3CDU","cmd","powershell"]
    interesting = list(dict.fromkeys(
        s for s in strs for kw in kws if kw.lower() in s.lower()
    ))[:25]
    return {
        "URLs":        list(dict.fromkeys(urls))[:10],
        "IPs/Domains": list(dict.fromkeys(ips))[:10],
        "File Paths":  list(dict.fromkeys(paths))[:10],
        "Interesting": interesting,
    }

def entropy(data):
    counts = Counter(data)
    return -sum((c/len(data))*math.log2(c/len(data)) for c in counts.values() if c)

# ── build text sections ───────────────────────────────────────────────────────

sections = {}

# Section 1 – Prefetch
lines = ["SECTION 1 — PREFETCH FILE ANALYSIS", "="*62, ""]
pf_files = sorted(f for f in os.listdir(BASE) if f.endswith(".pf"))
for pf in pf_files:
    info = parse_pf(os.path.join(BASE, pf))
    lines += [f"[{pf}]",
              f"  EXE Name  : {info.get('exe','')}",
              f"  PF Ver    : {info.get('ver','')}  (31 = Windows 10/11)",
              f"  Run Count : {info.get('run_count','')}",
              f"  Last Run  : {info['runs'][0] if info.get('runs') else 'N/A'}"]
    for r in info.get("runs", [])[1:]:
        lines.append(f"            : {r}")
    lines.append("  Key referenced paths:")
    for p in info.get("paths", [])[:6]:
        lines.append(f"    {p}")
    lines.append("")
sections["1_prefetch"] = lines

# Section 2 – Hashes
lines = ["SECTION 2 — SAMPLE HASHES", "="*62, ""]
samples = ["KFJUUWORMM.exe", "LMIGuardianDll.dll", "BLOGYZOBEU.dat"]
sample_data = {}
for name in samples:
    path = os.path.join(EXT, name)
    data, md5, sha1, sha256 = hashes(path)
    sample_data[name] = data
    lines += [f"[{name}]",
              f"  Size   : {len(data):,} bytes",
              f"  MD5    : {md5}",
              f"  SHA1   : {sha1}",
              f"  SHA256 : {sha256}", ""]
sections["2_hashes"] = lines

# Section 3 – PE headers
lines = ["SECTION 3 — PE HEADER ANALYSIS", "="*62, ""]
for name in ["KFJUUWORMM.exe", "LMIGuardianDll.dll"]:
    info = pe_info(sample_data[name])
    lines += [f"[{name}]"] + [f"  {k:12}: {v}" for k,v in info.items()] + [""]
sections["3_pe_headers"] = lines

# Section 4 – IOCs
lines = ["SECTION 4 — IOC / STRING EXTRACTION", "="*62, ""]
for name in samples:
    iocs = ioc_extract(sample_data[name])
    lines.append(f"[{name}]")
    for cat, items in iocs.items():
        if items:
            lines.append(f"  -- {cat} --")
            lines += [f"     {i}" for i in items]
    lines.append("")
sections["4_iocs"] = lines

# Section 5 – BLOGYZOBEU.dat
dat = sample_data["BLOGYZOBEU.dat"]
ent = entropy(dat)
sigs = {b"MZ":"PE Exe", b"PK":"ZIP", b"\x7fELF":"ELF",
        b"Rar!":"RAR", b"\x1f\x8b":"GZIP", b"\xd0\xcf":"OLE2"}
ftype = next((v for k,v in sigs.items() if dat[:len(k)]==k), "Unknown/Encrypted")
lines = ["SECTION 5 — BLOGYZOBEU.dat ENTROPY & TYPE", "="*62, "",
         f"  Magic bytes (hex) : {dat[:16].hex()}",
         f"  File type match   : {ftype}",
         f"  Shannon entropy   : {ent:.4f}  (>7.0 = encrypted/compressed/packed)",
         "",
         "  INTERPRETATION:",
         "  Entropy of 7.96 is near-maximum (8.0 = perfectly random).",
         "  This strongly indicates the file is either encrypted payload",
         "  data or a packed/compressed blob — consistent with a C2",
         "  data file or second-stage payload dropped by KFJUUWORMM.exe.",
         ""]
sections["5_dat_entropy"] = lines

# ── print all to console ──────────────────────────────────────────────────────

for sec_lines in sections.values():
    for line in sec_lines:
        print(line)
    print()

# ── save screenshots as PNG ───────────────────────────────────────────────────

def save_screenshot(title, lines, filename):
    font_size = 14
    try:
        font = ImageFont.truetype("cour.ttf", font_size)
    except:
        font = ImageFont.load_default()

    padding   = 20
    line_h    = font_size + 4
    width     = 900
    height    = padding*2 + len(lines)*line_h + 40

    img  = Image.new("RGB", (width, height), color=(18, 18, 18))
    draw = ImageDraw.Draw(img)

    # title bar
    draw.rectangle([0, 0, width, 36], fill=(40, 40, 80))
    draw.text((10, 8), f"Challenge 1 — Malware Analysis  |  {title}", font=font, fill=(200, 220, 255))

    y = 46
    for line in lines:
        color = (255, 255, 255)
        if line.startswith("===") or line.startswith("SECTION"):
            color = (100, 200, 255)
        elif line.startswith("[") and line.endswith("]"):
            color = (255, 200, 80)
        elif line.strip().startswith("--") and line.strip().endswith("--"):
            color = (150, 255, 150)
        elif "SHA256" in line or "MD5" in line or "SHA1" in line:
            color = (200, 200, 200)
        elif "CLKSTG_3CDU" in line or "_READY_TEMP_" in line or "LMIGUARDIAN" in line:
            color = (255, 120, 120)
        elif "entropy" in line.lower() or "encrypted" in line.lower():
            color = (255, 160, 60)
        draw.text((padding, y), line[:110], font=font, fill=color)
        y += line_h

    out_path = os.path.join(OUTDIR, filename)
    img.save(out_path)
    print(f"[SAVED] {out_path}")

save_screenshot("Prefetch Analysis",       sections["1_prefetch"],   "01_prefetch_analysis.png")
save_screenshot("Sample Hashes",           sections["2_hashes"],     "02_sample_hashes.png")
save_screenshot("PE Header Analysis",      sections["3_pe_headers"], "03_pe_headers.png")
save_screenshot("IOC String Extraction",   sections["4_iocs"],       "04_ioc_strings.png")
save_screenshot("BLOGYZOBEU.dat Entropy",  sections["5_dat_entropy"],"05_dat_entropy.png")

print(f"\nAll screenshots saved to: {OUTDIR}")
