import ctypes, struct, datetime, os, re

BASE = os.environ.get(
    "CHALLENGE1_DATA",
    os.path.join(os.path.dirname(__file__), "..", "data", "challenge1"),
)

def decompress_mam(data):
    """Decompress Windows 10 MAM-compressed prefetch using RtlDecompressBufferEx."""
    if data[:3] != b"MAM":
        return data  # already raw
    uncompressed_size = struct.unpack_from("<I", data, 4)[0]
    buf = ctypes.create_string_buffer(uncompressed_size)
    final_size = ctypes.c_ulong(0)
    workspace = ctypes.create_string_buffer(0x10000)
    # COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004 | 0x0100 = 0x0104... actually LZNT1=2, XPRESS=3, XPRESS_HUFF=4
    # MAM uses XPRESS_HUFF (0x0004) with COMPRESSION_ENGINE_MAXIMUM (0x0100) -> 0x0104? No.
    # Actually RtlDecompressBufferEx with CompressionFormat = COMPRESSION_FORMAT_XPRESS_HUFF = 0x0004
    ntdll = ctypes.windll.ntdll
    status = ntdll.RtlDecompressBufferEx(
        4,  # COMPRESSION_FORMAT_XPRESS_HUFF
        buf, uncompressed_size,
        (ctypes.c_char * (len(data)-8)).from_buffer_copy(data[8:]),
        len(data) - 8,
        ctypes.byref(final_size),
        workspace
    )
    if status != 0:
        return None
    return buf.raw[:final_size.value]

def parse_prefetch_raw(data, filename):
    """Parse decompressed prefetch (version 30 = Win10)."""
    info = {"file": filename}
    try:
        ver = struct.unpack_from("<I", data, 0)[0]
        info["pf_version"] = ver
        # File name at offset 16, 60 wchars
        exe_name = data[16:76].decode("utf-16-le", errors="ignore").rstrip("\x00")
        info["exe_name"] = exe_name
        # Run count at offset 208 (v30)
        run_count = struct.unpack_from("<I", data, 208)[0]
        info["run_count"] = run_count
        # Last run times: 8 timestamps at offset 128 (v30), each 8 bytes FILETIME
        last_runs = []
        for i in range(8):
            raw_ts = struct.unpack_from("<Q", data, 128 + i * 8)[0]
            if raw_ts:
                unix_ts = (raw_ts - 116444736000000000) / 10000000
                if 0 < unix_ts < 2e9:
                    last_runs.append(datetime.datetime.utcfromtimestamp(unix_ts).strftime("%Y-%m-%d %H:%M:%S UTC"))
        info["last_run_times"] = last_runs
        # File references section header at offset 224 (v30)
        # Strings section: find UTF-16 paths
        strs = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data)
        paths = []
        for s in strs:
            decoded = s.decode("utf-16-le", errors="ignore").strip()
            if "\\" in decoded and len(decoded) > 8:
                paths.append(decoded)
        info["referenced_paths"] = list(dict.fromkeys(paths))[:25]
    except Exception as e:
        info["error"] = str(e)
    return info

print("=" * 70)
print("PREFETCH ANALYSIS — Windows 10 MAM Decompressed")
print("=" * 70)

pf_files = sorted([f for f in os.listdir(BASE) if f.endswith(".pf")])
for pf in pf_files:
    raw = open(os.path.join(BASE, pf), "rb").read()
    decompressed = decompress_mam(raw)
    if decompressed is None:
        print(f"\n[{pf}] — decompression FAILED")
        continue
    info = parse_prefetch_raw(decompressed, pf)
    print(f"\n{'-'*60}")
    print(f"  File       : {info['file']}")
    print(f"  EXE Name   : {info.get('exe_name', 'N/A')}")
    print(f"  PF Version : {info.get('pf_version')} (30=Win10)")
    print(f"  Run Count  : {info.get('run_count', 'N/A')}")
    lrt = info.get("last_run_times", [])
    if lrt:
        print(f"  Last Run   : {lrt[0]}")
        for t in lrt[1:]:
            print(f"             : {t}")
    else:
        print("  Last Run   : N/A")
    paths = info.get("referenced_paths", [])
    if paths:
        print("  Referenced paths:")
        for p in paths:
            print(f"    {p}")
