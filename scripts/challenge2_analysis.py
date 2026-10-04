"""
Challenge 2 - Log Analysis: Who is compromised and how?
Covers: AV detections, quarantine (Malicious), web_block, suspicious domains,
        USB events, beaconing / C2 patterns, clock-skew anomalies.
"""

import csv, re, collections, math, os, sys
from datetime import datetime

DATA   = os.environ.get(
    "CHALLENGE2_DATA",
    os.path.join(os.path.dirname(__file__), "..", "data", "challenge2"),
)
OUTDIR = os.environ.get(
    "CHALLENGE2_OUTPUT",
    os.path.join(os.path.dirname(__file__), "..", "data", "generated", "challenge2"),
)
os.makedirs(OUTDIR, exist_ok=True)

SEC_FILE = DATA + "\\endpoint_security.csv"
WEB_FILE = DATA + "\\web_activity.csv"
USB_FILE = DATA + "\\usb_events.csv"

def parse_dt(s):
    for fmt in ("%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M"):
        try: return datetime.strptime(s.strip(), fmt)
        except: pass
    return None

# ─────────────────────────────────────────────────────────────────────────────
# PASS 1 – endpoint_security.csv
# ─────────────────────────────────────────────────────────────────────────────
print("Loading endpoint_security.csv ...")

av_detections   = []   # {ep, host, unit, sig, path, time}
quarantine_mal  = []   # FileType: Malicious
web_blocks      = collections.Counter()   # (ep,host,unit,dest) -> count
web_block_rows  = []
av_summary      = {}   # ep -> last scan summary line
infected_eps    = set()

with open(SEC_FILE, encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        ep   = row["endpoint_id"]
        host = row["endpoint_name"]
        unit = row["unit"]
        lt   = row["log_type"]
        msg  = row["message"]
        et   = row["event_time"]

        if lt == "av_scan":
            if "Infected file is" in msg and "FOUND" in msg:
                m = re.search(r"Infected file is (.+?):\s*(.+?)\s*FOUND", msg)
                if m:
                    av_detections.append({
                        "ep": ep, "host": host, "unit": unit,
                        "path": m.group(1).strip(),
                        "sig":  m.group(2).strip(),
                        "time": et
                    })
                    infected_eps.add(ep)
            if "Knownviruses" in msg:
                av_summary[ep] = msg

        elif lt == "quarantine":
            if "FileType: Malicious" in msg:
                m = re.search(r"File:\s*(\S+)\s*\|.*?Quarantined At:\s*([^|]+)\|.*?SHA256:\s*(\S+)", msg)
                quarantine_mal.append({
                    "ep": ep, "host": host, "unit": unit,
                    "file":   m.group(1) if m else "?",
                    "qtime":  m.group(2).strip() if m else "?",
                    "sha256": m.group(3) if m else "?",
                    "msg":    msg[:120]
                })
                infected_eps.add(ep)

        elif lt == "web_block":
            web_blocks[(ep, host, unit, msg.strip())] += 1
            web_block_rows.append({
                "ep": ep, "host": host, "unit": unit,
                "dest": msg.strip(), "time": et
            })
            infected_eps.add(ep)

# ─────────────────────────────────────────────────────────────────────────────
# PASS 2 – web_activity.csv  (2.8M rows – stream, don't load all into RAM)
# ─────────────────────────────────────────────────────────────────────────────
print("Loading web_activity.csv (2.8M rows) ...")

# Known-bad TLD / domain patterns
SUSPICIOUS_PATTERNS = [
    r"\.onion$", r"\.ru$", r"\.cn$", r"\.tk$", r"\.top$", r"\.xyz$",
    r"\.pw$", r"\.cc$", r"\.su$", r"\.bit$",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",   # raw IPs
    r"pastebin\.com", r"ngrok\.io", r"duckdns\.org",
    r"no-ip\.", r"ddns\.net", r"hopto\.org", r"servebeer\.com",
    r"portmap\.io", r"pagekite\.me",
]
SUSPICIOUS_RE = re.compile("|".join(SUSPICIOUS_PATTERNS), re.I)

# Legitimate noise to skip
WHITELIST = re.compile(
    r"(google|microsoft|windows|apple|amazon|akamai|cloudflare|digicert"
    r"|ocsp|crl|windowsupdate|office365|office|msftncsi|gstatic"
    r"|googleapis|youtube|linkedin|github|ubuntu|debian|\.local$"
    r"|\.lan$|\.bbrouter$|\.dlink$|\.hgu_lan$|localhost)", re.I)

ep_dest_count   = collections.Counter()   # ep -> total destinations
ep_raw_ip_count = collections.Counter()   # ep -> raw IP contacts
ep_suspicious   = collections.defaultdict(set)  # ep -> suspicious domains
ep_hosts        = {}   # ep -> (host, unit)
ep_times        = collections.defaultdict(list) # ep -> list of event datetimes (sample)
ep_unique_dest  = collections.defaultdict(set)  # ep -> unique destinations

raw_ip_re = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

with open(WEB_FILE, encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        ep   = row["endpoint_id"]
        host = row["endpoint_name"]
        unit = row["unit"]
        dest = row["message"].strip().lower()
        et   = row["event_time"]

        ep_hosts[ep] = (host, unit)
        ep_dest_count[ep] += 1
        ep_unique_dest[ep].add(dest)

        if raw_ip_re.match(dest):
            ep_raw_ip_count[ep] += 1

        if SUSPICIOUS_RE.search(dest) and not WHITELIST.search(dest):
            ep_suspicious[ep].add(dest)

        # sample timestamps for beaconing detection (keep first 5000 per ep)
        if len(ep_times[ep]) < 5000:
            dt = parse_dt(et)
            if dt:
                ep_times[ep].append(dt)

# ─────────────────────────────────────────────────────────────────────────────
# PASS 3 – beaconing detection (regular interval contacts to same dest)
# ─────────────────────────────────────────────────────────────────────────────
print("Scanning for beaconing patterns ...")

ep_dest_times = collections.defaultdict(lambda: collections.defaultdict(list))

with open(WEB_FILE, encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        ep   = row["endpoint_id"]
        dest = row["message"].strip().lower()
        et   = row["event_time"]
        if WHITELIST.search(dest): continue
        dt = parse_dt(et)
        if dt:
            ep_dest_times[ep][dest].append(dt)

beaconing_hits = []  # (ep, host, unit, dest, interval_secs, count)
for ep, dest_map in ep_dest_times.items():
    host, unit = ep_hosts.get(ep, ("?","?"))
    for dest, times in dest_map.items():
        if len(times) < 8: continue
        times.sort()
        gaps = [(times[i+1]-times[i]).total_seconds() for i in range(len(times)-1)]
        gaps = [g for g in gaps if 0 < g < 86400]
        if len(gaps) < 5: continue
        mean_gap = sum(gaps)/len(gaps)
        if mean_gap < 10: continue   # too fast = noise
        variance = sum((g-mean_gap)**2 for g in gaps)/len(gaps)
        cv = (variance**0.5) / mean_gap  # coefficient of variation
        if cv < 0.15 and 30 <= mean_gap <= 7200:  # very regular, 30s–2h interval
            beaconing_hits.append({
                "ep": ep, "host": host, "unit": unit,
                "dest": dest, "interval": round(mean_gap),
                "count": len(times), "cv": round(cv, 3)
            })

beaconing_hits.sort(key=lambda x: x["cv"])

# ─────────────────────────────────────────────────────────────────────────────
# PASS 4 – clock skew (event_time vs received_time gap)
# ─────────────────────────────────────────────────────────────────────────────
print("Checking clock skew ...")

clock_skew = {}  # ep -> max skew seconds
with open(SEC_FILE, encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        ep = row["endpoint_id"]
        et = parse_dt(row["event_time"])
        rt = parse_dt(row["received_time"])
        if et and rt:
            skew = abs((rt - et).total_seconds())
            if skew > clock_skew.get(ep, 0):
                clock_skew[ep] = skew

# ─────────────────────────────────────────────────────────────────────────────
# PRINT RESULTS
# ─────────────────────────────────────────────────────────────────────────────

out_sections = {}

# ── S1: AV Detections ────────────────────────────────────────────────────────
lines = ["SECTION 1 — AV DETECTIONS (av_scan: FOUND)", "="*65, ""]
if av_detections:
    by_ep = collections.defaultdict(list)
    for d in av_detections:
        by_ep[d["ep"]].append(d)
    for ep, dets in sorted(by_ep.items()):
        h, u = ep_hosts.get(ep, ("?","?"))
        lines.append(f"[{ep}]  {h}  ({u})")
        for d in dets:
            lines.append(f"  {d['time']}  {d['sig']}")
            lines.append(f"    Path: {d['path']}")
        lines.append("")
else:
    lines.append("  No AV detections found.")
out_sections["1_av"] = lines

# ── S2: Quarantine – Malicious ────────────────────────────────────────────────
lines = ["SECTION 2 — QUARANTINE: FileType=Malicious", "="*65, ""]
seen_sha = set()
unique_q = []
for q in quarantine_mal:
    key = (q["ep"], q["sha256"])
    if key not in seen_sha:
        seen_sha.add(key)
        unique_q.append(q)

by_ep = collections.defaultdict(list)
for q in unique_q:
    by_ep[q["ep"]].append(q)
for ep, qs in sorted(by_ep.items()):
    h, u = ep_hosts.get(ep, ("?","?"))
    lines.append(f"[{ep}]  {h}  ({u})  — {len(qs)} unique malicious file(s)")
    for q in qs:
        lines.append(f"  Quarantined: {q['qtime']}")
        lines.append(f"  SHA256     : {q['sha256']}")
        lines.append(f"  Msg        : {q['msg'][:100]}")
    lines.append("")
out_sections["2_quarantine"] = lines

# ── S3: Web Blocks ────────────────────────────────────────────────────────────
lines = ["SECTION 3 — WEB FILTER BLOCKS (web_block)", "="*65, ""]
by_ep = collections.defaultdict(list)
for row in web_block_rows:
    by_ep[row["ep"]].append(row)
for ep, rows in sorted(by_ep.items()):
    h, u = ep_hosts.get(ep, ("?","?"))
    dests = collections.Counter(r["dest"] for r in rows)
    lines.append(f"[{ep}]  {h}  ({u})  — {len(rows)} block events, {len(dests)} unique destinations")
    for dest, cnt in dests.most_common(10):
        lines.append(f"  {cnt:4d}x  {dest}")
    lines.append("")
out_sections["3_web_blocks"] = lines

# ── S4: Suspicious External Destinations ─────────────────────────────────────
lines = ["SECTION 4 — SUSPICIOUS EXTERNAL DESTINATIONS", "="*65, ""]
sus_eps = [(ep, dests) for ep, dests in ep_suspicious.items() if dests]
sus_eps.sort(key=lambda x: -len(x[1]))
for ep, dests in sus_eps[:20]:
    h, u = ep_hosts.get(ep, ("?","?"))
    lines.append(f"[{ep}]  {h}  ({u})  — {len(dests)} suspicious destinations")
    for d in sorted(dests)[:15]:
        lines.append(f"  {d}")
    lines.append("")
out_sections["4_suspicious_dest"] = lines

# ── S5: Raw IP contacts (top offenders) ──────────────────────────────────────
lines = ["SECTION 5 — RAW IP CONTACTS (top 20 endpoints)", "="*65, ""]
for ep, cnt in ep_raw_ip_count.most_common(20):
    h, u = ep_hosts.get(ep, ("?","?"))
    lines.append(f"  {ep}  {h:12s}  ({u:15s})  raw-IP contacts: {cnt:6d}")
out_sections["5_raw_ips"] = lines

# ── S6: Beaconing ─────────────────────────────────────────────────────────────
lines = ["SECTION 6 — BEACONING DETECTION (regular-interval contacts)", "="*65, ""]
if beaconing_hits:
    for b in beaconing_hits[:30]:
        lines.append(f"[{b['ep']}]  {b['host']}  ({b['unit']})")
        lines.append(f"  Destination : {b['dest']}")
        lines.append(f"  Interval    : {b['interval']}s  |  Count: {b['count']}  |  CV: {b['cv']}")
        lines.append("")
else:
    lines.append("  No strong beaconing patterns detected.")
out_sections["6_beaconing"] = lines

# ── S7: USB Events ────────────────────────────────────────────────────────────
lines = ["SECTION 7 — USB EVENTS", "="*65, ""]
with open(USB_FILE, encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        lines.append(f"[{row['endpoint_id']}]  {row['endpoint_name']}  ({row['unit']})")
        lines.append(f"  Time   : {row['event_time']}")
        lines.append(f"  Device : {row['message'].strip()}")
        lines.append("")
out_sections["7_usb"] = lines

# ── S8: Compromised Endpoint Summary ─────────────────────────────────────────
lines = ["SECTION 8 — COMPROMISED ENDPOINT SUMMARY", "="*65, ""]

# Aggregate all signals
all_compromised = {}
def flag(ep, reason):
    if ep not in all_compromised:
        h, u = ep_hosts.get(ep, ("?","?"))
        all_compromised[ep] = {"host": h, "unit": u, "reasons": []}
    all_compromised[ep]["reasons"].append(reason)

for d in av_detections:
    flag(d["ep"], f"AV detection: {d['sig'][:60]}")
for q in unique_q:
    flag(q["ep"], f"Quarantine Malicious: {q['sha256'][:20]}...")
for row in web_block_rows:
    flag(row["ep"], f"Web block: {row['dest'][:60]}")
for b in beaconing_hits[:10]:
    flag(b["ep"], f"Beaconing -> {b['dest'][:50]} every {b['interval']}s")
for ep, dests in ep_suspicious.items():
    if len(dests) >= 3:
        flag(ep, f"Suspicious domains ({len(dests)}): {', '.join(sorted(dests)[:3])}...")

for ep, info in sorted(all_compromised.items()):
    lines.append(f"[{ep}]  {info['host']}  ({info['unit']})")
    seen = set()
    for r in info["reasons"]:
        if r not in seen:
            lines.append(f"  * {r}")
            seen.add(r)
    lines.append("")
out_sections["8_summary"] = lines

# Print all
for sec_lines in out_sections.values():
    for line in sec_lines:
        print(line)
    print()

# ─────────────────────────────────────────────────────────────────────────────
# SAVE SCREENSHOTS
# ─────────────────────────────────────────────────────────────────────────────
from PIL import Image, ImageDraw, ImageFont

def save_screenshot(title, lines, filename):
    font_size = 13
    try:    font = ImageFont.truetype("cour.ttf", font_size)
    except: font = ImageFont.load_default()
    padding = 18
    line_h  = font_size + 4
    width   = 1000
    height  = padding*2 + len(lines)*line_h + 40
    img  = Image.new("RGB", (width, height), (15, 15, 25))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, width, 34], fill=(30, 50, 90))
    draw.text((10, 8), f"Challenge 2 — Log Analysis  |  {title}", font=font, fill=(180, 220, 255))
    y = 44
    for line in lines:
        color = (255,255,255)
        if line.startswith("SECTION") or line.startswith("==="):
            color = (100,200,255)
        elif line.startswith("[EP") and "]" in line:
            color = (255,200,60)
        elif line.strip().startswith("*"):
            color = (255,100,100)
        elif "Malicious" in line or "FOUND" in line or "beacon" in line.lower():
            color = (255,120,80)
        elif "suspicious" in line.lower() or "block" in line.lower():
            color = (255,180,60)
        elif "usb" in line.lower() or "UDisk" in line:
            color = (180,255,180)
        draw.text((padding, y), line[:120], font=font, fill=color)
        y += line_h
    out_path = os.path.join(OUTDIR, filename)
    img.save(out_path)
    print(f"[SAVED] {out_path}")

titles = {
    "1_av":             ("AV Detections",                  "01_av_detections.png"),
    "2_quarantine":     ("Quarantine Malicious Files",     "02_quarantine_malicious.png"),
    "3_web_blocks":     ("Web Filter Blocks",              "03_web_blocks.png"),
    "4_suspicious_dest":("Suspicious Destinations",        "04_suspicious_destinations.png"),
    "5_raw_ips":        ("Raw IP Contacts",                "05_raw_ip_contacts.png"),
    "6_beaconing":      ("Beaconing Detection",            "06_beaconing.png"),
    "7_usb":            ("USB Events",                     "07_usb_events.png"),
    "8_summary":        ("Compromised Endpoint Summary",   "08_compromised_summary.png"),
}

for key, (title, fname) in titles.items():
    save_screenshot(title, out_sections[key], fname)

print(f"\nAll screenshots saved to: {OUTDIR}")
