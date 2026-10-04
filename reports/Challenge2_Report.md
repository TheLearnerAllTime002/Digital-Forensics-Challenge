# Challenge 2 — Log Analysis Report: Who is Compromised and How?

---

## Scope

Analysis date: 04 October 2026

---

## Executive Summary

Organisation X runs 248 Linux desktops across 19 units. I was given two weeks of agent logs covering web activity,
antivirus scans, quarantine records, web-filter blocks, and USB events. After working through all three files, the
picture is clear: the organisation has a multi-layered compromise. There are endpoints with confirmed malware
detections (AV hits + quarantined malicious files), endpoints actively beaconing to a suspicious C2 domain
(`*.svc-d93955.example`), endpoints that had a USB mass-storage device plugged in outside business hours, and a
large number of machines contacting raw IP addresses and suspicious external destinations at unusual volumes.

The most critical finding is a cluster of endpoints beaconing to subdomains of `svc-d93955.example` at very
regular intervals (every ~30 minutes), which is a textbook C2 heartbeat pattern. These endpoints also have
quarantined malicious files and web-filter blocks for IP-lookup services (`api.ipify.org`, `ip-api.com`), which
is consistent with a RAT performing initial reconnaissance.

---

## Tools Used

| Tool / Method              | Purpose                                                        |
|----------------------------|----------------------------------------------------------------|
| Python 3 (csv, re, math)   | Parsing all three log files, counting, filtering               |
| Custom beaconing detector  | Coefficient-of-variation analysis on per-endpoint/per-dest gaps|
| Shannon entropy / Counter  | Identifying high-volume raw-IP contacts                        |
| Pillow (PIL)               | Saving annotated screenshots as PNG                            |
| Passive threat intel       | Domain/IP reputation (recommended for follow-up)              |

---

## Methodology

### Analysis

I processed the three log files in sequence, building up a picture of each endpoint's behaviour.

**endpoint_security.csv (23,540 rows)**
I split this into three streams: `av_scan` (AV detections), `quarantine` (malicious file records), and
`web_block` (web-filter blocks). For quarantine records I deduplicated by (endpoint, SHA256) because the service
re-lists the entire quarantine folder on every scan — the same file can appear dozens of times. I only counted
`FileType: Malicious` records as confirmed detections; files quarantined by extension alone were ignored.

**web_activity.csv (2,812,118 rows)**
I streamed this file in a single pass (too large to load into RAM). For each row I tracked:
- Total destination count per endpoint
- Raw IP address contacts (no hostname, just a dotted-quad)
- Contacts matching suspicious TLDs or known-bad domain patterns (.ru, .cn, .tk, .xyz, .top, .pw, .cc, .su,
  ngrok.io, duckdns.org, no-ip variants, portmap.io, pastebin.com, etc.)
- Timestamps per (endpoint, destination) pair for beaconing analysis

I whitelisted known-good infrastructure (Google, Microsoft, Windows Update, Apple, Akamai, Cloudflare, DigiCert,
Office 365, etc.) to reduce noise.

**Beaconing detection**
For every (endpoint, destination) pair with ≥8 contacts, I computed the inter-contact gaps, filtered out gaps
over 24 hours, then calculated the mean gap and coefficient of variation (CV = stddev / mean). A CV below 0.15
with a mean gap between 30 seconds and 2 hours is a strong indicator of automated, timer-driven beaconing. I
sorted results by CV ascending (most regular first).

**usb_events.csv (8 rows)**
Small enough to read in full. I noted device class, vendor:product ID, and whether the timing was suspicious.

### Findings

---

#### Finding 1 — C2 Beaconing to `*.svc-d93955.example`

This is the most serious finding. Four endpoints are making highly regular, automated contacts to subdomains of
`svc-d93955.example`. The subdomain names are random-looking (n4f74, n7de7, n8b1a, n9f9c, nf7f4), which is
consistent with domain-generation algorithm (DGA) or per-implant unique C2 subdomains.

| Endpoint   | Host       | Unit         | C2 Subdomain                  | Interval | Count | CV    |
|------------|------------|--------------|-------------------------------|----------|-------|-------|
| EPMDU6L5   | host-b05e  | unit-oscar   | n4f74.svc-d93955.example      | 3766s    | 11    | 0.082 |
| EPVEKWWM   | host-aa1b  | unit-papa    | n7de7.svc-d93955.example      | 1833s    | 10    | 0.091 |
| EPIZFLLQ   | host-d056  | unit-delta   | nf7f4.svc-d93955.example      | 1827s    | 13    | 0.091 |
| EPIZFLLQ   | host-d056  | unit-delta   | n9f9c.svc-d93955.example      | 1889s    | 13    | 0.091 |
| EPTDOI6T   | host-4a53  | unit-india   | n8b1a.svc-d93955.example      | 3707s    | 11    | 0.104 |

A CV of 0.08–0.10 means the gaps between contacts vary by less than 10% — this is machine-generated traffic, not
human browsing. The intervals of ~30 minutes (1800s) and ~60 minutes (3600s) are classic RAT heartbeat timings.

EPMDU6L5 also has a quarantined malicious file (SHA256: 5dd59e8309b4be90aad5...) and blocked `api.ipify.org`
(a public IP-lookup service — malware uses this to discover the victim's external IP before reporting to C2).

EPIZFLLQ has two different C2 subdomains, suggesting either two implants or a failover mechanism.

---

#### Finding 2 — Confirmed Malware Detections (AV + Quarantine)

The following endpoints have confirmed malicious files in quarantine (`FileType: Malicious`):

**EP4YIFHV** (host-a616, unit-lima) — 20 unique malicious files quarantined. This is the most heavily infected
machine in the estate. The sheer number of unique SHA256 hashes suggests either a dropper that generates new
variants, or a machine that has been used to stage/test multiple malware samples.

**EPMVZYZO** (host-ba01, unit-quebec) — 4 unique malicious files. Also blocked `www.googleapis.com` (unusual
for a Linux desktop — may indicate a malware component trying to use Google APIs for C2).

**EPVSWBNA** (host-e103, unit-delta) — 3 unique malicious files.

**EPPGWIOF** (host-8e2e, unit-india) — 2 unique malicious files with distinct SHA256 hashes.

**EPSJWX5J** (host-0982, unit-golf) — 1 malicious file (SHA256: d831cf990c1445b507ef...).

**EPGSQVEB** (host-9a4f, unit-bravo) — 1 malicious file (SHA256: 404ee57531c33156d621...).

**EPVC2P55** (host-aca0, unit-alpha) — 1 malicious file (SHA256: 925b63ce20d94bc4a0d9...).

**EPQKOBYG** (host-d29a, unit-romeo) — 1 malicious file (SHA256: f475a7462dd85932ad7f...).

**EPSES7ZK** (host-4b8a, unit-papa) — 1 malicious file (SHA256: f0c485571570100898f2...).

**EPNPX6VY** (host-6ef6, unit-juliett) — 1 malicious file (SHA256: bde5bba12f076659ab19...).

**EPWZ7L6L** (host-a61e, unit-sierra) — 1 malicious file (SHA256: dd294df9886197bd6880...).

**EPZRAPEL** (host-d14b, unit-foxtrot) — 1 malicious file (SHA256: 2e4dff1672bbabba74a0...).

Multiple endpoints share the same SHA256 hash `5e10b3490160cca0fc87...`:
EPOC6Y4R, EPMQTKSL, EPLDM6PE, EPJYEC7F, EPR4BEDS, EPFQSCDV, EPC2L3UH, EPDRB236, EP2SJ6NE, EPF4AJCM, EPEPF4AJCM.
This is the same malware binary spreading across units — a lateral movement or shared infection source.

Similarly, SHA256 `93ffd792f92437a850e4...` appears on EP2SJ6NE and EPF4AJCM (unit-bravo and unit-golf).

---

#### Finding 3 — Web Filter Blocks: IP Lookup Services

Several endpoints were blocked trying to reach `api.ipify.org` and `ip-api.com`. These are public services that
return the caller's external IP address. Legitimate software rarely needs these; malware uses them during the
initial infection phase to report the victim's IP to the attacker.

Endpoints blocked on IP-lookup services:
- EPMDU6L5 (host-b05e, unit-oscar) — `api.ipify.org` ← also beaconing to C2
- EP2EVFKU (host-ecfb, unit-sierra) — `api.ipify.org`
- EPIXXNDT (host-e032, unit-kilo) — `api.ipify.org`
- EPO7DU5Z (host-cfaa, unit-foxtrot) — `api.ipify.org`
- EPTX4FCZ (host-b44e, unit-foxtrot) — `api.ipify.org`
- EPNXD2NI (host-bfb4, unit-quebec) — `api.ipify.org`
- EPN6LGXP (host-9cd3, unit-foxtrot) — `ip-api.com`

---

#### Finding 4 — Web Filter Blocks: `sync.aralego.com`

`sync.aralego.com` is a known adware/tracking domain. Multiple endpoints were blocked on it:
EP2C4ZH5, EP65VPYQ, EP6RMQC5, EPAJI3E5, EPBZVWPM, EPEPIZFLLQ, EPKTB5NE, EPMQTKSL, EPMY53PL, EPN6LGXP,
EPO7DU5Z, EPNXD2NI, EPR6HUBY, EPT3KTUL, EPTX4FCZ, EPG67237.
While this alone is not a compromise indicator, combined with other signals it suggests adware or a browser
hijacker is present on these machines.

---

#### Finding 5 — USB Mass Storage Device (Suspicious)

**EPD24DBC** (host-7394, unit-foxtrot) had a generic USB mass-storage device plugged in on 22-09-2026 at
18:23 (6:23 PM local time). The device has vendor:product ID `abcd:1234` — this is a placeholder/fake ID,
not a real manufacturer code. Legitimate USB drives have real vendor IDs. This is consistent with a custom-built
or modified USB device, potentially used for data exfiltration or malware delivery.

The received_time shows the log was uploaded the next morning (23-09-2026 09:05), suggesting the endpoint was
offline or the agent was delayed — which could indicate the machine was taken offline after the USB was used.

EP7FZ2XY (host-9764, unit-quebec) had a Logitech USB mouse plugged in (046d:c077) — this is a legitimate
peripheral and not suspicious.

---

#### Finding 6 — High-Volume Raw IP Contacts

Several endpoints are contacting large numbers of raw IP addresses (no hostname resolution). While some of this
is normal (CDN IPs, etc.), the volume on certain endpoints is anomalous. The top offenders by raw-IP contact
count are worth investigating further, particularly those that also have other compromise indicators.

---

#### Finding 7 — `yandex.ru` Web Block

Three endpoints (EP65VPYQ, EPPWQND4, EPTX4FCZ) were blocked trying to reach `yandex.ru` (Russian search
engine). In an Indian organisation context, this is unusual and may indicate malware with Russian-origin C2
infrastructure, or a user attempting to access a geo-blocked service.

---

### Outcome

**Confirmed compromised (C2 beaconing + malware):**
- EPMDU6L5 (host-b05e, unit-oscar) — beaconing + malicious quarantine + IP lookup
- EPVEKWWM (host-aa1b, unit-papa) — beaconing to C2
- EPIZFLLQ (host-d056, unit-delta) — beaconing to two C2 subdomains + web blocks
- EPTDOI6T (host-4a53, unit-india) — beaconing to C2 + web blocks

**Confirmed compromised (malware detected/quarantined):**
- EP4YIFHV (host-a616, unit-lima) — 20 unique malicious files
- EPMVZYZO (host-ba01, unit-quebec) — 4 malicious files
- EPVSWBNA (host-e103, unit-delta) — 3 malicious files
- EPPGWIOF (host-8e2e, unit-india) — 2 malicious files
- EPSJWX5J, EPGSQVEB, EPVC2P55, EPQKOBYG, EPSES7ZK, EPNPX6VY, EPWZ7L6L, EPZRAPEL — 1 malicious file each

**Shared malware hash (lateral spread):**
- 11 endpoints share SHA256 `5e10b3490160cca0fc87...` across units bravo, charlie, delta, foxtrot, golf,
  juliett, romeo — indicating the same malware binary has spread across organisational units.

**Suspicious USB activity:**
- EPD24DBC (host-7394, unit-foxtrot) — fake-ID USB mass storage device plugged in after hours.

**Suspicious behaviour (IP lookup blocks, high raw-IP volume):**
- EP2EVFKU, EPIXXNDT, EPO7DU5Z, EPTX4FCZ, EPNXD2NI, EPN6LGXP — IP-lookup service blocks

---

## Step-by-Step Process with Screenshots

### Step 1 — Understand the Data

Read the README.md to understand the schema. Three files, same column layout. Key columns: `endpoint_id`,
`endpoint_name`, `unit`, `log_type`, `event_time`, `received_time`, `message`.

### Step 2 — Parse endpoint_security.csv

Streamed through 23,540 rows. Split by log_type:
- `av_scan`: extracted lines containing "FOUND" for confirmed detections
- `quarantine`: extracted records with `FileType: Malicious`, deduplicated by (ep, SHA256)
- `web_block`: collected all blocked destinations per endpoint

Screenshots: [01_av_detections.png](../docs/evidence/challenge2/01_av_detections.png), [02_quarantine_malicious.png](../docs/evidence/challenge2/02_quarantine_malicious.png), [03_web_blocks.png](../docs/evidence/challenge2/03_web_blocks.png)

### Step 3 — Parse web_activity.csv

Streamed 2.8M rows. Built per-endpoint counters for total destinations, raw IP contacts, and suspicious
domain contacts. Applied a whitelist to remove known-good infrastructure noise.

Screenshots: [04_suspicious_destinations.png](../docs/evidence/challenge2/04_suspicious_destinations.png), [05_raw_ip_contacts.png](../docs/evidence/challenge2/05_raw_ip_contacts.png)

### Step 4 — Beaconing Detection

Second pass through web_activity.csv, collecting timestamps per (endpoint, destination) pair. For pairs with
≥8 contacts, computed mean inter-contact gap and coefficient of variation. CV < 0.15 with gap 30s–2h flagged
as beaconing. Sorted by CV ascending to surface the most regular (most suspicious) patterns first.

Key finding: `*.svc-d93955.example` subdomains with CV ~0.09 — extremely regular, machine-generated traffic.

Screenshot: [06_beaconing.png](../docs/evidence/challenge2/06_beaconing.png)

### Step 5 — USB Events

Read all 8 rows of usb_events.csv. Identified one suspicious mass-storage device with fake vendor ID `abcd:1234`
on EPD24DBC after business hours.

Screenshot: [07_usb_events.png](../docs/evidence/challenge2/07_usb_events.png)

### Step 6 — Compile Compromised Endpoint Summary

Aggregated all signals (AV, quarantine, web blocks, beaconing, suspicious domains) per endpoint into a single
summary table.

Screenshot: [08_compromised_summary.png](../docs/evidence/challenge2/08_compromised_summary.png)

---

## Remediation Recommendations

1. **Immediately isolate** EPMDU6L5, EPVEKWWM, EPIZFLLQ, EPTDOI6T — these are actively beaconing to C2.
   Disconnect from the network now.

2. **Block `*.svc-d93955.example`** at the DNS resolver and perimeter firewall. Also block `api.ipify.org`
   and `ip-api.com` for all endpoints — no legitimate business application needs these.

3. **Reimage** all endpoints with confirmed malicious quarantine files. Do not attempt to clean in place.

4. **Investigate the shared hash** `5e10b3490160cca0fc87...` — submit to VirusTotal, identify the malware
   family, and hunt for it across all 248 endpoints using the AV agent.

5. **Investigate EPD24DBC** (host-7394, unit-foxtrot) — the USB device with fake vendor ID `abcd:1234` is
   highly suspicious. Check what files were accessed or copied during the 18:23 session on 22-09-2026.

6. **Enforce USB device control** — block all mass-storage USB devices organisation-wide via endpoint policy.
   Only whitelisted, IT-issued devices should be permitted.

7. **Review `yandex.ru` blocks** on EP65VPYQ, EPPWQND4, EPTX4FCZ — determine if this is user behaviour or
   malware C2 fallback.

8. **Audit all endpoints** in unit-foxtrot, unit-delta, unit-india, unit-papa, unit-oscar — these units have
   the highest concentration of compromise indicators.

9. **Check clock integrity** — some endpoints show significant skew between `event_time` and `received_time`.
   Endpoints with manipulated clocks may be attempting to obscure the true timeline of infection.

10. **Deploy network-level detection** for DGA-style subdomains (random-prefix + fixed parent domain pattern)
    at the DNS layer to catch future C2 infrastructure of this type.

---

## IOC Summary Table

| Indicator                          | Type         | Notes                                              |
|------------------------------------|--------------|----------------------------------------------------|
| *.svc-d93955.example               | C2 Domain    | Beaconing target, DGA-style subdomains             |
| n4f74.svc-d93955.example           | C2 Domain    | EPMDU6L5 beacon, ~62 min interval                  |
| n7de7.svc-d93955.example           | C2 Domain    | EPVEKWWM beacon, ~30 min interval                  |
| nf7f4.svc-d93955.example           | C2 Domain    | EPIZFLLQ beacon, ~30 min interval                  |
| n9f9c.svc-d93955.example           | C2 Domain    | EPIZFLLQ beacon, ~31 min interval                  |
| n8b1a.svc-d93955.example           | C2 Domain    | EPTDOI6T beacon, ~62 min interval                  |
| api.ipify.org                      | Domain       | IP-lookup service, used by malware for recon       |
| ip-api.com                         | Domain       | IP-lookup service, used by malware for recon       |
| sync.aralego.com                   | Domain       | Adware/tracking domain                             |
| abcd:1234                          | USB VID:PID  | Fake/custom USB device on EPD24DBC                 |
| 5e10b3490160cca0fc87...            | SHA256       | Shared malware hash across 11 endpoints            |
| 5dd59e8309b4be90aad5...            | SHA256       | Malicious file on EPMDU6L5 (C2 beacon host)        |
| EPMDU6L5 / host-b05e               | Endpoint     | C2 beacon + malware + IP lookup — highest priority |
| EPVEKWWM / host-aa1b               | Endpoint     | C2 beacon                                          |
| EPIZFLLQ / host-d056               | Endpoint     | C2 beacon (two subdomains)                         |
| EPTDOI6T / host-4a53               | Endpoint     | C2 beacon                                          |
| EP4YIFHV / host-a616               | Endpoint     | 20 unique malicious files — likely staging machine |
| EPD24DBC / host-7394               | Endpoint     | Suspicious USB mass-storage after hours            |
