"""prompts.py — LLM prompt builders for each dashboard preset."""

import json


def build_security_prompt(data: dict) -> str:
    return f"""You are a network security analyst reviewing a HOME network (not enterprise).

Analyze the 24-hour security summary below.

ROGUE AP ANALYSIS RULES — read carefully before flagging:
- A home network in a residential area will routinely detect 50-150+ rogue APs — these are
  neighbor routers, mesh nodes, IoT devices. High counts alone are NOT suspicious.
- Only flag rogue APs as HIGH if: (a) an SSID matches one of the homeowner's own network
  names (evil twin), OR (b) RSSI is stronger than -60 dBm (physically very close, not a
  neighbor), OR (c) is_adhoc is true AND signal is strong.
- If evil_twin_candidates list is empty, rogue APs are almost certainly neighbor noise — rate LOW.
- Do NOT flag rogue AP count as HIGH purely based on volume in a residential context.
- Rogue APs with no SSID (empty string) are typically probe responses — not threats.

WAN / BROADBAND ANALYSIS:
- WAN data is provided where available from the UniFi health endpoint.
- Do not request ISP-specific data — it is not available via the local API.
- Comment on latency or unusual tx/rx ratios if the data warrants it.

GENERAL INSTRUCTIONS:
- Look for: port scanning, new unrecognized devices, unusual outbound patterns,
  slow beaconing, brute-force attempts, multi-event compromise chains.
- Rate each finding: HIGH / MED / LOW
- Reference specific IPs, hostnames, MACs, SSIDs, or RSSI values from the data
- If nothing is genuinely suspicious, say so clearly — do not invent concerns
- Bullet points, concise
- End with a single-line overall verdict

DATA:
{json.dumps(data, indent=2)}"""


def build_health_prompt(data: dict) -> str:
    return f"""You are a network infrastructure analyst reviewing home network device health.

Analyze the device health summary below. Look for:
- Devices with high CPU or memory usage (flag anything above 80%)
- Devices that are offline or in an error/isolated state
- Abnormally long uptimes suggesting missed reboots or stuck processes
- Any device whose health metrics stand out as needing attention

IMPORTANT: Do NOT comment on whether firmware versions are current or outdated.
You have no internet access and your training data is stale — you cannot reliably
know what the latest firmware version is. Only flag firmware if multiple devices
show significantly different versions from each other, suggesting inconsistent patching.

Instructions:
- Rate each finding: HIGH / MED / LOW
- Reference specific device names, IPs, and metrics where relevant
- If everything looks healthy, say so clearly
- Bullet points, concise
- End with a single-line overall verdict

DATA:
{json.dumps(data, indent=2)}"""


def build_diagnostics_prompt(data: dict) -> str:
    return f"""You are validating the DATA PIPELINE of a home-network dashboard — NOT hunting for security threats.

Your job is to sanity-check that the data pulled from the UniFi controller looks complete and internally consistent, so the user can trust the security/health/performance analyses. Do NOT perform a security review here.

CONTEXT — UniFi Network API version churn (read before judging):
- The data includes `controller_version` (the UniFi Network app version) and `events_endpoint_ok` (whether ANY event-fetch path returned data). Always state the controller_version in your assessment.
- The EVENTS activity-log endpoint (stat/event / list/event) is REMOVED or RENAMED across UniFi Network versions — notably the 10.x line. If `events_endpoint_ok` is false, the events feed is UNAVAILABLE on this version: report it as a KNOWN LIMITATION / DEGRADED tied to the version, NOT as evidence of a broken pipeline.
- CLIENTS and ALARMS are the CORE feeds. If client_count is sane AND alarms are present, the pipeline is fundamentally HEALTHY even with events unavailable. Events are the (noisier, less security-relevant) activity log; alarms carry the threats/blocks/IPS signal.
- alarm_count_24h = 0 while the alarm endpoint itself works (alarms exist outside the 24h window) means a quiet 24h or a time-filter window — NOT a broken fetch.

Check for:
- Missing or zero/empty fields where data is expected. A zero client_count, or empty sample_client, points to a broken fetch path. (EXCEPT events — see CONTEXT: a zero/empty events feed is expected when events_endpoint_ok is false, and is a version limitation, not a break.)
- event_time_range: is the window plausible? A 'newest' timestamp in the future, or one that is hours/days stale, suggests events aren't updating.
- client_count vs the length of clients_raw — do they agree? A mismatch suggests truncation or a paging bug.
- clients_raw rows missing hostname/ip/mac or holding obviously malformed values.
- sample_alarm / sample_event / sample_client: do the field shapes look like real UniFi objects, or are they null/empty (endpoint returning nothing)?

Instructions:
- Frame every finding as a DATA QUALITY status: OK / SUSPECT / BROKEN — not a security severity.
- Point to the specific field or count that looks wrong and say what it implies about the fetch path.
- If the data looks complete and consistent, say so plainly — do not invent problems.
- Bullet points, concise.
- Overall verdict: OK / DEGRADED / BROKEN, and name the controller_version. Use BROKEN ONLY if the CORE feeds (clients AND alarms) are failing. If clients and alarms are healthy and only the events activity-log is unavailable, the verdict is DEGRADED (events endpoint moved in this Network version) — NOT BROKEN.

DATA:
{json.dumps(data, indent=2)}"""


def build_trends_prompt(data: dict) -> str:
    return f"""You are analyzing BANDWIDTH TRENDS for a home network, using snapshots collected across separate dashboard runs over time.

Each data point is the bandwidth a single client consumed in the interval between two consecutive snapshots: rx_mb = download, tx_mb = upload. The goal is to separate benign, stable usage from patterns that are persistent or getting worse run over run.

DATA SANITY — DO THIS FIRST, before any trend call:
- These intervals come from differencing CUMULATIVE UniFi counters. A counter reset/rollover, a missed snapshot, or a client re-associating produces a PHANTOM interval — e.g. a single interval showing tens or hundreds of GB, or any value larger than the link could physically carry in that interval. Treat such values as MEASUREMENT ARTIFACTS / data-quality noise: exclude them from the trend and name them as suspected counter artifacts. NEVER report a phantom interval as real traffic or as exfiltration. The classic failure is reading a cumulative odometer as a per-interval delta.

KNOWN HOST ROLES (traffic here is internal/trusted, NOT exfiltration):
- 192.168.1.111 (neo7-dtp) is a Hyper-V HOST. Its traffic is overwhelmingly the guest VM's egress: inbound = Docker image pulls; outbound = the local AI agent shipping prompts to another LAN machine for inference, plus DB-snapshot pulls — almost all of it over TAILSCALE to another device ON THIS network. High volume, including upload-heavy, on this host is EXPECTED and internal.

INTERNAL vs EXTERNAL is the whole question for "exfiltration":
- Exfiltration = data leaving to an EXTERNAL destination (public internet — NOT LAN, NOT Tailscale). UniFi per-client rx/tx totals do NOT reveal the destination; heavy upload may be entirely LAN/Tailscale.
- If an authoritative WAN-egress figure is provided for a host (e.g. a wan_out_bytes field from the VM's nftables watch), base the exfiltration judgment on THAT, not on total volume.
- If the destination cannot be determined, you may NOT escalate to WORSENING on volume alone — say INCONCLUSIVE / destination-unconfirmed and state what data would settle it.

Analyze:
- Direction: are rx and tx trending UP, DOWN, or STABLE across the series (excluding phantom intervals)? Quantify roughly (recent vs earlier).
- Persistence: one-off spike (usually benign) vs sustained across many REAL snapshots.
- Upload emphasis: sustained/rising TX to an EXTERNAL destination can indicate cloud sync, backups, or exfiltration — but TX to LAN/Tailscale, or from a known host role above, is normal. Cameras and backup tools also upload heavily.
- Anomalies: GENUINE step-changes (not counter artifacts), suspiciously regular EXTERNAL beaconing, or growth that compounds across runs.

Context:
- This is a HOME network. iCloud/OneDrive/Dropbox sync, Windows Update delivery, and camera uploads are all normal.
- A short series (few intervals) means LOW confidence — say so rather than over-reading noise.

Instructions:
- Classify the trend: BENIGN / WATCH / WORSENING — or INCONCLUSIVE when the data is phantom-heavy or the destination is unconfirmed.
- "Busy internal host" explains VOLUME only — it NEVER excuses external egress to an unknown destination. Still flag genuine sustained EXTERNAL upload or a NEW external destination regardless of how busy a host is.
- Reference actual MB figures and timestamps; name which intervals you treated as artifacts.
- If there isn't enough REAL history to judge, say so and state roughly how many more snapshots would help.
- Bullet points, concise.
- End with a single-line overall verdict.

DATA:
{json.dumps(data, indent=2)}"""


def build_performance_prompt(data: dict) -> str:
    return f"""You are a network performance analyst reviewing a home broadband connection and LAN.

Analyze the performance summary below. Look for:
- WAN link issues: high latency, packet loss, or unexpectedly low throughput
- Clients consuming disproportionate bandwidth compared to others
- Large upload volumes to EXTERNAL destinations (public internet — NOT LAN, NOT Tailscale) that could indicate unexpected cloud sync, backup, or exfiltration. Upload to LAN/Tailscale is internal and is NOT exfiltration; per-client totals do not reveal destination, so do not infer exfiltration from volume alone.
- Any client whose traffic pattern stands out as anomalous for a home network
- Overall network health and whether any intervention would help

IMPORTANT CONTEXT:
- This is a HOME network. Cloud sync (iCloud, Dropbox, OneDrive), Windows Update
  delivery optimization, and security camera uploads are all normal upload sources.
- Infrastructure IPs (cable modem, router/gateway, switches) appear in the client
  list — their traffic is network overhead, not user activity. Do not flag them.
- 192.168.1.111 (neo7-dtp) is a Hyper-V HOST; its traffic is mostly the guest VM's
  egress to another LAN machine over Tailscale (internal). High/upload-heavy volume
  here is expected and internal — not exfiltration.
- A single interval showing tens/hundreds of GB is almost certainly a cumulative-
  counter artifact, not real traffic — treat as data quality, not a security event.
- Security cameras are expected to have high TX (upload) — only flag if one camera
  is dramatically inconsistent vs others on the same network.
- Do NOT request ISP or WAN provider information — unavailable via the local API.

Instructions:
- Rate each finding: HIGH / MED / LOW
- Reference specific client names, IPs, and actual MB figures where relevant
- If performance looks normal for a home network, say so clearly
- Bullet points, concise
- End with a single-line overall verdict

DATA:
{json.dumps(data, indent=2)}"""
