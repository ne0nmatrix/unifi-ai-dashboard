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


def build_performance_prompt(data: dict) -> str:
    return f"""You are a network performance analyst reviewing a home broadband connection and LAN.

Analyze the performance summary below. Look for:
- WAN link issues: high latency, packet loss, or unexpectedly low throughput
- Clients consuming disproportionate bandwidth compared to others
- Large upload volumes that could indicate unexpected cloud sync, backup, or exfiltration
- Any client whose traffic pattern stands out as anomalous for a home network
- Overall network health and whether any intervention would help

IMPORTANT CONTEXT:
- This is a HOME network. Cloud sync (iCloud, Dropbox, OneDrive), Windows Update
  delivery optimization, and security camera uploads are all normal upload sources.
- Infrastructure IPs (cable modem, router/gateway, switches) appear in the client
  list — their traffic is network overhead, not user activity. Do not flag them.
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
