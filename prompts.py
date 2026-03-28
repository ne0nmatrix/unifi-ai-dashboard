"""prompts.py — LLM prompt builders for each dashboard preset."""

import json


def build_security_prompt(data: dict) -> str:
    return f"""You are a network security analyst reviewing a home network (not enterprise).

Analyze the 24-hour security summary below. Look specifically for:
- Port scanning or host enumeration patterns
- New or unrecognized devices — flag their hostname and IP
- Unusual outbound connection patterns or destinations
- Slow beaconing (periodic connections at regular intervals to uncommon hosts)
- Repeated firewall blocks from the same source IP
- Rogue access points that may be impersonating known SSIDs
- Brute-force attempts on any exposed service
- Multi-event chains that individually look innocent but together suggest compromise

Instructions:
- Rate each finding: HIGH / MED / LOW
- Reference specific IPs, hostnames, or MACs from the data where relevant
- If nothing is genuinely suspicious, say so — do not invent concerns
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

Instructions:
- Rate each finding: HIGH / MED / LOW
- Reference specific client names, IPs, and actual MB figures where relevant
- If performance looks normal for a home network, say so clearly
- Bullet points, concise
- End with a single-line overall verdict

DATA:
{json.dumps(data, indent=2)}"""
