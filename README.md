# UniFi AI Dashboard

A local AI-powered security and network monitoring dashboard for UniFi networks. Pulls live data directly from your UniFi console via REST API, analyzes it with a locally-running LLM, and presents it in a UniFi-styled dark web UI — all without sending any data to the cloud.

---

## Features

### Dashboard Views
- **Security Overview** — connected clients, IPS alarms (24h filtered), firewall blocks, rogue AP detection, top event types
- **Device Health** — per-device CPU/memory bars, firmware version, uptime, online/offline state
- **Network Performance** — WAN status and latency, top clients ranked by bandwidth consumption
- **Data Diagnostics** — full client list, raw alarm/event samples for cross-referencing against your UniFi dashboard

### AI Analysis
- Streams LLM analysis token-by-token directly in the UI
- Pre-tuned prompts for each view (security threats, health anomalies, bandwidth hogs)
- Custom prompt box for ad-hoc questions about your network data
- HIGH / MED / LOW severity ratings on all findings

### Model Management
- Load and unload LM Studio models directly from the dashboard — no need to open LM Studio's GUI
- Polls until the model is ready before enabling analysis
- Status indicators show UniFi connection and LLM readiness at a glance

### Privacy First
- All data stays on your LAN — UniFi console → Python → local LLM → browser
- No cloud services, no telemetry, no external API calls
- `.env` pattern keeps all credentials out of source control

### Daily Report Mode
- Run `unifi_daily_analysis.py` as a scheduled task for an automated daily security digest
- Saves timestamped reports to a configurable directory
- `--dry-run` flag to validate data fetching without invoking the LLM
- `--discover` flag to find your site ID and test API connectivity

---

## Requirements

### Software
| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10+ | 3.12 recommended |
| LM Studio | 0.4.x+ | Local inference server |
| UniFi Network | Any modern firmware | UDM, UDM-Pro, Cloud Key, or self-hosted controller |

### Python Packages
```
requests
python-dotenv
flask
```

Install with:
```bash
pip install requests python-dotenv flask
```

### LLM Model
Any model served by LM Studio will work. Recommended for best analysis quality:
- **Qwen3 Coder Next** (80B MoE) — excellent at structured log analysis
- **Llama 3.3 70B** — strong general reasoning
- Smaller models (7B–14B) work fine for basic analysis with faster response times

---

## Setup

### 1. Clone the repo
```bash
git clone https://github.com/ne0nmatrix/unifi-ai-dashboard.git
cd unifi-ai-dashboard
pip install -r requirements.txt
```

### 2. Configure your environment
```bash
cp .env.example .env   # Mac/Linux
copy .env.example .env  # Windows
```

Edit `.env` with your details:

```env
# UniFi Console
UNIFI_CONSOLE_IP=192.168.1.1        # IP of your UDM/Cloud Key/controller
UNIFI_API_KEY=                       # Generated in UniFi → Settings → Control Plane → Integrations
UNIFI_SITE_ID=                       # Found via --discover (see below)
UNIFI_SITE_NAME=default              # Usually 'default' for single-site setups

# Local LLM (LM Studio)
LLM_ENDPOINT=http://localhost:1234   # Base URL only — no path suffix
LLM_MODEL=                           # Exact model ID from LM Studio (e.g. qwen/qwen3-coder-next)

# Reports (daily analysis mode only)
REPORT_DIR=./reports                 # Where to save daily report files
```

### 3. Generate your UniFi API key
1. Open UniFi Network → **Settings → Control Plane → Integrations**
2. Enter a name (e.g. `ai-dashboard`) and click **Create API Key**
3. Copy the key immediately — it is only shown once
4. Paste it into `UNIFI_API_KEY` in your `.env`

### 4. Find your Site ID
```bash
python unifi_daily_analysis.py --discover
```
Copy the `id` value printed for your site and paste it into `UNIFI_SITE_ID` in `.env`.

### 5. Validate connectivity
```bash
python unifi_daily_analysis.py --dry-run
```
This fetches all data and prints a summary without calling the LLM. Confirm the client count and alarm counts look right before proceeding.

### 6. Start LM Studio
- Open LM Studio and load your chosen model
- Start the local server (default port 1234)
- Confirm the model ID with: `curl http://localhost:1234/v1/models`
- Paste the `id` value into `LLM_MODEL` in `.env`

### 7. Launch the dashboard
```bash
python app.py
```
Opens automatically at `http://localhost:5000`

---

## Project Structure

```
unifi-ai-dashboard/
├── app.py                  # Flask backend and API routes
├── unifi_client.py         # UniFi REST API wrapper
├── lmstudio_client.py      # LM Studio model management and inference
├── prompts.py              # LLM prompt builders for each analysis preset
├── unifi_daily_analysis.py # Standalone daily report script (CLI)
├── templates/
│   └── index.html          # Single-page dashboard UI
├── .env.example            # Environment variable template
├── .gitignore
└── requirements.txt
```

---

## Scheduling Daily Reports (Optional)

To run the security analysis automatically each morning, set up a scheduled task pointing at:

```bash
python /path/to/unifi_daily_analysis.py
```

**Windows Task Scheduler:** Create a basic task, trigger daily at your preferred time, action = start a program → `python.exe`, arguments = `m:\repos\unifi-ai-dashboard\unifi_daily_analysis.py`

Reports are saved to `REPORT_DIR` as `security_YYYY-MM-DD.txt`.

---

## Notes

- **Rogue APs:** A high rogue AP count (50–100+) is normal in residential areas — these are neighboring networks your APs can hear, not actual threats. The LLM is instructed to contextualize these correctly.
- **Firmware warnings:** The LLM has no internet access and cannot verify current firmware versions. It is instructed not to flag firmware as outdated based on stale training data.
- **Client count:** Uses the `stat/sta` internal API endpoint which returns all known clients. The integration API is paginated and may return fewer.
- **Events vs Alarms:** UniFi separates general events from IPS/security alarms. Both are fetched and filtered to the last 24 hours by timestamp.
