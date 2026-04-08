#!/usr/bin/env python3
"""
app.py — UniFi AI Dashboard (v2)
Flask backend. Run: python app.py → opens http://localhost:5000

⚠️ NOTE:
- This version assumes correct paths are defined in unifi_client.fetch_security_data()
  and unifi_client.fetch_diagnostics() — see comments inside if you need to adjust them.
"""

import json
import os
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, Response, stream_with_context

from unifi_client import UniFiClient
from lmstudio_client import LMStudioClient
from prompts import build_security_prompt, build_health_prompt, build_performance_prompt
from db import init_db, save_snapshot, get_known_clients, get_before_after

load_dotenv()

app = Flask(__name__)
init_db()  # ensure tables exist on startup

unifi = UniFiClient(
    console_ip=os.getenv("UNIFI_CONSOLE_IP"),
    api_key=os.getenv("UNIFI_API_KEY"),
    site_id=os.getenv("UNIFI_SITE_ID"),
    site_name=os.getenv("UNIFI_SITE_NAME", "default"),
)

lmstudio = LMStudioClient(
    base_url=os.getenv("LLM_ENDPOINT", "http://localhost:1234"),
    default_model=os.getenv("LLM_MODEL", ""),
)


# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# ── Status ────────────────────────────────────────────────────────────────────
@app.route("/api/status")
def status():
    return jsonify({
        "unifi": unifi.test_connection(),
        "lmstudio": lmstudio.get_status(),
    })


# ── Data ──────────────────────────────────────────────────────────────────────
@app.route("/api/data/<preset>")
def get_data(preset):
    try:
        fetchers = {
            "security":    unifi.fetch_security_data,
            "health":      unifi.fetch_health_data,
            "performance": unifi.fetch_performance_data,
            "diagnostics": unifi.fetch_diagnostics,
        }
        if preset not in fetchers:
            return jsonify({"ok": False, "error": f"Unknown preset: {preset}"}), 400

        # Run fetch with robust fallback to prevent 500 crashes
        try:
            result = fetchers[preset]()
            if result is None:
                result = {}  # treat None as empty dict to avoid downstream errors
        except Exception as e:
            print(f"[!] {preset} fetch failed: {e}")
            result = {"error": str(e), "data": []}

        # Snapshot raw clients on every fetch for trend tracking
        try:
            raw_clients = unifi._clients()
            save_snapshot(raw_clients)
        except Exception:
            pass  # never let snapshot failure break the main response

        return jsonify({"ok": True, "data": result})
    except Exception as e:
        print(f"[!] get_data exception: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


# ── Analysis (streaming SSE) ───────────────────────────────────────────────────
@app.route("/api/analyze", methods=["POST"])
def analyze():
    body = request.json or {}
    preset = body.get("preset", "security")
    custom_prompt = body.get("custom_prompt", "").strip()
    data = body.get("data", {})
    model = body.get("model") or None

    if custom_prompt:
        prompt = f"{custom_prompt}\n\nNetwork data:\n{json.dumps(data, indent=2)}"
    else:
        builders = {
            "security": build_security_prompt,
            "health": build_health_prompt,
            "performance": build_performance_prompt,
        }
        prompt = builders.get(preset, build_security_prompt)(data)

    def generate():
        for chunk in lmstudio.stream_inference(prompt, model=model or lmstudio.default_model):
            yield f"data: {json.dumps({'chunk': chunk})}\n\n"
        yield f"data: {json.dumps({'done': True})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Model management ──────────────────────────────────────────────────────────
@app.route("/api/models")
def list_models():
    return jsonify(lmstudio.list_models())


@app.route("/api/models/load", methods=["POST"])
def load_model():
    model_id = (request.json or {}).get("model_id", "")
    return jsonify(lmstudio.load_model(model_id))


@app.route("/api/models/unload", methods=["POST"])
def unload_model():
    model_id = (request.json or {}).get("model_id", "")
    return jsonify(lmstudio.unload_model(model_id))


# ── Trends ───────────────────────────────────────────────────────────────────
@app.route("/api/trends/clients")
def trends_clients():
    return jsonify(get_known_clients())

@app.route("/api/trends/compare")
def trends_compare():
    mac = request.args.get("mac", "")
    split_date = request.args.get("split_date", "")
    if not mac or not split_date:
        return jsonify({"ok": False, "error": "mac and split_date are required"}), 400
    return jsonify(get_before_after(mac, split_date))


# ── Launch ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import webbrowser
    print("\n UniFi AI Dashboard")
    print(" http://localhost:5000\n")
    webbrowser.open("http://localhost:5000")
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
