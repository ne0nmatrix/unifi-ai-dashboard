#!/usr/bin/env python3
"""lmstudio_client.py — LM Studio REST API: status, model management, streaming."""

import json
import requests


class LMStudioClient:
    def __init__(self, base_url: str, default_model: str):
        self.base          = base_url.rstrip("/")
        self.default_model = default_model

    def _oai(self, path):  return f"{self.base}{path}"   # OpenAI-compat endpoints
    def _mgmt(self, path): return f"{self.base}{path}"   # LM Studio management API

    # ── Status ─────────────────────────────────────────────────────────────
    def get_status(self):
        try:
            r = requests.get(self._oai("/v1/models"), timeout=5)
            r.raise_for_status()
            loaded = r.json().get("data", [])
            ids    = [m["id"] for m in loaded]
            return {
                "ok":            True,
                "running":       True,
                "loaded_models": ids,
                "model_ready":   self.default_model in ids,
                "default_model": self.default_model,
            }
        except requests.exceptions.ConnectionError:
            return {"ok": False, "running": False, "error": "LM Studio not running"}
        except Exception as e:
            return {"ok": False, "running": False, "error": str(e)}

    # ── Model list ─────────────────────────────────────────────────────────
    def list_models(self):
        """
        Returns all on-disk models via LM Studio v0 management API.
        Falls back to loaded-only list if that endpoint isn't available.
        """
        try:
            r = requests.get(self._mgmt("/api/v0/models"), timeout=5)
            if r.ok:
                return {"ok": True, "models": r.json().get("data", [])}
        except Exception:
            pass
        # Fallback
        try:
            r = requests.get(self._oai("/v1/models"), timeout=5)
            r.raise_for_status()
            return {"ok": True, "models": r.json().get("data", [])}
        except Exception as e:
            return {"ok": False, "models": [], "error": str(e)}

    # ── Load / unload ──────────────────────────────────────────────────────
    def load_model(self, model_id: str):
        try:
            r = requests.post(
                self._mgmt("/api/v0/models/load"),
                json={"model": model_id},
                timeout=30,   # request returns quickly; loading happens async
            )
            if r.ok:
                return {"ok": True, "message": f"Loading {model_id} — may take a few minutes for large models."}
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def unload_model(self, model_id: str):
        if not model_id:
            # Nothing specified — unload whatever is currently loaded
            status = self.get_status()
            ids = status.get("loaded_models", [])
            if not ids:
                return {"ok": True, "message": "Nothing loaded."}
            model_id = ids[0]
        try:
            r = requests.post(
                self._mgmt("/api/v0/models/unload"),
                json={"model": model_id},
                timeout=15,
            )
            if r.ok:
                return {"ok": True, "message": f"Unloaded {model_id}."}
            return {"ok": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # ── Streaming inference ────────────────────────────────────────────────
    def stream_inference(self, prompt: str, model: str = None):
        model = model or self.default_model
        try:
            with requests.post(
                self._oai("/v1/chat/completions"),
                json={
                    "model":       model,
                    "messages":    [{"role": "user", "content": prompt}],
                    "max_tokens":  1500,
                    "temperature": 0.2,
                    "stream":      True,
                },
                stream=True,
                timeout=180,
            ) as r:
                r.raise_for_status()
                for line in r.iter_lines():
                    if not line:
                        continue
                    if isinstance(line, bytes):
                        line = line.decode("utf-8")
                    if not line.startswith("data: "):
                        continue
                    payload = line[6:].strip()
                    if payload == "[DONE]":
                        break
                    try:
                        delta = json.loads(payload)["choices"][0]["delta"].get("content", "")
                        if delta:
                            yield delta
                    except Exception:
                        pass
        except Exception as e:
            yield f"\n\n[Inference error: {e}]"
