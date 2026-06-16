#!/usr/bin/env python3
"""lmstudio_client.py — LM Studio REST API: status, model management, streaming."""

import json
import requests


class LMStudioClient:
    def __init__(self, base_url: str, default_model: str, max_tokens: int = 4096):
        self.base          = base_url.rstrip("/")
        self.default_model = default_model
        self.max_tokens    = max_tokens

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

    # ── Resolve model ──────────────────────────────────────────────────────
    def get_loaded_model(self):
        """
        Belt-and-suspenders model resolution for inference.

        Preference order:
          1. default_model, if it's set AND currently loaded (exact match).
          2. Otherwise the first currently-loaded model reported by LM Studio.
          3. Otherwise fall back to default_model (may be "").

        This guarantees inference uses something already resident in memory
        whenever possible, so a stale/blank LLM_MODEL can never silently
        JIT-load an unintended model and clobber your RAM.
        """
        try:
            r = requests.get(self._oai("/v1/models"), timeout=5)
            r.raise_for_status()
            ids = [m["id"] for m in r.json().get("data", [])]
            if self.default_model and self.default_model in ids:
                return self.default_model
            if ids:
                return ids[0]
        except Exception:
            pass
        return self.default_model

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
    def stream_inference(self, prompt: str, model: str | None = None):
        model = model or self.get_loaded_model()
        try:
            with requests.post(
                self._oai("/v1/chat/completions"),
                json={
                    "model":       model,
                    "messages":    [{"role": "user", "content": prompt}],
                    "max_tokens":  self.max_tokens,
                    "temperature": 0.2,
                    "stream":      True,
                },
                stream=True,
                timeout=180,
            ) as r:
                r.raise_for_status()
                got_content   = False
                finish_reason = None
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
                        choice = json.loads(payload)["choices"][0]
                        # Render only the visible answer (content). A reasoning
                        # model's thinking arrives under reasoning_content, which
                        # we intentionally ignore.
                        piece = choice.get("delta", {}).get("content", "")
                        if choice.get("finish_reason"):
                            finish_reason = choice["finish_reason"]
                        if piece:
                            got_content = True
                            yield piece
                    except Exception:
                        pass
                # A reasoning model can spend its whole budget thinking and never
                # emit a visible answer. Surface that instead of a blank pane.
                if not got_content:
                    if finish_reason == "length":
                        yield ("[No answer returned: the model hit its token limit "
                               f"({self.max_tokens}) while reasoning. Raise "
                               "LLM_MAX_TOKENS in .env, or load a non-reasoning model.]")
                    else:
                        yield "[No answer text was returned by the model.]"
        except Exception as e:
            yield f"\n\n[Inference error: {e}]"
