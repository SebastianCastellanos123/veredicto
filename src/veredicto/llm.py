"""Acceso al modelo de lenguaje.

Todo el sistema depende de la interfaz `LLM` (un método: complete). Hay dos
implementaciones: `AnthropicLLM` (API real de Claude) y `HeuristicLLM` (simulado, en
fake.py). Gracias a eso los tests y el CI corren sin red, sin clave y sin costo.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
DEFAULT_MODEL = "claude-sonnet-5-5"     # se puede cambiar con --model o VEREDICTO_MODEL
MAX_RESPONSE_BYTES = 8 * 1024 * 1024    # tope de lectura: una respuesta gigante no agota la memoria


class LLMError(Exception):
    """Fallo al consultar el modelo. El mensaje NUNCA incluye la clave de API."""


@dataclass
class LLMResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str, *, max_tokens: int) -> LLMResult: ...


# (método, url, cabeceras, cuerpo, timeout) -> (estado HTTP, cuerpo de la respuesta)
HttpFn = Callable[[str, str, dict, "bytes | None", float], "tuple[int, bytes]"]


def urllib_http(method: str, url: str, headers: dict, body: bytes | None, timeout: float
                ) -> tuple[int, bytes]:
    """Transporte HTTP real con la librería estándar (solo https)."""
    if not url.lower().startswith("https://"):
        raise LLMError("solo se permiten URLs https")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:     # noqa: S310 (https verificado)
            return resp.status, resp.read(MAX_RESPONSE_BYTES + 1)[:MAX_RESPONSE_BYTES]
    except urllib.error.HTTPError as e:
        return e.code, e.read(MAX_RESPONSE_BYTES)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise LLMError(f"no se pudo conectar: {type(e).__name__}") from None


_RETRY_STATUS = {429, 500, 502, 503, 529}


class AnthropicLLM:
    def __init__(self, api_key: str, model: str = DEFAULT_MODEL, *, http: HttpFn = urllib_http,
                 retries: int = 3, timeout: float = 90.0, sleep: Callable[[float], None] = time.sleep):
        if not api_key or not api_key.strip():
            raise LLMError("falta la clave de API (variable ANTHROPIC_API_KEY)")
        self._key = api_key.strip()
        self.model = model
        self.name = model
        self._http, self._retries, self._timeout, self._sleep = http, retries, timeout, sleep

    def complete(self, system: str, user: str, *, max_tokens: int) -> LLMResult:
        payload = json.dumps({
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")
        headers = {
            "x-api-key": self._key,
            "anthropic-version": API_VERSION,
            "content-type": "application/json",
        }

        status, body = 0, b""
        for attempt in range(self._retries + 1):
            status, body = self._http("POST", API_URL, headers, payload, self._timeout)
            if status == 200:
                break
            if status in _RETRY_STATUS and attempt < self._retries:
                self._sleep(2 ** attempt)           # espera 1 s, 2 s, 4 s... (límite de uso o servidor ocupado)
                continue
            raise LLMError(f"la API respondió HTTP {status}: {_api_error(body)}")

        try:
            data = json.loads(body)
            text = "".join(b.get("text", "") for b in data["content"] if b.get("type") == "text")
            usage = data.get("usage") or {}
            return LLMResult(text, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0)))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise LLMError("respuesta de la API con formato inesperado") from None


def _api_error(body: bytes) -> str:
    """Extrae un mensaje corto y seguro del error de la API."""
    try:
        err = json.loads(body).get("error", {})
        return f"{err.get('type', 'error')}: {str(err.get('message', ''))[:160]}"
    except (ValueError, AttributeError):
        return "sin detalle"
