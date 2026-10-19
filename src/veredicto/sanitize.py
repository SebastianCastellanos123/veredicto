"""Limpieza del texto que produce el modelo antes de publicarlo.

La salida de un modelo NO es confiable: si el PR contiene instrucciones maliciosas
(prompt injection), el modelo podría repetirlas. Aquí se neutralizan los vectores
más comunes en un comentario de GitHub:

  * menciones (@usuario): pueden notificar a personas o equipos;
  * enlaces y HTML: phishing o contenido activo;
  * bloques ```suggestion: GitHub los convierte en un botón "aplicar cambio" con un clic;
  * caracteres de control y textos gigantes.
"""
from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u202a-\u202e\u2066-\u2069]")
_URL = re.compile(r"(?i)\b(?:https?|ftp|javascript|data):[^\s)>\]]*")
_MD_LINK_TARGET = re.compile(r"\]\([^)]*\)")
_HTML_TAG = re.compile(r"</?[A-Za-z!][^>]{0,200}>")
_MENTION = re.compile(r"@(?=[A-Za-z0-9_-])")
_SUGGESTION_FENCE = re.compile(r"(?im)^(\s*`{3,}|\s*~{3,})\s*suggestion\b")


def clean_text(text: object, max_len: int) -> str:
    """Devuelve texto seguro para publicar, recortado a max_len caracteres."""
    if not isinstance(text, str):
        return ""
    s = _CONTROL.sub("", text)
    s = _SUGGESTION_FENCE.sub(lambda m: m.group(1), s)      # ```suggestion  →  ```
    s = _MD_LINK_TARGET.sub("]", s)                          # [texto](url)    →  [texto]
    s = _URL.sub("[enlace eliminado]", s)
    s = _HTML_TAG.sub("", s)
    s = _MENTION.sub("@\u200b", s)                           # @ana  →  @(espacio invisible)ana
    s = s.strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def one_line(text: object, max_len: int) -> str:
    """Igual que clean_text pero en una sola línea (para títulos y tablas)."""
    return re.sub(r"\s+", " ", clean_text(text, max_len * 2)).strip()[:max_len]
