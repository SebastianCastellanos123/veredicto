"""Oculta secretos ANTES de enviar el código a un modelo de lenguaje externo.

Un diff puede incluir una clave real subida por error. No debe salir de tu máquina
hacia un tercero. El marcador [REDACTED:tipo] conserva el hecho de que "aquí hay un
secreto" (el revisor puede reportarlo) sin revelar su valor.
"""
from __future__ import annotations

import re
from collections import Counter

_SIMPLE = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("api_key", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# nombre = "valor"  donde el nombre sugiere un secreto. Se conserva el nombre y se oculta el valor.
_ASSIGNMENT = re.compile(
    r"""(?ix)
    (\b[\w.-]*(?:api[_-]?key|secret|token|passwd|password|pwd)[\w.-]*)   # nombre
    (\s*[:=]\s*)
    (["'])([^"'\s]{8,})\3                                                 # valor
    """
)
# esquema://usuario:CONTRASEÑA@host
_URL_PASSWORD = re.compile(r"(\b[a-z][a-z0-9+.-]*://[^:\s/@]+:)([^@\s/]{3,})(@)")
_BLOB = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}")


def redact_line(line: str, counts: Counter | None = None) -> str:
    """Reemplaza secretos de una línea por [REDACTED:tipo]."""
    def bump(kind: str) -> None:
        if counts is not None:
            counts[kind] += 1

    for kind, pattern in _SIMPLE:
        line, n = pattern.subn(f"[REDACTED:{kind}]", line)
        for _ in range(n):
            bump(kind)

    def repl_assignment(m: re.Match) -> str:
        if m.group(4).startswith("[REDACTED:"):      # ya estaba oculto por otra regla
            return m.group(0)
        bump("credencial")
        return f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED:credencial]{m.group(3)}"

    line = _ASSIGNMENT.sub(repl_assignment, line)

    def repl_url(m: re.Match) -> str:
        bump("password_en_url")
        return f"{m.group(1)}[REDACTED:password_en_url]{m.group(3)}"

    line = _URL_PASSWORD.sub(repl_url, line)

    line, n = _BLOB.subn("[REDACTED:blob_base64]", line)
    for _ in range(n):
        bump("blob_base64")
    return line
