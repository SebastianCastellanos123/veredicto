"""Controles deterministas del orquestador: NO dependen del modelo.

Un modelo puede ser engañado (prompt injection). Si el autor del PR logra que el modelo
"obedezca" y responda "todo bien", estos controles igual levantan la alerta, porque son
código normal que lee el diff directamente.
"""
from __future__ import annotations

import re

from .diff import FileDiff
from .models import Finding, Severity

AGENT = "orquestador"

# Frases dirigidas a un revisor automático (español e inglés).
INJECTION = re.compile(
    r"(?i)(ignor(?:a|e)\b.{0,40}(?:instrucciones|instructions)"
    r"|ignore (?:all )?(?:previous|prior|above) instructions"
    r"|aprueba (?:este|el) (?:pr|cambio|c[oó]digo)"
    r"|approve this (?:pr|change|code)"
    r"|no reportes|do not report|olvida (?:tus|las) (?:reglas|instrucciones)"
    r"|system prompt|eres un (?:asistente|revisor) (?:que|y) (?:aprueba|ignora))"
)
# Trojan Source (CVE-2021-42574): caracteres bidireccionales que cambian cómo se VE el código.
BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
# Caracteres de ancho cero: ocultan texto o crean nombres que parecen iguales.
INVISIBLE = re.compile("[\u200b-\u200d\u2060\ufeff]")


def scan(files: list[FileDiff]) -> list[Finding]:
    out: list[Finding] = []
    for f in files:
        for no, text in f.added.items():
            if INJECTION.search(text):
                out.append(Finding(
                    AGENT, f.path, no, Severity.HIGH, "Texto que intenta manipular la revisión automática",
                    "Este texto está dirigido a un revisor automático (prompt injection). Un cambio legítimo "
                    "no necesita pedirle a un revisor que ignore reglas o apruebe.",
                    "Elimina el texto y revisa con cuidado el resto del cambio y a su autor."))
            if BIDI.search(text):
                out.append(Finding(
                    AGENT, f.path, no, Severity.HIGH, "Caracteres Unicode bidireccionales ocultos (Trojan Source)",
                    "La línea contiene caracteres invisibles que cambian el orden en que se muestra el código, "
                    "de modo que lo que ves en pantalla puede no ser lo que se ejecuta.",
                    "Elimina esos caracteres. No hay motivo legítimo para ellos en código fuente."))
            elif INVISIBLE.search(text):
                out.append(Finding(
                    AGENT, f.path, no, Severity.MEDIUM, "Caracteres invisibles en el código",
                    "La línea contiene caracteres de ancho cero que pueden ocultar texto o disfrazar identificadores.",
                    "Elimínalos y revisa que los nombres sean los que parecen."))
    return out
