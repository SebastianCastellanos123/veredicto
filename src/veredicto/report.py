"""Formato de los resultados: texto, Markdown (para GitHub) y JSON."""
from __future__ import annotations

import json

from .models import Finding, Review, Severity
from .sanitize import one_line

VERDICTS = {
    "nothing": "Nada que revisar",
    "ok": "Sin hallazgos relevantes",
    "review": "Conviene revisar los hallazgos",
    "changes": "Se recomiendan cambios antes de aceptar",
    "incomplete": "Revisión incompleta (un subagente falló)",
}
AGENT_LABELS = {"seguridad": "Seguridad", "calidad": "Calidad", "pruebas": "Pruebas", "orquestador": "Orquestador"}
MARKER = "<!-- veredicto:review -->"
DISCLAIMER = "Revisión automática: puede equivocarse y no sustituye a una revisión humana."


def _label(agent: str) -> str:
    return AGENT_LABELS.get(agent, one_line(agent, 20))


def _cell(text: str, max_len: int = 80) -> str:
    """Texto seguro para una celda de tabla Markdown: una línea, sin comillas invertidas y sin barras
    verticales (el nombre de un archivo lo controla quien abre el PR y podría romper la tabla)."""
    return one_line(text, max_len).replace("`", "").replace("|", "¦")


def _counts(rev: Review) -> str:
    c = {s: 0 for s in Severity}
    for f in rev.all_findings:
        c[f.severity] += 1
    parts = [f"{c[s]} {s.label}" for s in sorted(Severity, reverse=True) if c[s]]
    return ", ".join(parts) if parts else "ninguno"


def _where(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file


def inline_comment_body(f: Finding) -> str:
    """Texto del comentario que se publica sobre una línea del PR."""
    body = f"**[{f.severity.label.upper()} · {_label(f.agent)}] {f.title}**\n\n{f.explanation}".rstrip()
    if f.suggestion:
        body += f"\n\n**Sugerencia:** {f.suggestion}"
    return body


def _mode_line(rev: Review) -> str:
    if rev.mode.startswith("simulado"):
        return "Modo: **simulado** (reglas fijas, sin modelo de lenguaje)"
    return f"Modo: modelo de lenguaje `{one_line(rev.mode, 60)}`"


def to_markdown(rev: Review, *, details: bool = False) -> str:
    """Resumen para publicar en GitHub. details=True incluye también la explicación de cada hallazgo."""
    out = [MARKER, f"## Veredicto: {VERDICTS[rev.verdict]}", "", f"> {DISCLAIMER}", ""]
    out.append(_mode_line(rev))
    if rev.plan:
        out.append("Plan del orquestador: " + ", ".join(f"**{_label(a)}**" for a in rev.plan))
    out.append(f"Archivos revisados: {rev.files_reviewed} · Hallazgos: {_counts(rev)}")
    out.append("")

    allf = sorted(rev.all_findings, key=lambda f: (-int(f.severity), f.file, f.line or 0))
    if allf:
        out += ["| Severidad | Área | Ubicación | Hallazgo |", "|---|---|---|---|"]
        for f in allf:
            out.append(f"| {f.severity.label} | {_label(f.agent)} | `{_cell(_where(f))}` | {_cell(f.title, 100)} |")
        out.append("")
    if details:
        for f in allf:
            out += [f"### {f.severity.label.upper()} · {_label(f.agent)} · `{one_line(_where(f), 80).replace('`', '')}`", "",
                    inline_comment_body(f), ""]
    elif rev.general:
        out += ["### Hallazgos sin línea concreta", ""]
        for f in rev.general:
            out += [f"- **{f.title}** ({_label(f.agent)}, `{one_line(f.file, 80).replace('`', '')}`): {one_line(f.explanation, 300)}"]
        out.append("")

    notes = []
    if rev.omitted:
        notes.append(f"{rev.omitted} hallazgos de menor gravedad no se muestran por el límite de comentarios.")
    if rev.dropped:
        notes.append(f"{rev.dropped} hallazgos del modelo se descartaron por no poder verificarse contra el diff.")
    for fl in rev.failures:
        notes.append(f"El subagente **{_label(fl.agent)}** falló ({fl.reason}); esa parte NO se revisó.")
    if rev.redactions:
        n = sum(rev.redactions.values())
        notes.append(f"Se ocultaron {n} posibles secretos antes de enviar el código al modelo.")
    if rev.skipped_files:
        sk = "; ".join(f"`{one_line(p, 60).replace('`', '')}` ({r})" for p, r in list(rev.skipped_files.items())[:8])
        more = f" y {len(rev.skipped_files) - 8} más" if len(rev.skipped_files) > 8 else ""
        notes.append(f"No se revisaron: {sk}{more}.")
    if rev.input_tokens or rev.output_tokens:
        notes.append(f"Uso del modelo: {rev.input_tokens} tokens de entrada, {rev.output_tokens} de salida.")
    if notes:
        out += ["<details><summary>Detalles de la ejecución</summary>", ""] + [f"- {n}" for n in notes] + ["", "</details>"]
    return "\n".join(out).rstrip() + "\n"


def to_text(rev: Review) -> str:
    out = ["VEREDICTO · revisión de pull request", "=" * 60,
           f"Resultado:  {VERDICTS[rev.verdict]}",
           f"Modo:       {rev.mode}",
           f"Plan:       {', '.join(_label(a) for a in rev.plan) or '(ninguno)'}",
           f"Archivos:   {rev.files_reviewed} revisados · Hallazgos: {_counts(rev)}", ""]
    for f in sorted(rev.all_findings, key=lambda f: (-int(f.severity), f.file, f.line or 0)):
        out.append(f"[{f.severity.label.upper()}] {_label(f.agent)} · {_where(f)}")
        out.append(f"   {f.title}")
        if f.explanation:
            out.append(f"   {one_line(f.explanation, 400)}")
        if f.suggestion:
            out.append(f"   Sugerencia: {one_line(f.suggestion, 300)}")
        out.append("")
    if rev.omitted:
        out.append(f"({rev.omitted} hallazgos menores no se muestran por el límite)")
    if rev.dropped:
        out.append(f"({rev.dropped} hallazgos del modelo descartados: no verificables contra el diff)")
    for fl in rev.failures:
        out.append(f"AVISO: el subagente '{fl.agent}' falló ({fl.reason}); esa parte NO se revisó.")
    if rev.redactions:
        out.append(f"Se ocultaron {sum(rev.redactions.values())} posibles secretos antes de enviar el código al modelo.")
    for p, r in rev.skipped_files.items():
        out.append(f"No revisado: {one_line(p, 80)} ({r})")
    if rev.input_tokens or rev.output_tokens:
        out.append(f"Tokens: {rev.input_tokens} entrada / {rev.output_tokens} salida")
    out.append(DISCLAIMER)
    return "\n".join(out) + "\n"


def to_json(rev: Review) -> str:
    def fnd(f: Finding) -> dict:
        return {"agent": f.agent, "file": f.file, "line": f.line, "severity": f.severity.name.lower(),
                "title": f.title, "explanation": f.explanation, "suggestion": f.suggestion}
    return json.dumps({
        "verdict": rev.verdict, "mode": rev.mode, "plan": rev.plan,
        "files_reviewed": rev.files_reviewed,
        "findings": [fnd(f) for f in rev.findings], "general": [fnd(f) for f in rev.general],
        "failures": [{"agent": x.agent, "reason": x.reason} for x in rev.failures],
        "skipped_files": rev.skipped_files, "redactions": rev.redactions,
        "dropped": rev.dropped, "omitted": rev.omitted,
        "usage": {"input_tokens": rev.input_tokens, "output_tokens": rev.output_tokens},
    }, ensure_ascii=False, indent=2) + "\n"
