"""Orquestador de la revisión.

Qué hace él (en código, de forma determinista) y qué hace el modelo:

    ORQUESTADOR (código)                         SUBAGENTES (modelo)
    ─────────────────────────────────            ─────────────────────────────
    lee y filtra el diff                         analizan UN aspecto del código
    decide qué subagentes hacen falta     ──►    y devuelven hallazgos en JSON
    oculta secretos antes de enviar
    los ejecuta en paralelo y aísla fallos
    verifica cada hallazgo contra el diff   ◄──
    limpia el texto, quita duplicados, ordena
    calcula el veredicto

El modelo SOLO propone. Nada de lo que escriba el modelo (ni nada que haya escrito el autor
del PR dentro de su código) puede cambiar el veredicto ni publicar contenido sin pasar por
la validación y la limpieza.
"""
from __future__ import annotations

import re
import secrets
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import guards
from .agents import ALL_AGENTS, Agent, extract_json, to_findings
from .diff import parse_diff, render_files, skip_reason
from .llm import LLM
from .models import Failure, Finding, Review, Severity
from .sanitize import clean_text, one_line


@dataclass
class Config:
    max_chars: int = 60_000            # tamaño máximo del diff que ve cada subagente
    max_findings_per_agent: int = 8
    max_comments: int = 20             # tope de hallazgos publicados
    max_tokens: int = 2_000            # tope de respuesta por subagente (control de costo)
    lang: str = "es"
    workers: int = 3


def _normalize_path(p: str) -> str:
    p = p.strip().replace("\\", "/")
    for prefix in ("a/", "b/", "./"):
        if p.startswith(prefix):
            p = p[len(prefix):]
    return p


def _title_key(title: str) -> str:
    return re.sub(r"[^a-z0-9áéíóúñ]+", "", title.lower())[:40]


def review(diff_text: str, llm: LLM, cfg: Config | None = None, agents: tuple[Agent, ...] = ALL_AGENTS) -> Review:
    cfg = cfg or Config()

    # 1) Leer el diff y quedarse con lo que vale la pena revisar.
    skipped: dict[str, str] = {}
    reviewable = []
    for f in parse_diff(diff_text):
        reason = skip_reason(f) or (None if f.lines else "sin cambios de contenido")
        if reason:
            skipped[f.path] = reason
        else:
            reviewable.append(f)

    rev = Review(mode=llm.name, verdict="nothing", skipped_files=skipped, files_reviewed=len(reviewable))
    if not reviewable:
        return rev

    # 2) Planificar: qué subagentes hacen falta según lo que cambió (reglas, no modelo).
    plan: list[tuple[Agent, list]] = []
    for agent in agents:
        subset = agent.select(reviewable)
        if subset:
            plan.append((agent, subset))
            rev.plan[agent.id] = agent.why

    # Estadística de secretos ocultados (una sola vez, no por subagente).
    counts: Counter = Counter()
    render_files(reviewable, 10**9, counts)
    rev.redactions = dict(counts)

    # 3) Ejecutar los subagentes en paralelo. Un delimitador aleatorio por ejecución impide
    #    que el código del PR "cierre" la etiqueta y escape del bloque de datos.
    tag = "diff_no_confiable_" + secrets.token_hex(8)

    def run_one(agent: Agent, files: list):
        text, _included, too_big = render_files(files, cfg.max_chars)
        text = text.replace(tag, "")
        system = agent.system_prompt(tag, cfg.max_findings_per_agent, cfg.lang)
        result = llm.complete(system, agent.user_prompt(tag, text), max_tokens=cfg.max_tokens)
        data = extract_json(result.text)
        if data is None:
            raise ValueError("la respuesta no contiene un JSON válido")
        found, bad = to_findings(agent.id, data)
        return found, bad, result, too_big

    raw: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max(1, min(cfg.workers, len(plan)))) as pool:
        futures = [(agent, pool.submit(run_one, agent, files)) for agent, files in plan]
        for agent, fut in futures:
            try:
                found, bad, result, too_big = fut.result()
            except Exception as e:                       # un subagente caído no tumba la revisión
                rev.failures.append(Failure(agent.id, one_line(f"{type(e).__name__}: {e}", 160)))
                continue
            raw.extend(found)
            rev.dropped += bad
            rev.input_tokens += result.input_tokens
            rev.output_tokens += result.output_tokens
            for path in too_big:
                rev.skipped_files.setdefault(path, "excede el límite de tamaño")

    # 4) Verificar cada hallazgo contra el diff real y limpiar su texto.
    by_path = {f.path: f for f in reviewable}
    verified: dict[tuple, Finding] = {}
    for f in raw:
        path = _normalize_path(f.file)
        diff_file = by_path.get(path)
        title = one_line(f.title, 120)
        if diff_file is None or not title:
            rev.dropped += 1                              # el archivo no existe en el PR: alucinación o manipulación
            continue
        line = f.line if f.line in diff_file.right else None   # solo líneas realmente visibles en el diff
        clean = Finding(f.agent, path, line, f.severity, title,
                        clean_text(f.explanation, 900), clean_text(f.suggestion, 700))
        key = (path, line, _title_key(title))
        if key not in verified or clean.severity > verified[key].severity:
            verified[key] = clean

    # 4b) Controles deterministas (no dependen del modelo): si el modelo fue engañado y no vio algo
    #     evidente, esto lo detecta igual. No se duplica una línea que ya tiene un hallazgo grave.
    flagged = {(k[0], k[1]) for k, v in verified.items() if v.severity >= Severity.HIGH}
    for g in guards.scan(reviewable):
        if (g.file, g.line) not in flagged:
            verified.setdefault((g.file, g.line, _title_key(g.title)), g)

    # 5) Ordenar por gravedad, aplicar el tope y repartir entre anclados y generales.
    ordered = sorted(verified.values(), key=lambda x: (-int(x.severity), x.file, x.line or 0))
    kept, rev.omitted = ordered[: cfg.max_comments], max(0, len(ordered) - cfg.max_comments)
    rev.findings = [f for f in kept if f.line is not None]
    rev.general = [f for f in kept if f.line is None]

    # 6) Veredicto: lo calcula el código, jamás el modelo.
    rev.verdict = verdict_for(rev)
    return rev


def verdict_for(rev: Review) -> str:
    top = rev.max_severity
    if top is not None and top >= Severity.HIGH:
        return "changes"
    if top == Severity.MEDIUM:
        return "review"
    # Sin hallazgos graves, pero si algún subagente falló NO se puede afirmar que está limpio.
    return "incomplete" if rev.failures else "ok"
