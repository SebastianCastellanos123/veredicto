"""Línea de comandos.

    veredicto review --diff cambios.diff            # revisa un archivo de diff local
    veredicto review --git-range origin/main...HEAD # revisa los cambios de tu rama
    veredicto github --repo dueño/repo --pr 12      # revisa un PR y publica la revisión
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

from . import __version__
from .fake import HeuristicLLM
from .github import GitHubClient, GitHubError, publish
from .llm import DEFAULT_MODEL, AnthropicLLM, LLMError
from .models import Severity
from .orchestrator import Config, review
from .report import to_json, to_markdown, to_text

MAX_DIFF_BYTES = 10 * 1024 * 1024
_RANGE = re.compile(r"^[\w./~^@{}:-]+(?:\.{2,3}[\w./~^@{}:-]+)?$")
_FAIL_ON = {"none": None, "medium": Severity.MEDIUM, "high": Severity.HIGH, "critical": Severity.CRITICAL}


def _make_llm(kind: str, model: str | None):
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if kind == "mock" or (kind == "auto" and not key):
        if kind == "auto":
            print("aviso: no hay ANTHROPIC_API_KEY; se usa el modo SIMULADO (reglas, sin IA).", file=sys.stderr)
        return HeuristicLLM()
    return AnthropicLLM(key, model or os.environ.get("VEREDICTO_MODEL") or DEFAULT_MODEL)


def _read_diff(args) -> str:
    if args.git_range:
        rng = args.git_range
        if rng.startswith("-") or not _RANGE.match(rng):          # evita inyectar opciones de git
            raise SystemExit("error: rango de git no válido")
        out = subprocess.run(["git", "diff", "--no-color", "--no-ext-diff", rng, "--"],
                             capture_output=True, check=False)
        if out.returncode != 0:
            raise SystemExit("error: git diff falló: " + out.stderr.decode("utf-8", "replace")[:200])
        data = out.stdout
    elif args.diff == "-":
        data = sys.stdin.buffer.read(MAX_DIFF_BYTES + 1)
    else:
        with open(args.diff, "rb") as fh:
            data = fh.read(MAX_DIFF_BYTES + 1)
    if len(data) > MAX_DIFF_BYTES:
        raise SystemExit("error: el diff supera los 10 MB")
    return data.decode("utf-8", errors="replace")


def _config(args) -> Config:
    return Config(max_chars=args.max_chars, max_comments=args.max_comments, lang=args.lang)


def _exit_code(rev, fail_on: str) -> int:
    threshold = _FAIL_ON[fail_on]
    top = rev.max_severity
    return 2 if threshold is not None and top is not None and top >= threshold else 0


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--llm", choices=["auto", "mock", "anthropic"], default="auto",
                   help="auto: usa Claude si hay ANTHROPIC_API_KEY, si no el modo simulado")
    p.add_argument("--model", help=f"modelo de Claude (por defecto {DEFAULT_MODEL}; o variable VEREDICTO_MODEL)")
    p.add_argument("--max-chars", type=int, default=60_000, help="tamaño máximo del diff por subagente")
    p.add_argument("--max-comments", type=int, default=20, help="máximo de hallazgos publicados")
    p.add_argument("--lang", choices=["es", "en"], default="es")
    p.add_argument("--fail-on", choices=list(_FAIL_ON), default="none",
                   help="sale con código 2 si hay hallazgos de esta gravedad o más")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="veredicto", description="Revisor de pull requests con subagentes.")
    p.add_argument("--version", action="version", version=f"veredicto {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("review", help="revisar un diff local")
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--diff", help="archivo con el diff, o '-' para leer de la entrada estándar")
    src.add_argument("--git-range", help="rango de git, p. ej. origin/main...HEAD")
    r.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    _common(r)

    g = sub.add_parser("github", help="revisar un pull request de GitHub y publicar la revisión")
    g.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""), help="dueño/nombre")
    g.add_argument("--pr", type=int, required=True, help="número del pull request")
    g.add_argument("--dry-run", action="store_true", help="muestra la revisión sin publicarla")
    _common(g)
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):                        # Windows: que no falle con tildes
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    try:
        llm = _make_llm(args.llm, args.model)
        if args.cmd == "review":
            rev = review(_read_diff(args), llm, _config(args))
            print({"text": to_text, "markdown": to_markdown, "json": to_json}[args.format](rev), end="")
            return _exit_code(rev, args.fail_on)
        return _run_github(args, llm)
    except (LLMError, GitHubError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def _run_github(args, llm) -> int:
    client = GitHubClient(os.environ.get("GITHUB_TOKEN", ""), args.repo)
    pr = client.pull(args.pr)
    if pr["state"] != "open":
        print("El PR no está abierto: no hay nada que revisar."); return 0
    if pr["draft"]:
        print("El PR es un borrador: se omite la revisión."); return 0
    if pr["head_repo"] != pr["base_repo"]:
        print("El PR viene de un fork: se omite (sin permisos de escritura ni secretos por seguridad)."); return 0
    rev = review(client.diff(args.pr), llm, _config(args))
    if args.dry_run:
        print(to_markdown(rev, details=True), end="")
    else:
        how = publish(client, args.pr, pr["sha"], rev)
        print(f"Revisión publicada ({how}). Veredicto: {rev.verdict}.")
    return _exit_code(rev, args.fail_on)
