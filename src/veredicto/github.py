"""Cliente mínimo de la API de GitHub (solo lo necesario para revisar un PR)."""
from __future__ import annotations

import json
import re

from .llm import HttpFn, urllib_http
from .models import Review
from .report import inline_comment_body, to_markdown

API = "https://api.github.com"
_REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_BODY = 60_000          # GitHub admite 65.536 caracteres por comentario


class GitHubError(Exception):
    """Fallo con GitHub. Nunca incluye el token."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class GitHubClient:
    def __init__(self, token: str, repo: str, *, http: HttpFn = urllib_http, timeout: float = 60.0):
        if not token or not token.strip():
            raise GitHubError("falta el token de GitHub (variable GITHUB_TOKEN)")
        if not _REPO.match(repo or ""):
            raise GitHubError("el repositorio debe tener el formato dueño/nombre")
        self._token, self.repo, self._http, self._timeout = token.strip(), repo, http, timeout

    def _call(self, method: str, path: str, *, accept: str = "application/vnd.github+json",
              body: dict | None = None) -> tuple[int, bytes]:
        headers = {"Authorization": f"Bearer {self._token}", "Accept": accept,
                   "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "veredicto",
                   "Content-Type": "application/json"}
        data = json.dumps(body).encode("utf-8") if body is not None else None
        return self._http(method, f"{API}/repos/{self.repo}{path}", headers, data, self._timeout)

    @staticmethod
    def _number(n: int) -> int:
        if isinstance(n, bool) or not isinstance(n, int) or n < 1:
            raise GitHubError("el número de PR no es válido")
        return n

    def pull(self, n: int) -> dict:
        status, body = self._call("GET", f"/pulls/{self._number(n)}")
        if status != 200:
            raise GitHubError(f"no se pudo leer el PR (HTTP {status})", status)
        try:
            d = json.loads(body)
            return {"state": d["state"], "draft": bool(d.get("draft")), "sha": d["head"]["sha"],
                    "head_repo": (d["head"].get("repo") or {}).get("full_name", ""),
                    "base_repo": d["base"]["repo"]["full_name"]}
        except (ValueError, KeyError, TypeError):
            raise GitHubError("respuesta inesperada de GitHub al leer el PR") from None

    def diff(self, n: int) -> str:
        status, body = self._call("GET", f"/pulls/{self._number(n)}", accept="application/vnd.github.v3.diff")
        if status in (406, 422):
            raise GitHubError("el diff es demasiado grande para la API de GitHub", status)
        if status != 200:
            raise GitHubError(f"no se pudo descargar el diff (HTTP {status})", status)
        return body.decode("utf-8", errors="replace")

    def post_review(self, n: int, commit_id: str, body: str, comments: list[dict]) -> None:
        """Publica una revisión. El evento es SIEMPRE "COMMENT": un bot nunca aprueba ni bloquea."""
        payload = {"commit_id": commit_id, "body": body[:MAX_BODY], "event": "COMMENT", "comments": comments}
        status, resp = self._call("POST", f"/pulls/{self._number(n)}/reviews", body=payload)
        if status not in (200, 201):
            raise GitHubError(f"GitHub rechazó la revisión (HTTP {status})", status)


def publish(client: GitHubClient, n: int, commit_id: str, rev: Review) -> str:
    """Publica la revisión. Devuelve "inline" o "resumen" según cómo se pudo publicar."""
    comments = [{"path": f.file, "line": f.line, "side": "RIGHT", "body": inline_comment_body(f)}
                for f in rev.findings]
    try:
        client.post_review(n, commit_id, to_markdown(rev), comments)
        return "inline"
    except GitHubError as e:
        if e.status != 422 or not comments:          # 422: alguna línea no es comentable
            raise
    # Plan B: todo en un solo comentario general, con el detalle de cada hallazgo.
    client.post_review(n, commit_id, to_markdown(rev, details=True), [])
    return "resumen"
