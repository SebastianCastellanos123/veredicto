"""Lectura de diffs unificados (formato de `git diff` y de la API de GitHub)."""
from __future__ import annotations

import fnmatch
import re
from collections import Counter
from dataclasses import dataclass, field

from .redact import redact_line

_HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
MAX_LINE_CHARS = 400          # líneas más largas (código minificado) se recortan


@dataclass
class DiffLine:
    kind: str                 # "add" | "ctx" | "del" | "hunk"
    new_no: int | None        # número de línea en el archivo NUEVO (None para "del" y "hunk")
    text: str


@dataclass
class FileDiff:
    path: str
    old_path: str | None = None
    status: str = "modified"  # added | modified | deleted | renamed
    binary: bool = False
    lines: list[DiffLine] = field(default_factory=list)

    @property
    def right(self) -> dict[int, str]:
        """Líneas visibles del lado nuevo (añadidas + contexto): son las únicas comentables."""
        return {l.new_no: l.text for l in self.lines if l.new_no is not None}

    @property
    def added(self) -> dict[int, str]:
        return {l.new_no: l.text for l in self.lines if l.kind == "add" and l.new_no is not None}


def _unquote(path: str) -> str:
    path = path.strip()
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        path = path[1:-1].encode("latin-1", "backslashreplace").decode("unicode_escape", "ignore")
    return path


def _strip_prefix(path: str, prefix: str) -> str:
    path = _unquote(path)
    return path[len(prefix):] if path.startswith(prefix) else path


def parse_diff(text: str) -> list[FileDiff]:
    """Convierte un diff unificado en archivos con líneas numeradas.

    Los encabezados (diff --git, ---, +++) solo se interpretan FUERA de un hunk: dentro
    de uno, toda línea empieza por '+', '-' o ' ', así que el contenido del PR no puede
    "inventar" un archivo nuevo escribiendo '+++ b/otro' en su código.
    """
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    new_no = 0
    remaining_old = remaining_new = 0
    in_hunk = False

    for raw in text.splitlines():
        if in_hunk and cur is not None:
            if raw.startswith("\\"):                       # "\ No newline at end of file"
                continue
            if remaining_old > 0 or remaining_new > 0:
                tag, body = (raw[:1], raw[1:]) if raw else (" ", "")
                if tag == "+":
                    cur.lines.append(DiffLine("add", new_no, body)); new_no += 1; remaining_new -= 1
                elif tag == "-":
                    cur.lines.append(DiffLine("del", None, body)); remaining_old -= 1
                else:                                       # contexto (' ' o línea vacía)
                    cur.lines.append(DiffLine("ctx", new_no, body)); new_no += 1
                    remaining_old -= 1; remaining_new -= 1
                continue
            in_hunk = False                                 # el hunk terminó; sigue un encabezado

        if raw.startswith("diff --git "):
            cur = FileDiff(path="")
            files.append(cur)
            rest = raw[len("diff --git "):]
            # Rutas "a/x b/x": se toma la mitad derecha como ruta provisional.
            half = rest.rsplit(" b/", 1)
            cur.path = _unquote(half[1]) if len(half) == 2 else _strip_prefix(rest, "b/")
            continue
        if cur is None:
            continue
        if raw.startswith("new file mode"):
            cur.status = "added"
        elif raw.startswith("deleted file mode"):
            cur.status = "deleted"
        elif raw.startswith("rename from "):
            cur.status, cur.old_path = "renamed", _unquote(raw[len("rename from "):])
        elif raw.startswith("rename to "):
            cur.path = _unquote(raw[len("rename to "):])
        elif raw.startswith("Binary files ") or raw.startswith("GIT binary patch"):
            cur.binary = True
        elif raw.startswith("--- "):
            target = raw[4:].strip()
            if target != "/dev/null":
                cur.old_path = cur.old_path or _strip_prefix(target, "a/")
        elif raw.startswith("+++ "):
            target = raw[4:].strip()
            if target != "/dev/null":
                cur.path = _strip_prefix(target, "b/")
        else:
            m = _HUNK.match(raw)
            if m:
                new_no = int(m.group(2))
                nums = re.match(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", raw)
                remaining_old = int(nums.group(1)) if nums and nums.group(1) is not None else 1
                remaining_new = int(nums.group(2)) if nums and nums.group(2) is not None else 1
                cur.lines.append(DiffLine("hunk", None, raw))
                in_hunk = remaining_old > 0 or remaining_new > 0

    return [f for f in files if f.path]


# ---- qué archivos vale la pena revisar ------------------------------------------

_SKIP_PATTERNS = [
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "Cargo.lock",
    "Pipfile.lock", "composer.lock", "*.min.js", "*.min.css", "*.map", "*.svg", "*.pb.go",
    "*_generated.*", "*.generated.*", "*.snap",
]
_SKIP_DIRS = ("node_modules/", "vendor/", "dist/", "build/", ".git/", "__pycache__/")
_BINARY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
               ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".exe", ".dll", ".so", ".jar")
DOC_EXT = (".md", ".rst", ".txt", ".adoc")
_TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec)/|(_test\.|\.test\.|\.spec\.|(^|/)test_)")


def skip_reason(f: FileDiff) -> str | None:
    """Motivo por el que NO se revisa un archivo (None = sí se revisa)."""
    p = f.path.lower()
    if f.binary or p.endswith(_BINARY_EXT):
        return "archivo binario"
    if f.status == "deleted":
        return "archivo eliminado"
    if any(d in "/" + p for d in ("/" + x for x in _SKIP_DIRS)):
        return "directorio de dependencias o compilados"
    base = p.rsplit("/", 1)[-1]
    if any(fnmatch.fnmatch(base, pat.lower()) for pat in _SKIP_PATTERNS):
        return "archivo generado o de bloqueo de dependencias"
    return None


def is_doc(path: str) -> bool:
    return path.lower().endswith(DOC_EXT)


def is_test(path: str) -> bool:
    return bool(_TEST_RE.search(path.lower()))


# ---- texto que se entrega a los subagentes ---------------------------------------

def render_files(files: list[FileDiff], max_chars: int, counts: Counter | None = None
                 ) -> tuple[str, list[str], list[str]]:
    """Genera el texto del diff para el modelo, con números de línea y secretos ocultos.

    Devuelve (texto, rutas incluidas, rutas que no cupieron por el límite de tamaño).
    """
    parts: list[str] = []
    included: list[str] = []
    too_big: list[str] = []
    used = 0
    for f in files:
        block = [f"=== ARCHIVO: {f.path} ({f.status}) ==="]
        for l in f.lines:
            if l.kind == "hunk":
                block.append(l.text[:120])
                continue
            text = redact_line(l.text[:MAX_LINE_CHARS], counts)
            if l.kind == "del":
                block.append(f"{'':>6} | -{text}")
            else:
                block.append(f"{l.new_no:>6} | {'+' if l.kind == 'add' else ' '}{text}")
        chunk = "\n".join(block) + "\n"
        if used + len(chunk) > max_chars:
            too_big.append(f.path)
            continue
        parts.append(chunk)
        included.append(f.path)
        used += len(chunk)
    return "".join(parts), included, too_big
