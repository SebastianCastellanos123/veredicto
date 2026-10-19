import json
import threading
from pathlib import Path

import pytest

from veredicto.llm import LLMResult

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def sample_diff() -> str:
    return (ROOT / "testdata" / "sample.diff").read_text(encoding="utf-8")


def make_diff(path: str, lines: list[str], status: str = "added") -> str:
    """Construye un diff mínimo de un archivo nuevo con las líneas dadas."""
    body = "\n".join("+" + l for l in lines)
    header = f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1,{len(lines)} @@\n"
    return header + body + "\n"


class ScriptedLLM:
    """Modelo de pruebas: cada agente responde lo que el test indique. Registra todos los prompts."""

    name = "scripted"

    def __init__(self, replies: dict | None = None, default: str | None = None):
        self.replies = replies or {}
        self.default = default if default is not None else json.dumps({"findings": []})
        self.calls: list[tuple[str, str, str]] = []     # (agente, system, user)
        self._lock = threading.Lock()

    def complete(self, system: str, user: str, *, max_tokens: int) -> LLMResult:
        agent = system.split("AGENTE: ")[1].split("\n")[0]
        with self._lock:
            self.calls.append((agent, system, user))
        reply = self.replies.get(agent, self.default)
        if isinstance(reply, Exception):
            raise reply
        if callable(reply):
            reply = reply()
        if isinstance(reply, dict):
            reply = json.dumps(reply)
        return LLMResult(reply, input_tokens=100, output_tokens=20)


def finding(file="a.py", line=1, severity="high", title="Hallazgo", explanation="x", suggestion="y"):
    return {"file": file, "line": line, "severity": severity, "title": title,
            "explanation": explanation, "suggestion": suggestion}
