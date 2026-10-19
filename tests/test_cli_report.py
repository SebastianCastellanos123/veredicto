import json

import pytest

from veredicto import cli
from veredicto.fake import HeuristicLLM
from veredicto.github import GitHubError
from veredicto.llm import AnthropicLLM
from veredicto.models import Failure, Finding, Review, Severity
from veredicto.orchestrator import review
from veredicto.report import to_json, to_markdown, to_text

from conftest import ROOT

SAMPLE = str(ROOT / "testdata" / "sample.diff")


# ---------- informes ----------
def test_markdown_report_structure(sample_diff):
    md = to_markdown(review(sample_diff, HeuristicLLM()))
    assert md.startswith("<!-- veredicto:review -->") and "## Veredicto: Se recomiendan cambios" in md
    assert "Modo: **simulado**" in md and "| Severidad | Área | Ubicación | Hallazgo |" in md
    assert "no sustituye a una revisión humana" in md and "Se ocultaron 2 posibles secretos" in md
    assert "SuperSecret123" not in md and "a1b2c3d4e5f6g7h8" not in md
    assert "package-lock.json" in md


def test_report_never_breaks_table_or_injects_html_from_titles():
    f = Finding("seguridad", "a|b`c.py", 1, Severity.HIGH, "titulo | con <b>barra</b>\ny salto", "e", "")
    md = to_markdown(Review(mode="m", verdict="changes", findings=[f]))
    row = [l for l in md.splitlines() if l.startswith("| alta")][0]
    assert row.count("|") - row.count("\\|") == 5 and "\n" not in row


def test_failures_and_partial_results_are_reported():
    rev = Review(mode="claude-x", verdict="incomplete", failures=[Failure("seguridad", "TimeoutError")], plan={"seguridad": "x"})
    txt, md = to_text(rev), to_markdown(rev)
    assert "Revisión incompleta" in md and "esa parte NO se revisó" in md and "NO se revisó" in txt
    assert "modelo de lenguaje `claude-x`" in md


def test_json_report_is_valid(sample_diff):
    data = json.loads(to_json(review(sample_diff, HeuristicLLM())))
    assert data["verdict"] == "changes" and data["findings"] and set(data["plan"]) == {"seguridad", "calidad", "pruebas"}
    assert {"agent", "file", "line", "severity", "title"} <= set(data["findings"][0])


# ---------- línea de comandos ----------
def test_review_command_formats_and_exit_codes(capsys):
    assert cli.main(["review", "--llm", "mock", "--diff", SAMPLE, "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "changes"
    assert cli.main(["review", "--llm", "mock", "--diff", SAMPLE, "--fail-on", "critical"]) == 2
    assert cli.main(["review", "--llm", "mock", "--diff", SAMPLE, "--fail-on", "none"]) == 0
    capsys.readouterr()
    assert cli.main(["review", "--llm", "mock", "--diff", SAMPLE, "--format", "markdown"]) == 0
    assert "## Veredicto" in capsys.readouterr().out


def test_review_from_stdin(monkeypatch, capsys):
    import io, sys
    class FakeStdin:
        buffer = io.BytesIO(open(SAMPLE, "rb").read())
    monkeypatch.setattr(sys, "stdin", FakeStdin)
    assert cli.main(["review", "--llm", "mock", "--diff", "-", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["findings"]


def test_a_clean_diff_exits_zero_even_with_fail_on(tmp_path, capsys):
    p = tmp_path / "ok.diff"
    p.write_text("diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1,1 +1,2 @@\n # Hola\n+Más texto\n")
    assert cli.main(["review", "--llm", "mock", "--diff", str(p), "--fail-on", "medium"]) == 0
    assert "Sin hallazgos relevantes" in capsys.readouterr().out


def test_llm_selection(monkeypatch, capsys):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert isinstance(cli._make_llm("auto", None), HeuristicLLM)
    assert "SIMULADO" in capsys.readouterr().err                      # avisa en voz alta que no es IA
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-123")
    llm = cli._make_llm("auto", "modelo-x")
    assert isinstance(llm, AnthropicLLM) and llm.model == "modelo-x"
    assert isinstance(cli._make_llm("mock", None), HeuristicLLM)
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(Exception, match="clave"):
        cli._make_llm("anthropic", None)


def test_git_range_rejects_option_injection(capsys):
    for bad in ("--output=/tmp/x", "-p", "a;rm -rf /", "a b", "$(whoami)", "`id`"):
        with pytest.raises(SystemExit):
            cli.main(["review", "--llm", "mock", "--git-range", bad])


def test_git_range_reviews_real_changes(tmp_path, monkeypatch, capsys):
    import subprocess
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True, capture_output=True)
    run("git", "init", "-q", "-b", "main"); run("git", "config", "user.email", "a@b.c"); run("git", "config", "user.name", "t")
    (tmp_path / "a.py").write_text("x = 1\n"); run("git", "add", "."); run("git", "commit", "-qm", "base")
    (tmp_path / "a.py").write_text("x = 1\nresult = eval(input())\n"); run("git", "commit", "-qam", "cambio")
    monkeypatch.chdir(tmp_path)
    assert cli.main(["review", "--llm", "mock", "--git-range", "HEAD~1..HEAD", "--format", "json", "--fail-on", "high"]) == 2
    assert any(f["title"] == "Uso de eval/exec" for f in json.loads(capsys.readouterr().out)["findings"])


def test_missing_file_and_oversized_diff(tmp_path):
    assert cli.main(["review", "--llm", "mock", "--diff", str(tmp_path / "no-existe.diff")]) == 1


# ---------- comando github (con un cliente falso) ----------
class FakeClient:
    pr = {"state": "open", "draft": False, "sha": "abc", "head_repo": "yo/r", "base_repo": "yo/r"}
    posted: list = []

    def __init__(self, token, repo):
        if not token:
            raise GitHubError("falta el token de GitHub (variable GITHUB_TOKEN)")

    def pull(self, n): return dict(self.pr)
    def diff(self, n): return open(SAMPLE, encoding="utf-8").read()
    def post_review(self, n, commit_id, body, comments): FakeClient.posted.append((n, commit_id, body, comments))


@pytest.fixture
def gh(monkeypatch):
    monkeypatch.setattr(cli, "GitHubClient", FakeClient)
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    FakeClient.posted = []
    FakeClient.pr = {"state": "open", "draft": False, "sha": "abc", "head_repo": "yo/r", "base_repo": "yo/r"}


def test_github_publishes_a_review(gh, capsys):
    assert cli.main(["github", "--repo", "yo/r", "--pr", "5", "--llm", "mock"]) == 0
    (n, sha, body, comments), = FakeClient.posted
    assert (n, sha) == (5, "abc") and comments and all(c["side"] == "RIGHT" for c in comments)
    assert "Revisión publicada" in capsys.readouterr().out


@pytest.mark.parametrize("override,msg", [({"state": "closed"}, "no está abierto"), ({"draft": True}, "borrador"),
                                           ({"head_repo": "otro/fork"}, "fork")])
def test_github_skips_closed_draft_and_fork_prs(gh, capsys, override, msg):
    FakeClient.pr.update(override)
    assert cli.main(["github", "--repo", "yo/r", "--pr", "5", "--llm", "mock"]) == 0
    assert msg in capsys.readouterr().out and FakeClient.posted == []         # no se publica nada


def test_github_dry_run_and_missing_token(gh, monkeypatch, capsys):
    assert cli.main(["github", "--repo", "yo/r", "--pr", "5", "--llm", "mock", "--dry-run"]) == 0
    assert FakeClient.posted == [] and "## Veredicto" in capsys.readouterr().out
    monkeypatch.delenv("GITHUB_TOKEN")
    assert cli.main(["github", "--repo", "yo/r", "--pr", "5", "--llm", "mock"]) == 1
    assert "GITHUB_TOKEN" in capsys.readouterr().err
