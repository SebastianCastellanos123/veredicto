import json

import pytest

from veredicto.github import GitHubClient, GitHubError, publish
from veredicto.models import Finding, Review, Severity


class FakeHttp:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append({"method": method, "url": url, "headers": headers, "body": json.loads(body) if body else None})
        return self.responses.pop(0)


PR = json.dumps({"state": "open", "draft": False, "head": {"sha": "abc123", "repo": {"full_name": "yo/repo"}},
                 "base": {"repo": {"full_name": "yo/repo"}}}).encode()


def client(*responses):
    http = FakeHttp(*responses)
    return GitHubClient("tok-SECRETO", "yo/repo", http=http), http


def review_with_findings():
    f1 = Finding("seguridad", "app/a.py", 12, Severity.HIGH, "SQL", "Explicación", "Arreglo")
    f2 = Finding("calidad", "app/b.py", 3, Severity.LOW, "Print", "x", "")
    return Review(mode="simulado (reglas, sin IA)", verdict="changes", findings=[f1, f2], files_reviewed=2)


def test_pull_and_diff_requests():
    c, http = client((200, PR), (200, b"diff --git a/x b/x\n"))
    pr = c.pull(7)
    assert pr == {"state": "open", "draft": False, "sha": "abc123", "head_repo": "yo/repo", "base_repo": "yo/repo"}
    assert c.diff(7).startswith("diff --git")
    first, second = http.calls
    assert first["url"] == "https://api.github.com/repos/yo/repo/pulls/7" and first["headers"]["Authorization"] == "Bearer tok-SECRETO"
    assert second["headers"]["Accept"] == "application/vnd.github.v3.diff"


def test_review_is_always_a_plain_comment_never_approve_or_block():
    c, http = client((200, b"{}"))
    assert publish(c, 7, "abc123", review_with_findings()) == "inline"
    body = http.calls[0]["body"]
    assert body["event"] == "COMMENT" and body["commit_id"] == "abc123"
    assert body["comments"][0] == {"path": "app/a.py", "line": 12, "side": "RIGHT",
                                   "body": body["comments"][0]["body"]}
    assert "SQL" in body["comments"][0]["body"] and "Sugerencia" in body["comments"][0]["body"]
    assert "veredicto:review" in body["body"]


def test_falls_back_to_a_single_summary_when_a_line_is_not_commentable():
    c, http = client((422, b'{"message":"line must be part of the diff"}'), (200, b"{}"))
    assert publish(c, 7, "abc123", review_with_findings()) == "resumen"
    retry = http.calls[1]["body"]
    assert retry["comments"] == [] and "Explicación" in retry["body"] and "Arreglo" in retry["body"]   # el detalle viaja en el resumen


def test_other_errors_are_not_swallowed():
    c, _ = client((403, b"{}"))
    with pytest.raises(GitHubError, match="403"):
        publish(c, 7, "abc123", review_with_findings())
    c2, _ = client((422, b"{}"))
    with pytest.raises(GitHubError):                      # 422 sin comentarios que reintentar: se propaga
        publish(c2, 7, "abc123", Review(mode="m", verdict="ok"))


def test_input_validation_and_no_token_leaks():
    for bad in ("", "sin-barra", "a/b/c", "yo/repo; rm -rf", "../x/y", "yo/re po"):
        with pytest.raises(GitHubError):
            GitHubClient("t", bad)
    with pytest.raises(GitHubError, match="token"):
        GitHubClient("  ", "yo/repo")
    c, _ = client((500, b"boom"))
    for bad_pr in (0, -1, True, "7", None, 1.5):
        with pytest.raises(GitHubError):
            c.pull(bad_pr)                                # no se construye ninguna URL con valores raros
    with pytest.raises(GitHubError) as e:
        c.pull(7)
    assert "tok-SECRETO" not in str(e.value)


def test_huge_diff_and_weird_responses():
    c, _ = client((406, b"too big"), (200, b"no es json"))
    with pytest.raises(GitHubError, match="demasiado grande"):
        c.diff(1)
    with pytest.raises(GitHubError, match="inesperada"):
        c.pull(1)
