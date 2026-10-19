from collections import Counter

from veredicto.diff import is_doc, is_test, parse_diff, render_files, skip_reason

from conftest import make_diff


def test_parse_numbers_lines_and_kinds():
    d = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,3 +1,4 @@\n a\n-b\n+b2\n+b3\n c\n"
    (f,) = parse_diff(d)
    assert f.path == "x.py" and f.status == "modified"
    assert [(l.kind, l.new_no) for l in f.lines if l.kind != "hunk"] == [("ctx", 1), ("del", None), ("add", 2), ("add", 3), ("ctx", 4)]
    assert f.added == {2: "b2", 3: "b3"}
    assert set(f.right) == {1, 2, 3, 4}          # las eliminadas no se pueden comentar


def test_header_lookalikes_inside_a_hunk_do_not_create_files():
    d = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,1 +1,3 @@\n a\n+++ b/otro.py\n+diff --git a/falso b/falso\n"
    files = parse_diff(d)
    assert [f.path for f in files] == ["x.py"]
    assert files[0].added[2] == "++ b/otro.py"


def test_new_deleted_renamed_and_binary():
    d = (make_diff("nuevo.py", ["x = 1"]) +
         "diff --git a/viejo.py b/viejo.py\ndeleted file mode 100644\n--- a/viejo.py\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-x\n"
         "diff --git a/a.py b/b.py\nsimilarity index 90%\nrename from a.py\nrename to b.py\n"
         "diff --git a/i.png b/i.png\nBinary files a/i.png and b/i.png differ\n")
    f = {x.path: x for x in parse_diff(d)}
    assert f["nuevo.py"].status == "added"
    assert f["viejo.py"].status == "deleted"
    assert f["b.py"].status == "renamed" and f["b.py"].old_path == "a.py"
    assert f["i.png"].binary


def test_no_newline_marker_and_empty_context_lines():
    d = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,2 @@\n-a\n\\ No newline at end of file\n+b\n\n"
    (f,) = parse_diff(d)
    assert f.added == {1: "b"}
    assert f.right[2] == ""                     # línea de contexto vacía (algunos editores recortan el espacio)


def test_garbage_input_does_not_crash():
    assert parse_diff("") == []
    assert parse_diff("esto no es un diff\n@@ nada\n") == []
    assert parse_diff("\x00\x01 diff --git") == []


def test_skip_reasons():
    def reason(path, **kw):
        f = parse_diff(make_diff(path, ["x"]))[0]
        for k, v in kw.items():
            setattr(f, k, v)
        return skip_reason(f)
    assert reason("package-lock.json")
    assert reason("go.sum")
    assert reason("web/dist/app.js")
    assert reason("node_modules/x/index.js")
    assert reason("static/app.min.js")
    assert reason("logo.png")
    assert reason("app.py", binary=True)
    assert reason("app.py", status="deleted")
    assert reason("app/main.py") is None
    assert reason("Dockerfile") is None


def test_doc_and_test_detection():
    assert is_doc("README.md") and not is_doc("main.py")
    for p in ("tests/test_a.py", "src/a_test.go", "web/a.test.ts", "web/a.spec.js", "test_x.py", "pkg/__tests__/a.js"):
        assert is_test(p), p
    assert not is_test("src/contest.py") and not is_test("src/latest.js")


def test_render_has_line_numbers_and_hides_secrets():
    (f,) = parse_diff(make_diff("a.py", ["x = 1", 'API_KEY = "abcdefgh12345678"']))
    counts = Counter()
    text, included, too_big = render_files([f], 10_000, counts)
    assert "     1 | +x = 1" in text
    assert "abcdefgh12345678" not in text and "[REDACTED:credencial]" in text
    assert counts["credencial"] == 1 and included == ["a.py"] and too_big == []


def test_render_respects_size_limit_and_truncates_long_lines():
    big = parse_diff(make_diff("big.py", ["palabra " * 40] * 50))[0]
    small = parse_diff(make_diff("small.py", ["y = 1"]))[0]
    text, included, too_big = render_files([big, small], 2_000)
    assert too_big == ["big.py"] and included == ["small.py"] and len(text) <= 2_000
    minified = parse_diff(make_diff("m.js", ["var a=1;" * 600]))[0]
    assert len(render_files([minified], 10**6)[0]) < 1_000
