from collections import Counter

from veredicto.redact import redact_line
from veredicto.sanitize import clean_text, one_line


# ---- secretos (se construyen en tiempo de ejecución para que el repo no contenga tokens con forma real) ----
def test_provider_tokens_are_redacted():
    cases = {
        "aws_access_key": "AKIA" + "A" * 16,
        "github_token": "ghp_" + "a1" * 20,
        "anthropic_key": "sk-ant-" + "x" * 30,
        "slack_token": "xoxb-" + "1234567890-abc",
        "jwt": "eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12,
        "private_key": "-----BEGIN RSA PRIVATE KEY-----",
    }
    for kind, secret in cases.items():
        counts = Counter()
        out = redact_line(f"valor = {secret} # fin", counts)
        assert secret not in out and f"[REDACTED:{kind}]" in out, kind
        assert counts[kind] == 1


def test_assignments_and_url_passwords():
    counts = Counter()
    out = redact_line('db_password = "hunter2hunter2"', counts)
    assert "hunter2" not in out and out.startswith('db_password = "[REDACTED:credencial]"')
    out = redact_line("postgres://admin:Sup3rSecret@host:5432/db", counts)
    assert "Sup3rSecret" not in out and "admin:[REDACTED:password_en_url]@host" in out
    assert redact_line('title = "hola mundo largo"') == 'title = "hola mundo largo"'     # no es un secreto


def test_no_double_counting_and_normal_code_untouched():
    counts = Counter()
    out = redact_line('api_key = "' + "AKIA" + "B" * 16 + '"', counts)
    assert sum(counts.values()) == 1 and "AKIA" not in out
    code = "def suma(a, b): return a + b  # la clave es opcional"
    assert redact_line(code) == code


# ---- limpieza de la salida del modelo ----
def test_mentions_are_neutralized():
    out = clean_text("Avisa a @octocat y a @org/equipo", 200)
    assert "@octocat" not in out and "@org" not in out and "octocat" in out


def test_urls_links_and_html_are_removed():
    out = clean_text('Mira [aquí](https://evil.example/x) o https://evil.example/y <img src=x onerror=1> <b>hola</b>', 300)
    assert "evil.example" not in out and "<" not in out and "onerror" not in out
    assert "[aquí]" in out and "hola" in out


def test_suggestion_blocks_are_neutralized():
    # Un bloque ```suggestion se convierte en un botón de "aplicar cambio" en GitHub.
    out = clean_text("Cambia así:\n```suggestion\nos.system(x)\n```", 300)
    assert "suggestion" not in out and "os.system(x)" in out
    assert "suggestion" not in clean_text("~~~suggestion\nx\n~~~", 100)


def test_control_chars_length_and_bad_types():
    assert clean_text("a\x00b\x1b[31mc\u202ed", 100) == "ab[31mcd"
    assert len(clean_text("x" * 5_000, 100)) <= 100
    assert clean_text(None, 10) == "" and clean_text(123, 10) == ""
    assert "\n" not in one_line("uno\ndos\r\ntres", 50)
