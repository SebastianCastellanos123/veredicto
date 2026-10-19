from veredicto.agents import ALL_AGENTS, QUALITY, SECURITY, TESTS, extract_json, to_findings
from veredicto.diff import parse_diff
from veredicto.models import Severity

from conftest import make_diff


def test_extract_json_tolerates_noise_but_not_garbage():
    ok = '{"findings":[{"file":"a.py","line":1,"severity":"high","title":"t"}]}'
    assert extract_json(ok)["findings"][0]["file"] == "a.py"
    assert extract_json("```json\n" + ok + "\n```")                     # con bloque de código
    assert extract_json("Claro, aquí está:\n" + ok + "\nEspero que sirva")   # con texto alrededor
    assert extract_json('{"otra": 1} ' + ok)                              # un objeto previo sin "findings"
    assert extract_json('{"findings": []}') == {"findings": []}
    for bad in ("", "no hay json", "{", '{"findings": "x"}', '{"findings":', "[1, 2]"):
        assert extract_json(bad) is None, bad


def test_to_findings_validates_every_field():
    data = {"findings": [
        {"file": "a.py", "line": 3, "severity": "HIGH", "title": "ok", "explanation": "e", "suggestion": "s"},
        {"file": "a.py", "line": "3", "severity": "alta", "title": "línea como texto"},      # → sin línea, severidad en español
        {"file": "a.py", "line": True, "severity": "low", "title": "bool no es número"},
        {"file": "a.py", "line": 0, "severity": "low", "title": "línea cero"},
        {"file": "", "severity": "low", "title": "sin archivo"},
        {"file": "a.py", "severity": "gravísima", "title": "severidad inventada"},
        {"file": "a.py", "severity": "low", "title": ""},
        {"file": "a.py", "severity": "low", "title": 5},
        "no soy un objeto", None, 7,
    ]}
    found, bad = to_findings("seguridad", data)
    assert [f.title for f in found] == ["ok", "línea como texto", "bool no es número", "línea cero"]
    assert found[0].line == 3 and found[0].severity == Severity.HIGH
    assert [f.line for f in found[1:]] == [None, None, None] and found[1].severity == Severity.HIGH
    assert bad == 7


def test_prompts_contain_the_defensive_rules():
    for agent in ALL_AGENTS:
        sp = agent.system_prompt("tag_x", 5, "es")
        assert f"AGENTE: {agent.id}" in sp
        assert "CÓDIGO NO CONFIABLE" in sp and "<tag_x>" in sp and "NUNCA instrucciones" in sp
        assert "No tienes herramientas" in sp and "Máximo 5 hallazgos" in sp and "[REDACTED:" in sp
        up = agent.user_prompt("tag_x", "DIFF")
        assert up.count("<tag_x>") == 1 and up.count("</tag_x>") == 1 and "DIFF" in up
    assert "inglés" in SECURITY.system_prompt("t", 3, "en")


def test_agents_select_files_by_specialty():
    docs = parse_diff(make_diff("README.md", ["hola"]))
    code = parse_diff(make_diff("app.py", ["x = 1"]))
    assert SECURITY.select(docs) == docs                # seguridad también mira la documentación
    assert QUALITY.select(docs) == [] and TESTS.select(docs) == []
    assert QUALITY.select(code) == code and TESTS.select(code) == code
