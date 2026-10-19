"""Modelo SIMULADO: reglas que imitan a un revisor, sin inteligencia artificial.

Recibe EXACTAMENTE los mismos prompts que recibiría Claude y devuelve el mismo JSON. Así
se prueba todo el sistema (prompts, parseo, validación, orquestación, publicación) sin
red, sin clave y sin costo. Es honesto en el informe: siempre se muestra como "simulado".

No pretende igualar a un modelo real: solo detecta patrones conocidos.
"""
from __future__ import annotations

import json
import re

from .diff import is_test
from .llm import LLMResult

_FILE_HDR = re.compile(r"^=== ARCHIVO: (.+) \((\w+)\) ===$")
_LINE = re.compile(r"^\s*(\d+) \| ([+ ])(.*)$")
_TAG = re.compile(r"<(diff_no_confiable_[0-9a-f]+)>")
_AGENT = re.compile(r"^AGENTE: (\w+)$", re.M)
_MAX = re.compile(r"Máximo (\d+) hallazgos")
_CODE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs", ".c", ".cpp")
_FUNC = re.compile(r"^\s*(?:def |function |func |(?:public|private|protected|static)\s+[\w<>\[\]]+\s+\w+\s*\()")

# (regex, severidad, título, explicación, sugerencia)
_SECURITY = [
    (re.compile(r"\[REDACTED:(\w+)\]"), "critical", "Credencial o secreto en el código",
     "Hay un secreto real escrito en el código (tipo detectado: {0}). Quien tenga acceso al repositorio o a su historial podría usarlo.",
     "Quítalo del código, rótalo (genera uno nuevo) y léelo desde una variable de entorno o un gestor de secretos."),
    (re.compile(r"(?i)(ignor(?:a|e)\b.{0,40}(?:instrucciones|instructions)|ignore (?:all )?(?:previous|prior) instructions|aprueba (?:este|el) (?:pr|cambio|c[oó]digo)|approve this (?:pr|change)|no reportes|do not report)"),
     "high", "Texto que intenta manipular la revisión automática",
     "Este texto está dirigido a un revisor automático (prompt injection). Un cambio legítimo no necesita pedirle a un revisor que ignore reglas o apruebe.",
     "Elimina el texto y revisa con cuidado el resto del cambio y a su autor."),
    (re.compile(r"(?i)\b(?:execute|executemany|query|raw)\s*\(.*(?:\bf[\"']|[\"']\s*\+|[\"']\s*%\s*|\.format\()"),
     "high", "Posible inyección SQL",
     "La consulta se construye uniendo texto con datos externos. Un valor malicioso podría cambiar el significado de la consulta.",
     "Usa consultas parametrizadas: pasa los valores como parámetros (por ejemplo, `execute(sql, (valor,))`), nunca dentro del texto SQL."),
    (re.compile(r"shell\s*=\s*True"), "high", "Ejecución de comandos con shell=True",
     "Con shell=True, el texto se interpreta por el shell. Si incluye datos del usuario, permite inyectar comandos.",
     "Pasa una lista de argumentos y shell=False, y valida cualquier dato externo."),
    (re.compile(r"\b(?:eval|exec)\s*\("), "high", "Uso de eval/exec",
     "Ejecutar texto como código es muy peligroso si algún fragmento viene de fuera.",
     "Evita eval/exec; usa estructuras de datos o un parser seguro (por ejemplo, json.loads o ast.literal_eval)."),
    (re.compile(r"\bpickle\.loads?\s*\("), "high", "Deserialización insegura con pickle",
     "Deserializar datos no confiables con pickle permite ejecutar código arbitrario.",
     "Usa un formato de datos como JSON, o firma y valida los datos antes de deserializar."),
    (re.compile(r"\byaml\.load\s*\((?!.*Loader)"), "medium", "yaml.load sin Loader seguro",
     "yaml.load sin un Loader seguro puede construir objetos arbitrarios.", "Usa yaml.safe_load."),
    (re.compile(r"(?i)hashlib\.(?:md5|sha1)\s*\(|createHash\(['\"](?:md5|sha1)['\"]\)"), "medium",
     "Algoritmo de hash débil",
     "MD5 y SHA-1 se consideran rotos. Si se usan para contraseñas o firmas, no ofrecen protección real.",
     "Para contraseñas usa bcrypt, scrypt o argon2; para integridad, SHA-256 o superior."),
    (re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"), "medium",
     "Verificación de certificados TLS desactivada",
     "Sin verificar el certificado, la conexión es vulnerable a interceptación (man-in-the-middle).",
     "Deja la verificación activada y, si hace falta, configura la autoridad certificadora correcta."),
    (re.compile(r"chmod\s+(?:-R\s+)?777"), "medium", "Permisos 777",
     "Dar permisos de lectura, escritura y ejecución a todos facilita que otro proceso modifique el archivo.",
     "Usa los permisos mínimos necesarios (por ejemplo 640 o 750)."),
    (re.compile(r"(?i)access-control-allow-origin['\":\s]+\*|origins?\s*=\s*\[?[\"']\*[\"']"), "medium",
     "CORS abierto a cualquier origen",
     "Permitir cualquier origen deja que cualquier sitio web consuma esta API desde el navegador de un usuario.",
     "Permite solo los orígenes que realmente necesitas."),
    (re.compile(r"\bDEBUG\s*=\s*True"), "low", "Modo DEBUG activado",
     "El modo debug en producción expone detalles internos de la aplicación.", "Léelo de una variable de entorno y déjalo apagado por defecto."),
    (re.compile(r"pull_request_target"), "medium", "Workflow con pull_request_target",
     "pull_request_target corre con permisos de escritura y secretos. Si ejecuta código del PR, un atacante podría robarlos.",
     "Usa pull_request, o no ejecutes nunca código del PR en ese contexto."),
    (re.compile(r"(?i)curl\s[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh"), "high", "Descarga y ejecución directa de un script",
     "Ejecutar un script descargado sin revisarlo permite que quien controle el servidor ejecute código en tu entorno.",
     "Descarga el archivo, verifica su hash o firma y luego ejecútalo."),
]
_QUALITY = [
    (re.compile(r"^\s*except\s*:"), "medium", "except sin tipo de excepción",
     "Captura absolutamente todo, incluso errores que no deberías ocultar (como Ctrl+C), y dificulta depurar.",
     "Captura excepciones concretas (por ejemplo `except ValueError:`) y registra o relanza el error."),
    (re.compile(r"catch\s*\(\s*\w*\s*\)\s*\{\s*\}"), "medium", "Bloque catch vacío",
     "Un error se descarta en silencio y nadie se entera de que falló.", "Registra el error o relánzalo."),
    (re.compile(r"def\s+\w+\(.*=\s*(?:\[\]|\{\})"), "medium", "Argumento por defecto mutable",
     "El valor por defecto se crea una sola vez y se comparte entre llamadas, causando errores difíciles de ver.",
     "Usa `None` como valor por defecto y crea la lista o el diccionario dentro de la función."),
    (re.compile(r"\bprint\(|console\.log\(|fmt\.Println\("), "low", "Salida de depuración",
     "Parece una impresión de depuración olvidada.", "Usa el sistema de logging del proyecto o elimínala."),
    (re.compile(r"(?i)\b(?:TODO|FIXME|XXX)\b"), "info", "Tarea pendiente en el código",
     "Hay una marca de pendiente que puede quedar olvidada.", "Conviértela en un issue con responsable, o resuélvela en este cambio."),
]
_TEST_SKIP = re.compile(r"@pytest\.mark\.skip|\.skip\(|\bt\.Skip\(|@Ignore|\bxit\(|\bxdescribe\(|@unittest\.skip")
_TEST_VACUOUS = re.compile(r"\bassert\s+True\b|assertTrue\(\s*True\s*\)|expect\(true\)\.toBe\(true\)")


def _parse(user: str) -> dict[str, list[tuple[int, str, str]]]:
    """Reconstruye {archivo: [(línea, '+'|' ', texto)]} a partir del prompt (como lo haría un modelo)."""
    m = _TAG.search(user)
    if not m:
        return {}
    tag = m.group(1)
    start = user.index(f"<{tag}>") + len(tag) + 2
    end = user.rindex(f"</{tag}>")
    files: dict[str, list[tuple[int, str, str]]] = {}
    cur = None
    for raw in user[start:end].splitlines():
        h = _FILE_HDR.match(raw)
        if h:
            cur = files.setdefault(h.group(1), [])
            continue
        l = _LINE.match(raw)
        if l and cur is not None:
            cur.append((int(l.group(1)), l.group(2), l.group(3)))
    return files


class HeuristicLLM:
    name = "simulado (reglas, sin IA)"

    def complete(self, system: str, user: str, *, max_tokens: int) -> LLMResult:
        agent = (_AGENT.search(system) or [None, ""])[1]
        limit = int((_MAX.search(system) or [None, "8"])[1])
        files = _parse(user)
        findings = {"seguridad": self._security, "calidad": self._quality, "pruebas": self._tests}.get(agent, lambda f: [])(files)
        return LLMResult(json.dumps({"findings": findings[:limit]}, ensure_ascii=False))

    # ---- reglas por agente ----
    @staticmethod
    def _apply(rules, files):
        out = []
        for path, lines in files.items():
            for no, mark, text in lines:
                if mark != "+":
                    continue
                for rx, sev, title, expl, sugg in rules:
                    m = rx.search(text)
                    if m:
                        out.append({"file": path, "line": no, "severity": sev, "title": title,
                                    "explanation": expl.format(*m.groups()) if m.groups() else expl, "suggestion": sugg})
        return out

    def _security(self, files):
        return self._apply(_SECURITY, files)

    def _quality(self, files):
        out = self._apply(_QUALITY, files)
        for path, lines in files.items():           # funciones largas (≥ 50 líneas añadidas)
            starts = [i for i, (_, mk, tx) in enumerate(lines) if mk == "+" and _FUNC.match(tx)]
            for k, i in enumerate(starts):
                j = starts[k + 1] if k + 1 < len(starts) else len(lines)
                size = sum(1 for _, mk, _t in lines[i:j] if mk == "+")
                if size >= 50:
                    out.append({"file": path, "line": lines[i][0], "severity": "low", "title": "Función muy larga",
                                "explanation": f"Esta función añade unas {size} líneas. Las funciones largas son más difíciles de entender y de probar.",
                                "suggestion": "Divídela en funciones más pequeñas con un propósito claro."})
        return out

    def _tests(self, files):
        out = []
        has_tests = any(is_test(p) for p in files)
        for path, lines in files.items():
            if is_test(path):
                for no, mk, tx in lines:
                    if mk != "+":
                        continue
                    if _TEST_SKIP.search(tx):
                        out.append({"file": path, "line": no, "severity": "low", "title": "Prueba desactivada",
                                    "explanation": "Hay una prueba omitida (skip). Si nadie la reactiva, la cobertura baja sin que se note.",
                                    "suggestion": "Arréglala o elimínala, o deja un issue con responsable y fecha."})
                    elif _TEST_VACUOUS.search(tx):
                        out.append({"file": path, "line": no, "severity": "low", "title": "Prueba que no verifica nada",
                                    "explanation": "Esta aserción siempre es verdadera: la prueba pasa aunque el código esté roto.",
                                    "suggestion": "Verifica un resultado real del código bajo prueba."})
        if not has_tests:
            for path, lines in files.items():
                if path.lower().endswith(_CODE_EXT):
                    first = next(((no, tx) for no, mk, tx in lines if mk == "+" and _FUNC.match(tx)), None)
                    if first:
                        out.append({"file": path, "line": first[0], "severity": "medium", "title": "Cambios de lógica sin pruebas",
                                    "explanation": "El PR agrega funciones nuevas pero no incluye ninguna prueba. Sin pruebas, un cambio futuro puede romper esto sin que nadie lo note.",
                                    "suggestion": "Agrega pruebas que cubran el caso normal y los casos límite (entradas vacías, inválidas o maliciosas)."})
                        break
        return out
