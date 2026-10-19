"""Estructuras de datos compartidas."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {0: "info", 1: "baja", 2: "media", 3: "alta", 4: "crítica"}[int(self)]

    @classmethod
    def parse(cls, value: object) -> "Severity | None":
        """Acepta nombres en inglés o español. Devuelve None si no se reconoce."""
        if not isinstance(value, str):
            return None
        table = {
            "info": cls.INFO, "informativa": cls.INFO,
            "low": cls.LOW, "baja": cls.LOW,
            "medium": cls.MEDIUM, "media": cls.MEDIUM,
            "high": cls.HIGH, "alta": cls.HIGH,
            "critical": cls.CRITICAL, "crítica": cls.CRITICAL, "critica": cls.CRITICAL,
        }
        return table.get(value.strip().lower())


@dataclass
class Finding:
    agent: str                 # id del subagente que lo encontró
    file: str
    line: int | None           # None = no se puede anclar a una línea del diff
    severity: Severity
    title: str
    explanation: str
    suggestion: str = ""


@dataclass
class Failure:
    agent: str
    reason: str


@dataclass
class Review:
    mode: str                                   # p. ej. "simulado (reglas, sin IA)" o "claude-..."
    verdict: str                                # nothing | ok | review | changes
    plan: dict[str, str] = field(default_factory=dict)       # agente → por qué se activó
    findings: list[Finding] = field(default_factory=list)    # anclados a una línea
    general: list[Finding] = field(default_factory=list)     # sin línea
    failures: list[Failure] = field(default_factory=list)
    skipped_files: dict[str, str] = field(default_factory=dict)   # ruta → motivo
    redactions: dict[str, int] = field(default_factory=dict)      # tipo de secreto → cantidad
    dropped: int = 0                            # hallazgos descartados por no ser verificables
    omitted: int = 0                            # hallazgos válidos que no cupieron en el límite
    files_reviewed: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    @property
    def all_findings(self) -> list[Finding]:
        return [*self.findings, *self.general]

    @property
    def max_severity(self) -> Severity | None:
        sev = [f.severity for f in self.all_findings]
        return max(sev) if sev else None
