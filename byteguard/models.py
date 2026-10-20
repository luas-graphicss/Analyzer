from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any

ENGINE_VERSION = "3.2.0"
REPORT_SCHEMA_VERSION = 3

class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

SEVERITY_WEIGHTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 35,
    Severity.CRITICAL: 80,
}

RISK_LEVELS = {"no_significant_indicators": 0, "low": 1, "moderate": 2, "high": 3, "critical": 4}

@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    severity: Severity
    title: str
    description: str
    location: str
    evidence: tuple[str, ...] = ()
    confidence: float = 0.75
    offset: int | None = None

@dataclass(frozen=True, slots=True)
class FileContext:
    name: str
    kind: str
    size: int
    head: bytes
    entropy: float
    hashes: dict[str, str]
    complete: bool

@dataclass(slots=True)
class FileReport:
    name: str
    kind: str
    size: int
    bytes_scanned: int = 0
    entropy: float = 0.0
    hashes: dict[str, str] = field(default_factory=dict)
    complete: bool = True
    findings: list[Finding] = field(default_factory=list)
    children: list["FileReport"] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    indicators: list[dict[str, Any]] = field(default_factory=list)

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def mark_incomplete(self, reason: str) -> None:
        self.complete = False
        if reason not in self.errors:
            self.errors.append(reason)

@dataclass(frozen=True, slots=True)
class AnalysisReport:
    root: FileReport
    started_at: str
    duration_seconds: float
    bytes_scanned: int
    engine_version: str = ENGINE_VERSION

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(finding for node in self.root.walk() for finding in node.findings)

    @property
    def complete(self) -> bool:
        return all(node.complete for node in self.root.walk())

    @property
    def score(self) -> int:
        weights: dict[str, int] = {}
        for finding in self.findings:
            weights[finding.rule_id] = max(
                weights.get(finding.rule_id, 0), SEVERITY_WEIGHTS[finding.severity]
            )
        return min(100, sum(weights.values()))

    @property
    def risk(self) -> str:
        for minimum, level in ((80, "critical"), (35, "high"), (15, "moderate"), (1, "low")):
            if self.score >= minimum:
                return level
        return "no_significant_indicators" if self.complete else "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "engine": "ByteGuard",
            "engine_version": self.engine_version,
            "analysis_type": "static_offline",
            "started_at": self.started_at,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "risk": self.risk,
                "heuristic_score": self.score,
                "complete": self.complete,
                "files_scanned": sum(1 for _ in self.root.walk()),
                "bytes_scanned": self.bytes_scanned,
                "finding_count": len(self.findings),
            },
            "coverage": {
                "fully_read_files": sum(
                    node.metadata.get("bytes_complete", False) is True for node in self.root.walk()
                ),
                "incomplete_files": sum(not node.complete for node in self.root.walk()),
                "files_with_hashes": sum(bool(node.hashes) for node in self.root.walk()),
                "indicator_count": sum(len(node.indicators) for node in self.root.walk()),
                "scope": "supported_static_checks_only",
                "establishes_safety": False,
            },
            "severity_counts": {
                severity.value: sum(finding.severity == severity for finding in self.findings)
                for severity in Severity
            },
            "schema_version": REPORT_SCHEMA_VERSION,
            "limitations": [
                "Ausência de alertas não comprova que um arquivo é legítimo ou seguro.",
                "A pontuação é heurística: não é probabilidade nem um veredito definitivo de malware.",
                "Os arquivos analisados nunca são executados, modificados, colocados em quarentena ou enviados à rede.",
                "SHA-256 identifica conteúdo; só comprova integridade quando comparado com uma referência confiável.",
                "MD5, SHA-1 e CRC32 servem apenas para identificação e compatibilidade, não para confiança criptográfica.",
                "Uma assinatura válida não garante segurança; certificados roubados e software assinado malicioso existem.",
                "Authenticode usa WinVerifyTrust no Windows, sem rede. Revogação atual, catálogos e assinaturas secundárias não são garantidos.",
                "A comparação portátil do digest Authenticode cobre layouts PE canônicos; não autentica certificados, atributos assinados, carimbos de tempo nem o editor.",
                "Checksum PE é uma soma de integridade, não uma garantia criptográfica. Recursos, importações adiadas e callbacks TLS são lidos sem executar código.",
                "PDF recebe leitura limitada de objetos, strings e filtros Flate, ASCIIHex, ASCII85 e RunLength; xref, renderização e todos os filtros/preditores não são interpretados.",
                "Office XML recebe leitura de relacionamentos, campos DDE e indicadores XLM; macros VBA/OLE e bytecode não são integralmente descompilados.",
                "DTD e entidades XML são recusadas; templates, hyperlinks e demais referências externas nunca são seguidos.",
                "Atalhos LNK recebem inspeção limitada de cabeçalho, LinkInfo, StringData e blocos conhecidos; Shell IDLists e extensões não interpretadas deixam a cobertura parcial. Destinos, ícones e variáveis de ambiente nunca são resolvidos.",
                "PYZ é lido por um parser restrito de metadados; objetos de código nunca são desserializados ou executados.",
                "Conteúdo criptografado, empacotadores não suportados, limites atingidos e ameaças inéditas reduzem a cobertura.",
                "CLI e desktop isolam a análise em processo com prazo rígido; a API ScanEngine tem limites cooperativos e não substitui uma sandbox do sistema.",
            ],
            "file": asdict(self.root),
        }
