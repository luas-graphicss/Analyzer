import json
import os
import stat
import unicodedata
from pathlib import Path

from .engine import SHA256_PATTERN
from .models import SEVERITY_WEIGHTS, AnalysisReport
from .policy import ScanError

def safe_text(value: str) -> str:
    return "".join(
        f"\\u{ord(character):04x}" if unicodedata.category(character).startswith("C") else character
        for character in value
    )

def render_json(report: AnalysisReport) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True, allow_nan=False) + "\n"

RISK_LABELS = {
    "no_significant_indicators": "Sem indicadores significativos",
    "unknown": "Indeterminado",
    "low": "Baixo",
    "moderate": "Moderado",
    "high": "Alto",
    "critical": "Crítico",
}

def render_text(report: AnalysisReport) -> str:
    nodes = list(report.root.walk())
    lines = [
        f"ByteGuard {report.engine_version} | Análise estática offline",
        f"Arquivo: {safe_text(report.root.name)}",
        f"Formato pelos bytes: {report.root.kind}",
        f"Tamanho: {report.root.size:,} bytes",
        f"Risco: {RISK_LABELS[report.risk]} | Pontuação heurística: {report.score}/100",
        f"Cobertura: {'COMPLETA NOS TESTES SUPORTADOS' if report.complete else 'INCOMPLETA — consulte os avisos'}",
        f"Arquivos/payloads analisados: {len(nodes)}",
        f"Bytes analisados: {report.bytes_scanned:,} | Duração: {report.duration_seconds:.4f}s",
        f"Entropia global: {report.root.entropy:.4f} bits/byte",
        "",
        "IDENTIDADE E INTEGRIDADE",
    ]
    for algorithm, digest in report.root.hashes.items():
        lines.append(f"{algorithm.upper()}: {digest}")
    if not report.root.hashes:
        lines.append(
            "Hashes indisponíveis: não foi confirmada a leitura integral de um arquivo estável."
        )
    comparison = report.root.metadata.get("hash_comparison")
    if comparison:
        lines.append(
            f"Comparação SHA-256: {comparison['status']} | Referência: {comparison['expected_sha256']}"
        )
    lines.append("Hashes iguais comprovam igualdade de conteúdo com a referência, não segurança.")
    profile = report.root.metadata.get("byte_profile", {})
    if profile:
        lines.extend(
            (
                "",
                "PERFIL DE BYTES",
                f"Bytes nulos: {profile['null_bytes']:,} | Maior sequência nula: {profile['longest_null_run']:,}",
                f"Valores distintos: {profile['unique_byte_values']}/256 | Blocos de entropia: {profile['entropy_blocks_scanned']}",
                f"Primeiros 64 bytes: {profile['first_64_bytes_hex']}",
                f"Últimos 64 bytes: {profile['last_64_bytes_hex']}",
            )
        )
    lines.extend(("", "ESTRUTURA E CONTEÚDOS INTERNOS"))
    for node in nodes:
        lines.append(
            f"- {safe_text(node.name)} | {node.kind} | {node.bytes_scanned:,}/{node.size:,} bytes | {'cobertura concluída' if node.complete else 'cobertura parcial'}"
        )
        if node is not report.root and node.hashes:
            lines.append(f"  SHA256: {node.hashes['sha256']}")
        signature = node.metadata.get("authenticode")
        if signature:
            lines.append(
                f"  Authenticode: {signature['status']} | Provedor: {signature.get('backend') or 'não disponível'}"
            )
            if signature.get("reason"):
                lines.append(f"  {safe_text(signature['reason'])}")
            for record in signature.get("records", []):
                integrity = record.get("content_digest", {})
                if integrity:
                    lines.append(
                        f"  Digest da imagem ({integrity.get('algorithm', 'não identificado')}): {integrity['status']}; coincidência não autentica o signatário."
                    )
                    if integrity.get("calculated_digest"):
                        lines.append(f"    Calculado: {integrity['calculated_digest']}")
                    if integrity.get("declared_digest"):
                        lines.append(f"    Declarado: {integrity['declared_digest']}")
        pe = node.metadata.get("pe")
        if pe:
            lines.append(
                f"  PE: {pe.get('bits', '?')} bits | Máquina: {pe['machine']} | Seções: {pe['section_count']}"
            )
            for section in pe["sections"]:
                lines.append(
                    f"    {safe_text(section['name'])}: offset={section['offset']}, bytes={section['size']}, flags={section['flags']}, entropia={section.get('entropy', 'indisponível')}"
                )
                if section.get("sha256"):
                    lines.append(f"      SHA256: {section['sha256']}")
            if pe.get("imports"):
                lines.append(
                    f"  Bibliotecas importadas: {len(pe['imports'])}; funções detalhadas no JSON."
                )
            if "checksum_status" in pe:
                lines.append(
                    f"  Checksum PE: {pe['checksum_status']} | Declarado: {pe['checksum_declared']} | Calculado: {pe.get('checksum_calculated', 'indisponível')}"
                )
            if pe.get("delay_imports"):
                lines.append(f"  Bibliotecas com importação adiada: {len(pe['delay_imports'])}")
            if pe.get("tls_directory"):
                callbacks = pe["tls_directory"].get("callbacks")
                lines.append(
                    f"  Callbacks TLS: {len(callbacks) if callbacks is not None else 'não interpretados'}; nenhum foi executado."
                )
            if pe.get("resources"):
                lines.append(
                    f"  Recursos PE inspecionados: {sum(bool(item['scanned']) for item in pe['resources'])}/{len(pe['resources'])}"
                )
        pyinstaller = node.metadata.get("pyinstaller")
        if pyinstaller:
            for package in pyinstaller["packages"]:
                lines.append(
                    f"  PyInstaller/MEI: Python={package['python_version']}, entradas={package['entries']}, offset={package['offset']}"
                )
        if node.metadata.get("pyz"):
            lines.append(
                f"  PYZ: {node.metadata['pyz']['modules']} módulos; nenhum objeto de código foi carregado."
            )
        pdf = node.metadata.get("pdf")
        if pdf:
            lines.append(
                f"  PDF: {pdf['objects']} objetos | Streams inspecionados: {pdf['decoded_streams']}/{pdf['streams']} | Criptografado: {'sim' if pdf['encrypted'] else 'não'}"
            )
        xml = node.metadata.get("xml")
        if xml:
            lines.append(
                f"  XML: {xml['elements']} elementos | Profundidade: {xml['maximum_depth']} | Referências externas: {len(xml['relationships'])}; nenhuma foi acessada."
            )
        shortcut = node.metadata.get("lnk")
        if shortcut:
            lines.append(
                f"  Atalho LNK: {len(shortcut.get('fields', {}))} campos | {len(shortcut.get('extra_blocks', []))} blocos extras; nenhum destino foi acessado."
            )
            for field, value in shortcut.get("fields", {}).items():
                lines.append(f"    {field}: {safe_text(value)}")
        origin = node.metadata.get("origin")
        if origin:
            lines.append(f"  Origem: {safe_text(json.dumps(origin, ensure_ascii=True))}")
    usage = report.root.metadata.get("resource_usage", {})
    if usage:
        lines.extend(
            (
                "",
                "RECURSOS E COBERTURA",
                f"Bytes expandidos: {usage.get('expanded_bytes', 0):,} | Bytes decodificados: {usage.get('decoded_bytes', 0):,} | Tokens documentais: {usage.get('document_tokens', 0):,}",
            )
        )
        lines.append(
            "A política integral e a identificação da lista de hashes estão no relatório JSON."
        )
    lines.extend(("", "ACHADOS"))
    findings = sorted(
        report.findings, key=lambda item: SEVERITY_WEIGHTS[item.severity], reverse=True
    )
    if not findings:
        lines.append(
            "Nenhum indicador configurado foi detectado. Isso não é uma garantia de segurança."
        )
    for finding in findings:
        lines.extend(
            (
                f"[{finding.severity.upper()}] {safe_text(finding.title)} ({safe_text(finding.rule_id)})",
                f"  Local: {safe_text(finding.location)}",
                f"  {safe_text(finding.description)}",
                f"  Confiança heurística: {finding.confidence:.0%} | Offset: {finding.offset if finding.offset is not None else 'não aplicável'}",
            )
        )
        lines.extend(f"  Evidência: {safe_text(evidence)}" for evidence in finding.evidence)
    indicators = [(node, indicator) for node in nodes for indicator in node.indicators]
    if indicators:
        lines.extend(("", "INDICADORES EXTRAÍDOS — sem consulta de reputação"))
        lines.extend(
            f"- {indicator['type']}: {safe_text(indicator['value'])} | byte {indicator['offset']} | {safe_text(node.name)}"
            for node, indicator in indicators
        )
    warnings = [(node.name, error) for node in nodes for error in node.errors]
    if warnings:
        lines.extend(("", "AVISOS DE COBERTURA"))
        lines.extend(f"- {safe_text(name)}: {safe_text(error)}" for name, error in warnings)
    lines.extend(("", "LIMITAÇÕES"))
    lines.extend(f"- {limitation}" for limitation in report.to_dict()["limitations"])
    return "\n".join(lines) + "\n"

def load_hash_list(path: Path) -> frozenset[str]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise ScanError("A lista de hashes deve ser um arquivo regular de até 1 MiB.")
        source = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with source:
        data = source.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ScanError("The hash list exceeds the 1 MiB limit.")
    try:
        lines = data.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError as error:
        raise ScanError("The hash list must be UTF-8 text.") from error
    hashes = set()
    for number, line in enumerate(lines, start=1):
        value = line.partition("#")[0].strip()
        if not value:
            continue
        if SHA256_PATTERN.fullmatch(value) is None:
            raise ScanError(f"Invalid SHA-256 digest on hash list line {number}.")
        hashes.add(value.lower())
    return frozenset(hashes)

def save_report(path: Path, content: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    identity = os.fstat(descriptor)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        try:
            current = path.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                path.unlink()
        except OSError:
            pass
        raise
