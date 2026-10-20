import json
import math
import re
from dataclasses import asdict, fields

from .models import AnalysisReport, FileReport, Finding, Severity
from .policy import ScanError, ScanPolicy

HASH_LENGTHS = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
    "sha3_256": 64,
    "blake2b": 128,
    "crc32": 8,
}

def encode_message(kind: str, value: AnalysisReport | str, maximum: int) -> bytes:
    if kind not in {"report", "error"}:
        raise ScanError("Tipo de mensagem interna inválido.")
    payload = asdict(value) if isinstance(value, AnalysisReport) else value
    encoder = json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    output = bytearray()
    for chunk in encoder.iterencode({"protocol": 1, "kind": kind, "payload": payload}):
        encoded = chunk.encode("ascii")
        if len(output) + len(encoded) > maximum:
            raise ScanError(
                "O relatório excede o limite de transporte; nenhum veredito foi emitido."
            )
        output.extend(encoded)
    return bytes(output)

def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ScanError("A mensagem interna contém chaves JSON duplicadas.")
        result[key] = value
    return result

def _reject_constant(value: str):
    raise ScanError(f"Número JSON não finito recusado: {value}.")

def _text(value, maximum: int = 65536) -> str:
    if type(value) is not str or len(value) > maximum:
        raise ScanError("Texto inválido ou excessivo no relatório interno.")
    return value

def _integer(value, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ScanError("Contagem ou offset inválido no relatório interno.")
    return value

def _number(value, maximum: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ScanError("Número fora do intervalo no relatório interno.")
    return float(value)

def _object(value, expected: set[str]) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise ScanError("Estrutura inesperada no relatório interno.")
    return value

def _list(value, maximum: int) -> list:
    if type(value) is not list or len(value) > maximum:
        raise ScanError("Lista inválida ou excessiva no relatório interno.")
    return value

def _validate_json_tree(value, maximum: int) -> None:
    stack = [iter((value,))]
    visited = 0
    while stack:
        try:
            item = next(stack[-1])
        except StopIteration:
            stack.pop()
            continue
        visited += 1
        if visited > min(maximum, 1000000) or len(stack) > 64:
            raise ScanError("Complexidade excessiva no relatório interno.")
        if type(item) is dict:
            for key in item:
                _text(key)
            stack.append(iter(item.values()))
        elif type(item) is list:
            stack.append(iter(item))
        elif type(item) is str:
            _text(item)
        elif type(item) is float:
            if not math.isfinite(item):
                raise ScanError("Metadados contêm um número não finito.")
        elif type(item) is int:
            if abs(item) > (1 << 64) - 1:
                raise ScanError("Inteiro excessivo nos metadados.")
        elif item is not None and type(item) is not bool:
            raise ScanError("Tipo não permitido no relatório interno.")

def decode_message(data: bytes, policy: ScanPolicy) -> tuple[str, AnalysisReport | str]:
    if len(data) > policy.max_report_bytes:
        raise ScanError("A mensagem interna excede o limite de bytes.")
    try:
        message = json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        _validate_json_tree(message, policy.max_report_bytes)
        _object(message, {"protocol", "kind", "payload"})
        if type(message["protocol"]) is not int or message["protocol"] != 1:
            raise ScanError("Versão de protocolo interno não suportada.")
        if message["kind"] == "error":
            return "error", _text(message["payload"], 4096)
        if message["kind"] != "report":
            raise ScanError("Mensagem interna não reconhecida.")
        payload = _object(message["payload"], {field.name for field in fields(AnalysisReport)})
        count = 0
        scanned = 0

        def read_file(value, depth: int) -> FileReport:
            nonlocal count, scanned
            count += 1
            if count > policy.max_files or depth > policy.max_depth:
                raise ScanError("Árvore do relatório excede os limites da análise.")
            node = _object(value, {field.name for field in fields(FileReport)})
            maximum = policy.max_file_bytes if depth == 0 else policy.max_member_bytes
            size = _integer(node["size"], maximum)
            amount = _integer(node["bytes_scanned"], size)
            scanned += amount
            if scanned > policy.max_total_bytes or type(node["complete"]) is not bool:
                raise ScanError("Cobertura do relatório interno é inconsistente.")
            if type(node["hashes"]) is not dict or type(node["metadata"]) is not dict:
                raise ScanError("Hashes ou metadados inválidos no relatório interno.")
            if node["complete"] and node["errors"]:
                raise ScanError("Relatório completo não pode conter falhas de cobertura.")
            if "bytes_complete" in node["metadata"]:
                byte_coverage = node["metadata"]["bytes_complete"]
                if type(byte_coverage) is not bool or (byte_coverage and amount != size):
                    raise ScanError("Cobertura integral de bytes não comprovada.")
            if node["hashes"] and (
                amount != size or node["metadata"].get("bytes_complete") is not True
            ):
                raise ScanError("Hashes não podem representar uma leitura parcial.")
            for algorithm, digest in node["hashes"].items():
                if algorithm not in HASH_LENGTHS or not re.fullmatch(
                    rf"[0-9a-f]{{{HASH_LENGTHS[algorithm]}}}", _text(digest, 128)
                ):
                    raise ScanError("Hash interno não reconhecido ou malformado.")
            findings = []
            for item in _list(node["findings"], policy.max_findings_per_file):
                item = _object(item, {field.name for field in fields(Finding)})
                findings.append(
                    Finding(
                        _text(item["rule_id"], 256),
                        Severity(item["severity"]),
                        _text(item["title"]),
                        _text(item["description"]),
                        _text(item["location"]),
                        tuple(_text(entry) for entry in _list(item["evidence"], 4096)),
                        _number(item["confidence"], 1),
                        None if item["offset"] is None else _integer(item["offset"]),
                    )
                )
            indicators = _list(node["indicators"], policy.max_indicators)
            for indicator in indicators:
                if type(indicator) is not dict:
                    raise ScanError("Indicador interno inválido.")
                for key in ("type", "value"):
                    _text(indicator[key])
                _integer(indicator["offset"])
            return FileReport(
                name=_text(node["name"]),
                kind=_text(node["kind"], 128),
                size=size,
                bytes_scanned=amount,
                entropy=_number(node["entropy"], 8),
                hashes=node["hashes"],
                complete=node["complete"],
                findings=findings,
                children=[
                    read_file(child, depth + 1)
                    for child in _list(node["children"], policy.max_files)
                ],
                errors=[_text(error) for error in _list(node["errors"], policy.max_report_bytes)],
                metadata=node["metadata"],
                indicators=indicators,
            )

        root = read_file(payload["root"], 0)
        total = _integer(payload["bytes_scanned"], policy.max_total_bytes)
        if total != scanned:
            raise ScanError("Soma de bytes do relatório interno é inconsistente.")
        return "report", AnalysisReport(
            root,
            _text(payload["started_at"], 128),
            _number(payload["duration_seconds"], 1e12),
            total,
            _text(payload["engine_version"], 32),
        )
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as error:
        raise ScanError(f"Relatório interno rejeitado: {type(error).__name__}.") from error
