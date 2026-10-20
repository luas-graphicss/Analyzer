import binascii
import hashlib
import hmac
import io
import os
import re
import stat
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO

from .archives import ArchiveInspector
from .binary import inspect_binary
from .binary_io import BinaryReader, RangeReader
from .content import ContentInspector, entropy
from .documents import inspect_document
from .formats import analyze_structure, detect_format
from .models import SEVERITY_WEIGHTS, AnalysisReport, FileContext, FileReport, Finding, Severity
from .policy import ScanBudget, ScanError, ScanPolicy
from .shortcuts import inspect_shortcut
from .signatures import SignatureAnalyzer, StreamingAnalyzer

AnalyzerFactory = Callable[[], StreamingAnalyzer]
SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

class ScanEngine:
    def __init__(
        self,
        policy: ScanPolicy | None = None,
        known_hashes: Iterable[str] = (),
        analyzer_factories: Iterable[AnalyzerFactory] = (SignatureAnalyzer,),
        expected_sha256: str | None = None,
    ) -> None:
        self.policy = policy or ScanPolicy()
        values = tuple(known_hashes)
        if any(
            not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None
            for value in values
        ):
            raise ValueError("Known hash entries must be SHA-256 hex digests.")
        if expected_sha256 is not None and (
            not isinstance(expected_sha256, str)
            or SHA256_PATTERN.fullmatch(expected_sha256) is None
        ):
            raise ValueError(
                "O SHA-256 esperado deve conter exatamente 64 caracteres hexadecimais."
            )
        self.known_hashes = frozenset(value.lower() for value in values)
        self.expected_sha256 = expected_sha256.lower() if expected_sha256 else None
        self.analyzer_factories = tuple(analyzer_factories)

    def scan(self, filename: str | os.PathLike[str]) -> AnalysisReport:
        path = Path(filename).expanduser().absolute()
        if path.is_symlink():
            raise ScanError("Symbolic links are not accepted as scan targets.")
        flags = os.O_RDONLY
        for attribute in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC", "O_BINARY"):
            flags |= getattr(os, attribute, 0)
        started_at = datetime.now(UTC).isoformat()
        budget = ScanBudget(self.policy)
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise ScanError(f"Cannot open the scan target: {error}") from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ScanError("Only regular files can be scanned.")
            if before.st_size > self.policy.max_file_bytes:
                raise ScanError(
                    f"The file exceeds the configured limit of {self.policy.max_file_bytes} bytes."
                )
            stream = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with stream:
            report = self._scan_stream(stream, str(path), 0, before.st_size, budget)
            after = os.fstat(stream.fileno())
            try:
                named = path.stat(follow_symlinks=False)
                same_path = stat.S_ISREG(named.st_mode) and (named.st_dev, named.st_ino) == (
                    after.st_dev,
                    after.st_ino,
                )
            except OSError:
                same_path = False
            stable = same_path and (before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            report.metadata["file_stable"] = stable
            report.metadata["filesystem"] = {
                "device": before.st_dev,
                "inode": before.st_ino,
                "mode": stat.S_IMODE(before.st_mode),
                "mtime_ns": before.st_mtime_ns,
            }
            if not stable:
                for node in report.walk():
                    node.mark_incomplete(
                        "O arquivo ou caminho mudou durante a análise; hashes e confiança foram descartados."
                    )
                    node.hashes.clear()
                    node.metadata["bytes_complete"] = False
                    node.findings[:] = [
                        finding
                        for finding in node.findings
                        if not finding.rule_id.startswith("hash.")
                    ]
                    node.metadata["integrity_discarded"] = True
                    for section in node.metadata.get("pe", {}).get("sections", []):
                        section.pop("sha256", None)
                    for resource in node.metadata.get("pe", {}).get("resources", []):
                        resource.pop("sha256", None)
                    if "pe" in node.metadata:
                        node.metadata["pe"]["checksum_verified"] = False
                        node.metadata["pe"]["checksum_status"] = "discarded_file_changed"
                        node.metadata["pe"].pop("checksum_calculated", None)
                    if "authenticode" in node.metadata:
                        signature = node.metadata["authenticode"]
                        signature["status"] = "discarded_file_changed"
                        signature.pop("image_hashes", None)
                        signature["reason"] = (
                            "Resultados descartados: o arquivo mudou durante a análise."
                        )
                        for record in signature.get("records", []):
                            if "content_digest" in record:
                                record["content_digest"]["status"] = "discarded_file_changed"
                                record["content_digest"].pop("calculated_digest", None)
            if self.expected_sha256:
                digest = report.hashes.get("sha256")
                matches = hmac.compare_digest(digest, self.expected_sha256) if digest else None
                report.metadata["hash_comparison"] = {
                    "expected_sha256": self.expected_sha256,
                    "status": "match"
                    if matches
                    else "mismatch"
                    if matches is False
                    else "unavailable",
                    "establishes_safety": False,
                }
                if matches is not None:
                    report.findings.append(
                        Finding(
                            "hash.expected_match" if matches else "hash.expected_mismatch",
                            Severity.INFO if matches else Severity.HIGH,
                            "SHA-256 coincide com a referência"
                            if matches
                            else "SHA-256 diverge da referência",
                            "A comparação verifica igualdade de bytes, não se a referência é legítima ou segura.",
                            report.name,
                            (self.expected_sha256, digest),
                            1.0,
                        )
                    )
        self._limit_findings(report)
        report.metadata["analysis_configuration"] = {
            "policy": asdict(self.policy),
            "known_hash_count": len(self.known_hashes),
            "known_hash_list_sha256": hashlib.sha256(
                "\n".join(sorted(self.known_hashes)).encode("ascii")
            ).hexdigest(),
            "analyzers": [
                getattr(factory, "__name__", type(factory).__name__)
                for factory in self.analyzer_factories
            ],
            "max_depth": self.policy.max_depth,
            "max_file_bytes": self.policy.max_file_bytes,
            "max_total_bytes": self.policy.max_total_bytes,
            "timeout_seconds": self.policy.timeout_seconds,
            "online_reputation_checked": False,
        }
        report.metadata["resource_usage"] = {
            "bytes_scanned": budget.bytes_scanned,
            "expanded_bytes": budget.expanded_bytes,
            "structured_read_bytes": budget.inspection_bytes,
            "decoded_bytes": budget.decoded_bytes,
            "document_tokens": budget.document_tokens,
        }
        return AnalysisReport(
            report, started_at, round(time.monotonic() - budget.started, 4), budget.bytes_scanned
        )

    def _scan_stream(
        self,
        stream: BinaryIO,
        name: str,
        depth: int,
        size: int,
        budget: ScanBudget,
    ) -> FileReport:
        budget.register_file()
        report = FileReport(name=name, kind="unknown", size=size)
        analyzers = []
        for factory in self.analyzer_factories:
            try:
                analyzers.append(factory())
            except Exception as error:
                report.mark_incomplete(
                    f"Um analisador não pôde ser inicializado: {type(error).__name__}: {error}"
                )
        disabled_analyzers: set[int] = set()
        profile = ContentInspector(budget, allow_decode=depth < self.policy.max_depth)
        hashers = {
            "md5": hashlib.md5(usedforsecurity=False),
            "sha1": hashlib.sha1(usedforsecurity=False),
            "sha256": hashlib.sha256(),
            "sha384": hashlib.sha384(),
            "sha512": hashlib.sha512(),
            "sha3_256": hashlib.sha3_256(),
            "blake2b": hashlib.blake2b(),
        }
        crc32 = 0
        head = bytearray()
        offset = 0
        bytes_complete = False
        try:
            while True:
                budget.check_time()
                remaining = min(size - offset, budget.remaining_bytes)
                data = stream.read(min(self.policy.chunk_size, max(1, remaining)))
                if not data:
                    break
                if offset + len(data) > size:
                    raise ScanError("The content is longer than the declared file size.")
                budget.consume(len(data))
                if len(head) < self.policy.header_bytes:
                    head.extend(data[: self.policy.header_bytes - len(head)])
                for hasher in hashers.values():
                    hasher.update(data)
                crc32 = binascii.crc32(data, crc32)
                start = offset
                offset += len(data)
                profile.feed(data, start)
                for index, analyzer in enumerate(analyzers):
                    if index in disabled_analyzers:
                        continue
                    budget.check_time()
                    try:
                        analyzer.feed(data, start)
                    except Exception as error:
                        disabled_analyzers.add(index)
                        report.mark_incomplete(
                            f"Analisador {type(analyzer).__name__} falhou: {type(error).__name__}: {error}"
                        )
            if offset != size:
                raise ScanError("The content is shorter than the declared file size.")
            bytes_complete = True
        except (ScanError, OSError) as error:
            report.mark_incomplete(str(error))
        report.bytes_scanned = offset
        report.kind = detect_format(bytes(head))
        report.entropy = entropy(profile.counts, profile.size)
        report.metadata.update(profile.finish())
        report.metadata["bytes_complete"] = bytes_complete
        report.metadata["depth"] = depth
        report.indicators = profile.indicators
        for warning in profile.warnings:
            report.mark_incomplete(warning)
        if bytes_complete:
            report.hashes = {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()}
            report.hashes["crc32"] = f"{crc32:08x}"
        context = FileContext(
            name,
            report.kind,
            size,
            bytes(head),
            report.entropy,
            report.hashes.copy(),
            bytes_complete,
        )
        for index, analyzer in enumerate(analyzers):
            if index in disabled_analyzers:
                continue
            try:
                for finding in analyzer.finish(context):
                    if len(report.findings) >= self.policy.max_findings_per_file:
                        report.mark_incomplete("O limite de achados por arquivo foi atingido.")
                        break
                    report.findings.append(finding)
            except Exception as error:
                report.mark_incomplete(
                    f"Analisador {type(analyzer).__name__} não finalizou: {type(error).__name__}: {error}"
                )
        report.findings.extend(analyze_structure(context))
        if report.hashes.get("sha256") in self.known_hashes:
            report.findings.append(
                Finding(
                    "hash.known_denylist",
                    Severity.CRITICAL,
                    "SHA-256 corresponde à lista de bloqueio",
                    "O hash integral corresponde à lista fornecida pelo usuário. A confiabilidade depende da origem dessa lista.",
                    name,
                    (report.hashes["sha256"],),
                    1.0,
                )
            )
        if bytes_complete:
            reader = BinaryReader(stream, size, budget)
            inspect_binary(reader, report, name if depth == 0 else None)
            inspector = ArchiveInspector(
                budget,
                lambda source, member_name, member_depth, member_size: self._scan_stream(
                    source, member_name, member_depth, member_size, budget
                ),
            )
            inspector.inspect(stream, report, depth)
            seen_resources: dict[tuple[int, int], FileReport] = {}
            for index, resource in enumerate(report.metadata.get("pe", {}).get("resources", [])):
                identity = (resource["offset"], resource["size"])
                if identity in seen_resources:
                    child = seen_resources[identity]
                    resource["scanned"] = True
                    resource["shared_payload"] = child.name
                    if child.hashes.get("sha256"):
                        resource["sha256"] = child.hashes["sha256"]
                    continue
                if resource["size"] > self.policy.max_member_bytes:
                    report.mark_incomplete("Recurso PE excede o limite por payload.")
                    continue
                try:
                    child = inspector.inspect_member(
                        RangeReader(reader, resource["offset"], resource["size"]),
                        report,
                        f"pe-resource-{index}.bin",
                        depth,
                        resource["size"],
                        None,
                        origin={
                            "container": "pe_resource",
                            "resource_path": resource["path"],
                            "parent_offset": resource["offset"],
                            "executed": False,
                        },
                    )
                    if child is not None:
                        seen_resources[identity] = child
                        resource["scanned"] = True
                        if child.hashes.get("sha256"):
                            resource["sha256"] = child.hashes["sha256"]
                except (ScanError, OSError) as error:
                    report.mark_incomplete(f"Recurso PE não analisado: {error}")
                    break
            inspect_document(reader, report, depth, inspector.inspect_member)
            inspect_shortcut(reader, report, depth, inspector.inspect_member)
            if report.kind in {"ole", "dex", "wasm", "python_bytecode"}:
                report.metadata["semantic_analysis"] = "byte_level_only"
                report.mark_incomplete(
                    f"Formato {report.kind}: os bytes foram lidos, mas a semântica e todos os objetos internos não são integralmente interpretados."
                )
            for payload in profile.decoded:
                if len(payload.content) > self.policy.max_member_bytes:
                    report.mark_incomplete("Payload decodificado excede o limite por membro.")
                    continue
                try:
                    child = self._scan_stream(
                        io.BytesIO(payload.content),
                        f"{name}!decoded-{payload.encoding}@{payload.offset}",
                        depth + 1,
                        len(payload.content),
                        budget,
                    )
                    child.metadata["origin"] = {
                        "encoding": payload.encoding,
                        "parent_offset": payload.offset,
                        "executed": False,
                    }
                    report.children.append(child)
                    if not child.complete:
                        report.complete = False
                except (ScanError, OSError) as error:
                    report.mark_incomplete(str(error))
                    break
        self._limit_findings(report)
        return report

    def _limit_findings(self, report: FileReport) -> None:
        if len(report.findings) > self.policy.max_findings_per_file:
            report.findings.sort(
                key=lambda finding: SEVERITY_WEIGHTS[finding.severity], reverse=True
            )
            del report.findings[self.policy.max_findings_per_file :]
            report.mark_incomplete(
                "O limite de achados por arquivo foi atingido; os mais graves foram preservados."
            )
