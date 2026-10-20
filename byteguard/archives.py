import gzip
import re
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from collections.abc import Callable
from pathlib import PurePosixPath
from tempfile import SpooledTemporaryFile
from typing import BinaryIO

from .binary_io import BinaryReader, DecompressionReader, RangeReader
from .models import FileReport, Finding, Severity
from .policy import LimitExceeded, ScanBudget, ScanError
from .pyinstaller import PackedEntry, read_carchive, read_pyz, uncovered_ranges
from .zip_reader import open_checked_zip_member, unindexed_zip_records

ScanMember = Callable[[BinaryIO, str, int, int], FileReport]
SUPPORTED_ARCHIVES = frozenset({"zip", "gzip", "tar", "bzip2", "xz", "zlib", "pyz"})
UNSUPPORTED_ARCHIVES = frozenset({"7z", "rar", "zstd"})
ARCHIVE_ERRORS = (
    OSError,
    EOFError,
    ValueError,
    RuntimeError,
    zlib.error,
    zipfile.BadZipFile,
    zipfile.LargeZipFile,
    tarfile.TarError,
)

class ArchiveInspector:
    def __init__(self, budget: ScanBudget, scan_member: ScanMember) -> None:
        self.budget = budget
        self.policy = budget.policy
        self.scan_member = scan_member

    def inspect(self, stream: BinaryIO, report: FileReport, depth: int) -> None:
        if report.kind in UNSUPPORTED_ARCHIVES:
            self._skip(
                report, "archive.unsupported", "Formato de contêiner não suportado", report.kind
            )
            return
        markers = report.metadata.get("magic_markers", {})
        cookies = markers.get("pyinstaller", {}).get("offsets", [])
        packed_candidate = bool(cookies) and report.kind in {"pe", "elf", "macho", "unknown"}
        archive_kind = report.kind
        if archive_kind not in SUPPORTED_ARCHIVES and not packed_candidate:
            if not markers.get("zip") or not zipfile.is_zipfile(stream):
                return
            archive_kind = "zip"
            report.findings.append(
                Finding(
                    "archive.embedded_zip",
                    Severity.INFO,
                    "ZIP anexado ou arquivo políglota",
                    "Um diretório ZIP válido foi localizado além do formato principal; seus membros também serão analisados.",
                    report.name,
                    confidence=0.95,
                )
            )
        if depth >= self.policy.max_depth:
            self._skip(report, "archive.depth_limit", "Limite de profundidade atingido", str(depth))
            return
        try:
            self.budget.check_time()
            stream.seek(0)
            reader = BinaryReader(stream, report.size, self.budget)
            if packed_candidate:
                self._inspect_carchive(reader, report, depth, cookies)
                if markers.get("zip") and zipfile.is_zipfile(stream):
                    report.findings.append(
                        Finding(
                            "archive.embedded_zip",
                            Severity.INFO,
                            "ZIP adicional em executável empacotado",
                            "Um ZIP reconhecido será inspecionado independentemente dos candidatos MEI.",
                            report.name,
                            confidence=0.95,
                        )
                    )
                    self._inspect_zip(stream, report, depth)
            elif archive_kind == "pyz":
                entries = read_pyz(reader)
                report.metadata["pyz"] = {
                    "modules": len(entries),
                    "code_deserialized": False,
                    "python_magic": reader.read(4, 4).hex(),
                }
                self._check_packed_gaps(
                    reader,
                    report,
                    uncovered_ranges(
                        12,
                        reader.unpack("!I", 8)[0],
                        [(entry.offset, entry.offset + entry.stored_size) for entry in entries],
                    ),
                )
                self._inspect_packed_entries(reader, report, depth, entries)
            elif archive_kind == "zip":
                self._inspect_zip(stream, report, depth)
            elif archive_kind == "tar":
                self._inspect_tar(stream, report, depth)
            elif archive_kind == "gzip":
                with gzip.GzipFile(fileobj=stream, mode="rb") as source:
                    name = PurePosixPath(report.name).name
                    name = name[:-3] if name.lower().endswith(".gz") else f"{name}.unpacked"
                    self.inspect_member(source, report, name, depth, None, report.size)
            else:
                source = DecompressionReader(RangeReader(reader, 0, report.size), archive_kind)
                name = f"{PurePosixPath(report.name).stem}.unpacked"
                self.inspect_member(source, report, name, depth, None, report.size)
        except (ScanError, UnicodeError, struct.error, *ARCHIVE_ERRORS) as error:
            self._skip(report, "archive.unreadable", "Inspeção de contêiner incompleta", str(error))

    def _inspect_carchive(
        self, reader: BinaryReader, report: FileReport, depth: int, cookies: list[int]
    ) -> None:
        packages = []
        errors = []
        seen = set()
        for offset in reversed(cookies):
            self.budget.check_time()
            try:
                package = read_carchive(reader, offset)
            except LimitExceeded:
                raise
            except ScanError as error:
                errors.append(str(error))
                continue
            identity = (package.start, package.end)
            if identity in seen:
                continue
            seen.add(identity)
            packages.append(
                {
                    "offset": package.start,
                    "end": package.end,
                    "cookie_offset": offset,
                    "python_version": package.python_version,
                    "python_library": package.python_library,
                    "entries": len(package.entries),
                }
            )
            if any(
                package.start < previous[1] and package.end > previous[0]
                for previous in seen
                if previous != identity
            ):
                self._skip(
                    report,
                    "pyinstaller.overlapping_packages",
                    "Pacotes MEI sobrepostos",
                    "Cookies válidos descrevem regiões sobrepostas; a interpretação é ambígua.",
                )
            self._check_packed_gaps(reader, report, package.unindexed_ranges)
            self._inspect_packed_entries(reader, report, depth, package.entries)
        report.metadata["pyinstaller"] = {
            "packages": packages,
            "unvalidated_cookie_candidates": len(errors),
            "code_executed": False,
        }
        if not packages:
            self._skip(
                report,
                "pyinstaller.invalid_cookie",
                "Cookie MEI não validado",
                errors[-1] if errors else "Nenhum pacote válido.",
            )
        else:
            report.findings.append(
                Finding(
                    "pyinstaller.package",
                    Severity.INFO,
                    "Pacote PyInstaller/MEI inspecionado",
                    "Cookies, tabela de entradas, limites e payloads descomprimidos foram inspecionados sem carregar código Python. PyInstaller não implica malícia.",
                    report.name,
                    (f"pacotes={len(packages)}",),
                    1.0,
                )
            )

    def _check_packed_gaps(
        self, reader: BinaryReader, report: FileReport, gaps: tuple[tuple[int, int], ...]
    ) -> None:
        for start, end in gaps:
            cursor = start
            while cursor < end:
                length = min(self.policy.chunk_size, self.policy.max_metadata_bytes, end - cursor)
                if any(reader.read(cursor, length)):
                    report.metadata.setdefault("unindexed_packed_regions", []).append(
                        {"offset": start, "size": end - start, "expanded": False}
                    )
                    self._skip(
                        report,
                        "pyinstaller.unindexed_data",
                        "Dados fora do índice do pacote",
                        f"offset={start}, bytes={end - start}; o conteúdo não indexado não foi expandido.",
                    )
                    break
                cursor += length

    def _inspect_packed_entries(
        self, reader: BinaryReader, report: FileReport, depth: int, entries: tuple[PackedEntry, ...]
    ) -> None:
        seen: set[str] = set()
        for entry in entries:
            self.budget.check_time()
            self._validate_name(report, entry.name)
            normalized = self._normalized_name(entry.name)
            if normalized in seen:
                report.findings.append(
                    Finding(
                        "archive.duplicate_name",
                        Severity.LOW,
                        "Colisão de nomes em pacote",
                        "Entradas podem se sobrescrever em alguns sistemas de arquivos.",
                        report.name,
                        (entry.name,),
                        0.9,
                    )
                )
            seen.add(normalized)
            if entry.typecode == "o":
                if not entry.stored_size and not entry.expanded_size:
                    continue
                self._skip(
                    report,
                    "pyinstaller.option_payload",
                    "Opção MEI contém payload",
                    "Uma entrada de opção possui dados inesperados; os bytes serão inspecionados.",
                )
            if report.kind != "pyz" and entry.typecode not in set("bdzZmMsxonl"):
                self._skip(
                    report,
                    "pyinstaller.unknown_entry_type",
                    "Tipo de entrada MEI desconhecido",
                    f"{entry.name}: tipo={entry.typecode!r}; somente os bytes serão analisados.",
                )
            if entry.typecode in {"d", "n"}:
                self._skip(
                    report,
                    "pyinstaller.external_dependency",
                    "Referência externa não seguida",
                    entry.name,
                )
                continue
            if (
                entry.expanded_size is not None
                and entry.expanded_size > self.policy.max_member_bytes
            ):
                self._skip(
                    report, "archive.member_limit", "Entrada excede o limite de tamanho", entry.name
                )
                continue
            if (
                entry.expanded_size is not None
                and entry.expanded_size / max(1, entry.stored_size)
                > self.policy.max_compression_ratio
            ):
                self._skip(
                    report,
                    "archive.compression_ratio",
                    "Razão de compressão excessiva",
                    entry.name,
                    Severity.HIGH,
                )
                continue
            self.budget.check_file_capacity()
            source = RangeReader(reader, entry.offset, entry.stored_size)
            if entry.compressed:
                source = DecompressionReader(source)
            try:
                self.inspect_member(
                    source,
                    report,
                    entry.name,
                    depth,
                    entry.expanded_size,
                    entry.stored_size,
                    origin={
                        "container": "pyz" if report.kind == "pyz" else "pyinstaller",
                        "member_name": entry.name,
                        "entry_type": entry.typecode,
                        "parent_offset": entry.offset,
                        "stored_size": entry.stored_size,
                        "compressed": entry.compressed,
                        "executed": False,
                        "code_deserialized": False,
                    },
                )
            except LimitExceeded:
                raise
            except (ScanError, *ARCHIVE_ERRORS) as error:
                self._skip(
                    report,
                    "archive.member_unreadable",
                    "Payload não inspecionado",
                    f"{entry.name}: {error}",
                )

    @staticmethod
    def _normalized_name(name: str) -> str:
        return "/".join(
            part.rstrip(" .")
            for part in unicodedata.normalize("NFKC", name).replace("\\", "/").casefold().split("/")
        )

    def _skip(
        self,
        report: FileReport,
        rule_id: str,
        title: str,
        detail: str,
        severity: Severity = Severity.INFO,
    ) -> None:
        report.mark_incomplete(f"{title}: {detail}")
        report.findings.append(
            Finding(rule_id, severity, title, detail, report.name, confidence=1.0)
        )

    def _validate_name(self, report: FileReport, name: str) -> None:
        normalized = name.replace("\\", "/")
        path = PurePosixPath(normalized)
        if (
            path.is_absolute()
            or ".." in path.parts
            or re.match(r"^[a-zA-Z]:", normalized)
            or "\x00" in name
        ):
            report.findings.append(
                Finding(
                    "archive.path_traversal",
                    Severity.HIGH,
                    "Unsafe archive member path",
                    "The member path could escape an extraction directory. No files are extracted by this scanner.",
                    report.name,
                    (name,),
                    0.95,
                )
            )
        if any(unicodedata.category(character).startswith("C") for character in name):
            report.findings.append(
                Finding(
                    "archive.control_name",
                    Severity.MEDIUM,
                    "Nome de membro contém controles invisíveis",
                    "Controles Unicode podem ocultar extensões ou alterar a apresentação do nome.",
                    report.name,
                    (ascii(name),),
                    0.85,
                )
            )
        if ":" in normalized or any(
            part.rstrip(" .").split(".")[0].upper()
            in {
                "CON",
                "PRN",
                "AUX",
                "NUL",
                *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10)),
            }
            for part in path.parts
        ):
            report.findings.append(
                Finding(
                    "archive.windows_special_name",
                    Severity.MEDIUM,
                    "Nome especial ou fluxo alternativo Windows",
                    "O nome pode representar dispositivo reservado ou fluxo NTFS em vez de um arquivo comum.",
                    report.name,
                    (name,),
                    0.9,
                )
            )
        if name.lower().endswith("vbaproject.bin"):
            report.findings.append(
                Finding(
                    "office.vba_project",
                    Severity.MEDIUM,
                    "Embedded Office VBA project",
                    "An Office VBA project is present. Its compressed macro source is not decompressed by this engine.",
                    report.name,
                    (name,),
                    0.85,
                )
            )

    def _preflight_zip(self, stream: BinaryIO) -> int:
        size = stream.seek(0, 2)
        stream.seek(max(0, size - 65557))
        tail = stream.read(65557)
        self.budget.consume_inspection(len(tail))
        position = tail.rfind(b"PK\x05\x06")
        while position >= 0:
            if position + 22 <= len(tail):
                record = struct.unpack_from("<4s4H2IH", tail, position)
                if position + 22 + record[7] == len(tail):
                    break
            position = tail.rfind(b"PK\x05\x06", 0, position)
        if position < 0:
            raise ScanError("A valid ZIP end-of-directory record was not found.")
        _, disk, directory_disk, local_count, total_count, directory_size, directory_offset, _ = (
            record
        )
        if disk or directory_disk or local_count != total_count:
            raise ScanError("Multi-volume ZIP files are not supported.")
        if total_count == 0xFFFF or directory_size == 0xFFFFFFFF or directory_offset == 0xFFFFFFFF:
            raise ScanError("ZIP64 directories are not inspected by this bounded ZIP reader.")
        if total_count > self.policy.max_archive_members:
            raise LimitExceeded("ZIP member count exceeds the configured limit.")
        if directory_size > self.policy.max_zip_directory_bytes:
            raise LimitExceeded("ZIP central directory exceeds the metadata size limit.")
        if directory_offset + directory_size > size:
            raise ScanError("ZIP central directory extends beyond the file.")
        stream.seek(0)
        return total_count

    def _inspect_zip(self, stream: BinaryIO, report: FileReport, depth: int) -> None:
        expected_count = self._preflight_zip(stream)
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            if len(members) != expected_count:
                raise ScanError(
                    "A quantidade de entradas ZIP diverge do registro final do diretório."
                )
            names = {member.filename.replace("\\", "/").casefold() for member in members}
            if "[content_types].xml" in names:
                applications = [
                    label
                    for prefix, label in (
                        ("word/", "Word"),
                        ("xl/", "Excel"),
                        ("ppt/", "PowerPoint"),
                    )
                    if any(name.startswith(prefix) for name in names)
                ]
                if applications:
                    report.metadata["office_package"] = {
                        "applications": applications,
                        "macro_project_present": any(
                            name.endswith("vbaproject.bin") for name in names
                        ),
                        "relationships_followed": False,
                        "macros_executed": False,
                    }
            if len(members) > self.policy.max_archive_members:
                raise LimitExceeded("ZIP member count exceeds the configured limit.")
            offsets = sorted(member.header_offset for member in members)
            if len(set(offsets)) != len(offsets):
                raise ScanError("Múltiplas entradas ZIP apontam para o mesmo cabeçalho local.")
            boundaries = dict(
                zip(offsets, offsets[1:] + [archive.start_dir] if offsets else [], strict=True)
            )
            reader = BinaryReader(stream, report.size, self.budget)
            zip_markers = report.metadata.get("magic_markers", {}).get("zip", {})
            for offset in unindexed_zip_records(
                reader, members, archive.start_dir, zip_markers.get("offsets", [])
            ):
                self._skip(
                    report,
                    "archive.unindexed_zip_record",
                    "Registro ZIP fora do índice ativo",
                    f"offset={offset}; o conteúdo comprimido não foi inspecionado.",
                )
            if zip_markers.get("truncated"):
                report.mark_incomplete(
                    "O limite de candidatos ZIP impede conferir todos os registros locais."
                )
            report.metadata["zip"] = {
                "members": len(members),
                "verified_members": 0,
                "validation": "local_header_decompression_eof_size_crc32",
            }
            seen: set[str] = set()
            for member in members:
                self.budget.check_time()
                self._validate_name(report, member.filename)
                normalized_name = self._normalized_name(member.filename)
                if normalized_name in seen:
                    report.findings.append(
                        Finding(
                            "archive.duplicate_name",
                            Severity.LOW,
                            "Duplicate archive member name",
                            "Different archive readers may choose different entries for the same name.",
                            report.name,
                            (member.filename,),
                            0.65,
                        )
                    )
                seen.add(normalized_name)
                if member.is_dir():
                    if member.file_size:
                        self._skip(
                            report,
                            "archive.directory_payload",
                            "Entrada de diretório ZIP contém dados",
                            member.filename,
                        )
                        continue
                    try:
                        source = open_checked_zip_member(
                            reader, member, boundaries[member.header_offset]
                        )
                        source.read(1)
                        report.metadata["zip"]["verified_members"] += 1
                    except LimitExceeded:
                        raise
                    except (ScanError, UnicodeError, struct.error, *ARCHIVE_ERRORS) as error:
                        self._skip(
                            report,
                            "archive.member_unreadable",
                            "Diretório ZIP inválido",
                            str(error),
                        )
                    continue
                if stat.S_ISLNK(member.external_attr >> 16):
                    self._skip(report, "archive.link", "Archive link not followed", member.filename)
                    continue
                if member.flag_bits & 1:
                    self._skip(
                        report,
                        "archive.encrypted",
                        "Encrypted member not inspected",
                        member.filename,
                    )
                    continue
                if member.compress_type not in {
                    zipfile.ZIP_STORED,
                    zipfile.ZIP_DEFLATED,
                    zipfile.ZIP_BZIP2,
                }:
                    self._skip(
                        report,
                        "archive.compression_method",
                        "Unsupported ZIP compression method",
                        f"{member.filename}: method {member.compress_type}",
                    )
                    continue
                if member.file_size > self.policy.max_member_bytes:
                    self._skip(
                        report, "archive.member_limit", "Archive member size limit", member.filename
                    )
                    continue
                if (
                    member.file_size / max(member.compress_size, 1)
                    > self.policy.max_compression_ratio
                ):
                    self._skip(
                        report,
                        "archive.compression_ratio",
                        "Excessive compression ratio",
                        member.filename,
                        Severity.HIGH,
                    )
                    continue
                self.budget.check_file_capacity()
                try:
                    source = open_checked_zip_member(
                        reader, member, boundaries[member.header_offset]
                    )
                    child = self.inspect_member(
                        source,
                        report,
                        member.filename,
                        depth,
                        member.file_size,
                        member.compress_size,
                        origin={
                            "container": "zip",
                            "member_name": member.filename,
                            "header_offset": member.header_offset,
                            "stored_size": member.compress_size,
                            "executed": False,
                        },
                    )
                    if child is not None:
                        report.metadata["zip"]["verified_members"] += 1
                except LimitExceeded:
                    raise
                except (ScanError, UnicodeError, struct.error, *ARCHIVE_ERRORS) as error:
                    self._skip(
                        report,
                        "archive.member_unreadable",
                        "Unreadable archive member",
                        f"{member.filename}: {error}",
                    )

    def _preflight_tar(self, stream: BinaryIO, size: int) -> None:
        offset = 0
        metadata_bytes = 0
        metadata_count = 0
        member_count = 0
        extended_types = {
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        }
        reader = BinaryReader(stream, size, self.budget)
        terminated = False
        while offset + 512 <= size:
            self.budget.check_time()
            header = reader.read(offset, 512)
            if header == b"\x00" * 512:
                if offset + 1024 > size or reader.read(offset + 512, 512) != b"\x00" * 512:
                    raise ScanError("O TAR não possui os dois blocos de término esperados.")
                cursor = offset + 1024
                while cursor < size:
                    length = min(
                        self.policy.chunk_size, self.policy.max_metadata_bytes, size - cursor
                    )
                    if any(reader.read(cursor, length)):
                        raise ScanError(
                            "Há dados não nulos após o término TAR; possível contêiner concatenado."
                        )
                    cursor += length
                terminated = True
                break
            member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            member_count += 1
            if member_count > self.policy.max_archive_members:
                raise LimitExceeded("TAR header count exceeds the configured limit.")
            if member.size < 0 or offset + 512 + member.size > size:
                raise ScanError("TAR member extends beyond the archive.")
            if member.type == tarfile.GNUTYPE_SPARSE:
                raise ScanError("Sparse TAR files are not inspected.")
            if member.type in extended_types:
                metadata_bytes += member.size
                metadata_count += 1
                if metadata_bytes > 65536 or metadata_count > 16:
                    raise LimitExceeded(
                        "TAR extended metadata exceeds the configured safety limit."
                    )
            offset += 512 + ((member.size + 511) // 512) * 512
        if not terminated:
            raise ScanError("O TAR terminou sem os blocos de fechamento; a cobertura é parcial.")
        stream.seek(0)

    def _inspect_tar(self, stream: BinaryIO, report: FileReport, depth: int) -> None:
        self._preflight_tar(stream, report.size)
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for count, member in enumerate(archive, start=1):
                self.budget.check_time()
                if count > self.policy.max_archive_members:
                    raise LimitExceeded("TAR member count exceeds the configured limit.")
                self._validate_name(report, member.name)
                if member.isdir():
                    if member.size:
                        self._skip(
                            report,
                            "archive.directory_payload",
                            "Diretório TAR contém dados",
                            f"{member.name}: bytes não expandidos={member.size}",
                        )
                    continue
                if not member.isfile() or member.issparse():
                    self._skip(
                        report,
                        "archive.special_entry",
                        "Non-regular or sparse TAR member not followed",
                        member.name,
                    )
                    continue
                if member.size > self.policy.max_member_bytes:
                    raise LimitExceeded(f"TAR member exceeds the size limit: {member.name}")
                self.budget.check_file_capacity()
                source = archive.extractfile(member)
                if source is None:
                    raise ScanError(f"TAR member could not be read: {member.name}")
                with source:
                    self.inspect_member(source, report, member.name, depth, member.size, None)

    def inspect_member(
        self,
        source: BinaryIO,
        parent: FileReport,
        name: str,
        depth: int,
        expected_size: int | None,
        compressed_size: int | None,
        *,
        origin: dict | None = None,
    ) -> FileReport | None:
        if depth >= self.policy.max_depth:
            self._skip(parent, "archive.depth_limit", "Limite de profundidade atingido", name)
            return None
        self.budget.check_file_capacity()
        total = 0
        with SpooledTemporaryFile(max_size=4 * 1024 * 1024, mode="w+b") as buffer:
            while True:
                self.budget.check_time()
                remaining = min(
                    self.policy.max_member_bytes - total,
                    self.budget.remaining_bytes - total,
                    self.policy.max_expanded_bytes - self.budget.expanded_bytes,
                )
                block = source.read(min(self.policy.chunk_size, max(1, remaining + 1)))
                if not block:
                    break
                self.budget.consume_expanded(len(block))
                total += len(block)
                if total > self.policy.max_member_bytes:
                    raise LimitExceeded(f"Expanded member exceeds the size limit: {name}")
                if total > self.budget.remaining_bytes:
                    raise LimitExceeded(
                        f"Expanded member exceeds the cumulative byte budget: {name}"
                    )
                if (
                    compressed_size is not None
                    and total / max(compressed_size, 1) > self.policy.max_compression_ratio
                ):
                    self._skip(
                        parent,
                        "archive.compression_ratio",
                        "Excessive compression ratio",
                        name,
                        Severity.HIGH,
                    )
                    return
                buffer.write(block)
            if expected_size is not None and total != expected_size:
                raise ScanError(f"Member size differs from its metadata: {name}")
            buffer.seek(0)
            child = self.scan_member(buffer, f"{parent.name}!{name}", depth + 1, total)
            child.metadata["origin"] = origin or {
                "container": parent.kind,
                "member_name": name,
                "stored_size": compressed_size,
                "executed": False,
            }
            parent.children.append(child)
            if not child.complete:
                parent.complete = False
            return child
