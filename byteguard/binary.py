import hashlib
import hmac
import math
import struct
from collections import Counter
from datetime import UTC, datetime

from .authenticode import verify_authenticode
from .binary_io import BinaryReader
from .models import FileReport, Finding, Severity
from .pe_features import (
    read_delay_imports,
    read_import_functions,
    read_resources,
    read_rva_string,
    read_tls,
)
from .pe_integrity import hash_authenticode_image, read_authenticode_digest
from .policy import LimitExceeded, ScanError

def _finding(
    report: FileReport,
    rule: str,
    title: str,
    detail: str,
    severity: Severity = Severity.LOW,
    offset: int | None = None,
) -> None:
    report.findings.append(
        Finding(rule, severity, title, detail, report.name, confidence=0.8, offset=offset)
    )

def _range_profile(reader: BinaryReader, offset: int, size: int) -> dict:
    counts: Counter[int] = Counter()
    digest = hashlib.sha256()
    cursor = 0
    while cursor < size:
        amount = min(
            reader.budget.policy.chunk_size, reader.budget.policy.max_metadata_bytes, size - cursor
        )
        data = reader.read(offset + cursor, amount)
        digest.update(data)
        counts.update(data)
        cursor += amount
    entropy = (
        -sum((count / size) * math.log2(count / size) for count in counts.values()) if size else 0.0
    )
    return {"sha256": digest.hexdigest(), "entropy": round(entropy, 6), "bytes_profiled": size}

def inspect_binary(
    reader: BinaryReader, report: FileReport, native_path: str | None = None
) -> None:
    try:
        if report.kind == "pe":
            _inspect_pe(reader, report, native_path)
        elif report.kind == "elf":
            _inspect_elf(reader, report)
        elif report.kind in {"macho", "java_or_fat_macho"}:
            _inspect_macho(reader, report)
    except (ScanError, struct.error, OverflowError, ValueError) as error:
        report.mark_incomplete(f"Inspeção estrutural {report.kind} incompleta: {error}")
        _finding(
            report,
            f"{report.kind}.structure_incomplete",
            "Estrutura binária não validada por completo",
            str(error),
        )

def _inspect_pe(reader: BinaryReader, report: FileReport, native_path: str | None) -> None:
    dos = reader.read(0, 64)
    pe_offset = struct.unpack_from("<I", dos, 60)[0]
    if pe_offset < 64:
        raise ScanError("O cabeçalho PE sobrepõe o cabeçalho DOS.")
    header = reader.read(pe_offset, 24)
    if header[:4] != b"PE\x00\x00":
        raise ScanError("MZ sem assinatura PE válida; pode ser DOS ou estrutura malformada.")
    machine, count, timestamp, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", header, 4
    )
    if not 1 <= count <= 96:
        raise ScanError(f"Quantidade de seções PE fora do limite: {count}.")
    optional_offset = pe_offset + 24
    table_offset = optional_offset + optional_size
    table = reader.read(table_offset, count * 40)
    metadata = {
        "header_offset": pe_offset,
        "machine": f"0x{machine:04x}",
        "section_count": count,
        "timestamp": timestamp,
        "characteristics": f"0x{characteristics:04x}",
        "sections": [],
    }
    report.metadata["pe"] = metadata
    if timestamp > int(datetime.now(UTC).timestamp()) + 86400 * 2:
        _finding(
            report,
            "pe.future_timestamp",
            "Timestamp PE no futuro",
            "O timestamp COFF está no futuro; timestamps podem ser forjados e não comprovam autoria.",
        )
    ranges = []
    sections = []
    for index in range(count):
        raw = table[index * 40 : (index + 1) * 40]
        name = raw[:8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", raw, 8)
        flags = struct.unpack_from("<I", raw, 36)[0]
        section = {
            "name": name,
            "rva": rva,
            "virtual_size": virtual_size,
            "offset": raw_offset,
            "size": raw_size,
            "flags": f"0x{flags:08x}",
        }
        sections.append((rva, virtual_size, raw_offset, raw_size, flags))
        metadata["sections"].append(section)
        if name.upper().startswith(
            ("UPX", ".UPX", "MPRESS", ".MPRESS", ".ASPACK", ".VMP", ".THEMIDA")
        ):
            _finding(
                report,
                "pe.packer_section",
                "Seção associada a empacotador",
                f"Seção {name!r}; empacotamento também é usado por software legítimo.",
                Severity.MEDIUM,
                table_offset + index * 40,
            )
        if flags & 0xA0000000 == 0xA0000000:
            _finding(
                report,
                "pe.writable_executable",
                "Seção PE gravável e executável",
                f"A seção {name!r} permite escrita e execução.",
                Severity.MEDIUM,
                table_offset + index * 40,
            )
        if raw_size:
            if raw_offset < table_offset + len(table) or raw_offset + raw_size > reader.size:
                report.mark_incomplete(f"Intervalo inválido na seção PE {name!r}.")
                _finding(
                    report,
                    "pe.section_bounds",
                    "Seção PE fora dos limites",
                    f"Seção {name!r}: offset={raw_offset}, bytes={raw_size}.",
                    Severity.MEDIUM,
                )
                continue
            ranges.append((raw_offset, raw_offset + raw_size))
            section.update(_range_profile(reader, raw_offset, raw_size))
            if raw_size >= 4096 and section["entropy"] >= 7.5 and flags & 0x20000000:
                _finding(
                    report,
                    "pe.executable_entropy",
                    "Alta entropia em seção executável",
                    f"Seção {name!r}, entropia={section['entropy']:.4f}; pode indicar compressão ou criptografia.",
                    Severity.LOW,
                    raw_offset,
                )
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:], strict=False)):
        report.mark_incomplete("Seções PE sobrepostas tornam o mapeamento ambíguo.")
        _finding(
            report,
            "pe.overlapping_sections",
            "Seções PE sobrepostas",
            "Leitores podem interpretar bytes diferentes para a mesma seção.",
            Severity.MEDIUM,
        )
    optional = reader.read(optional_offset, optional_size)
    if len(optional) < 2:
        raise ScanError("Cabeçalho opcional PE ausente.")
    magic = struct.unpack_from("<H", optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ScanError(f"Magic do cabeçalho opcional PE não suportado: 0x{magic:04x}.")
    directory_base = 96 if magic == 0x10B else 112
    if len(optional) < directory_base:
        raise ScanError("Cabeçalho opcional PE truncado.")
    entry = struct.unpack_from("<I", optional, 16)[0]
    image_base = struct.unpack_from(
        "<I" if magic == 0x10B else "<Q", optional, 28 if magic == 0x10B else 24
    )[0]
    section_alignment, file_alignment = struct.unpack_from("<II", optional, 32)
    image_size, header_size, checksum = struct.unpack_from("<III", optional, 56)
    subsystem, dll_flags = struct.unpack_from("<HH", optional, 68)
    directory_count = struct.unpack_from("<I", optional, directory_base - 4)[0]
    metadata.update(
        {
            "bits": 32 if magic == 0x10B else 64,
            "entrypoint_rva": entry,
            "image_base": image_base,
            "image_size": image_size,
            "header_size": header_size,
            "checksum_declared": checksum,
            "checksum_verified": False,
            "subsystem": subsystem,
            "aslr": bool(dll_flags & 0x40),
            "dep": bool(dll_flags & 0x100),
            "cfg": bool(dll_flags & 0x4000),
            "imports": [],
        }
    )
    if header_size > reader.size or header_size < table_offset + count * 40:
        raise ScanError("SizeOfHeaders PE incompatível com o arquivo.")
    metadata["checksum_offset"] = optional_offset + 64
    metadata["security_directory_offset"] = optional_offset + directory_base + 32
    word_sum = report.metadata.get("byte_profile", {}).get("little_endian_word_sum")
    if word_sum is not None:
        word_sum -= sum(
            value << (8 * ((optional_offset + 64 + index) % 2))
            for index, value in enumerate(optional[64:68])
        )
        if word_sum < 0:
            raise ScanError("Os bytes do checksum mudaram após a leitura integral do arquivo.")
        while word_sum >> 16:
            word_sum = (word_sum & 0xFFFF) + (word_sum >> 16)
        calculated = (word_sum + reader.size) & 0xFFFFFFFF
        metadata["checksum_calculated"] = calculated
        metadata["checksum_verified"] = bool(checksum and checksum == calculated)
        metadata["checksum_status"] = (
            "not_set" if not checksum else "match" if checksum == calculated else "mismatch"
        )
        if checksum and checksum != calculated:
            _finding(
                report,
                "pe.checksum_mismatch",
                "Checksum PE divergente",
                "O checksum declarado não coincide com os bytes integrais; não é uma assinatura criptográfica nem prova isolada de malware.",
                Severity.LOW,
                optional_offset + 64,
            )
    virtual_ranges = sorted(
        (rva, rva + max(virtual, size)) for rva, virtual, _, size, _ in sections if virtual or size
    )
    if any(start < header_size or end > 0x100000000 for start, end in virtual_ranges) or any(
        left[1] > right[0] for left, right in zip(virtual_ranges, virtual_ranges[1:], strict=False)
    ):
        report.mark_incomplete("Seções virtuais PE sobrepostas ou fora do espaço RVA.")
        _finding(
            report,
            "pe.virtual_overlap",
            "Mapeamento virtual PE ambíguo",
            "As seções sobrepõem cabeçalhos ou outros intervalos virtuais.",
            Severity.MEDIUM,
        )
    if (
        not file_alignment
        or file_alignment & (file_alignment - 1)
        or section_alignment < file_alignment
    ):
        _finding(
            report,
            "pe.alignment_anomaly",
            "Alinhamento PE inconsistente",
            "O alinhamento declarado não segue as restrições usuais do formato.",
        )
    if directory_count > (len(optional) - directory_base) // 8:
        raise ScanError("Tabela de diretórios PE ultrapassa o cabeçalho opcional.")

    def map_rva(value: int, length: int = 1) -> int:
        if value < 0 or length < 0 or value + max(1, length) > 0x100000000:
            raise ScanError("Intervalo RVA negativo ou fora do espaço de 32 bits.")
        candidates = [
            offset + value - rva
            for rva, _, offset, size, _ in sections
            if offset >= header_size
            and size
            and rva <= value < rva + size
            and value + length <= rva + size
            and offset + value - rva + length <= reader.size
        ]
        if value < header_size and value + length <= header_size:
            candidates.append(value)
        if len(candidates) != 1:
            raise ScanError(f"RVA 0x{value:x} não é mapeável de maneira inequívoca.")
        return candidates[0]

    def run_check(label, check):
        try:
            check()
        except LimitExceeded:
            raise
        except (ScanError, ValueError, struct.error) as error:
            report.mark_incomplete(f"Inspeção PE {label} incompleta: {error}")
            _finding(
                report,
                f"pe.{label}_incomplete",
                "Estrutura PE não validada por completo",
                str(error),
            )

    if entry and not any(
        rva <= entry < rva + max(virtual, size) and flags & 0x20000000
        for rva, virtual, _, size, flags in sections
    ):
        _finding(
            report,
            "pe.entrypoint_anomaly",
            "Entry point fora de seção executável",
            f"RVA de entrada 0x{entry:x} não pertence a uma seção executável.",
            Severity.MEDIUM,
        )
    directories = [
        struct.unpack_from("<II", optional, directory_base + index * 8)
        for index in range(min(directory_count, 16))
    ]
    if len(directories) > 14:
        metadata["dotnet"] = bool(directories[14][0])
    if len(directories) > 9:
        metadata["tls_directory"] = {"rva": directories[9][0], "size": directories[9][1]}
        if directories[9][0]:
            _finding(
                report,
                "pe.tls_directory",
                "Diretório TLS presente",
                "Callbacks TLS podem executar antes do entry point; a presença também é comum em programas legítimos.",
                Severity.INFO,
            )
    certificate_offset, certificate_size = directories[4] if len(directories) > 4 else (0, 0)
    run_check(
        "certificates",
        lambda: _inspect_certificates(
            reader, report, certificate_offset, certificate_size, ranges, native_path
        ),
    )
    if len(directories) > 9 and any(directories[9]):
        run_check(
            "tls",
            lambda: metadata.update(
                {
                    "tls_directory": read_tls(
                        reader,
                        map_rva,
                        *directories[9],
                        metadata["bits"],
                        image_base,
                        [(0, header_size), *virtual_ranges],
                    )
                }
            ),
        )
        for callback in metadata.get("tls_directory", {}).get("callbacks", []):
            if not any(
                rva <= callback["rva"] < rva + max(virtual, size) and flags & 0x20000000
                for rva, virtual, _, size, flags in sections
            ):
                _finding(
                    report,
                    "pe.tls_callback_anomaly",
                    "Callback TLS fora de seção executável",
                    f"O callback TLS aponta para RVA 0x{callback['rva']:x} sem permissão de execução.",
                    Severity.MEDIUM,
                    callback["offset"],
                )
    metadata["delay_imports"] = []
    if len(directories) > 13 and any(directories[13]):
        run_check(
            "delay_imports",
            lambda: metadata.update(
                {
                    "delay_imports": read_delay_imports(
                        reader, map_rva, *directories[13], metadata["bits"], image_base
                    )
                }
            ),
        )
    metadata["resources"] = []
    if len(directories) > 2 and any(directories[2]):
        run_check(
            "resources",
            lambda: read_resources(reader, map_rva, *directories[2], metadata["resources"]),
        )
    image_end = max((end for _, end in ranges), default=header_size)
    if image_end < reader.size:
        overlay_bytes = reader.size - image_end
        if certificate_size and certificate_offset >= image_end:
            overlay_bytes -= certificate_size
        metadata["overlay"] = {
            "offset": image_end,
            "size": max(0, overlay_bytes),
            "certificate_bytes_excluded": certificate_size
            if certificate_offset >= image_end
            else 0,
        }
        if overlay_bytes > 0:
            _finding(
                report,
                "pe.overlay",
                "Dados após a imagem PE",
                f"Há {overlay_bytes} bytes além das seções, descontada a tabela de certificados. Instaladores e PyInstaller usam overlays legítimos.",
                Severity.INFO,
                image_end,
            )
    if len(directories) > 1 and directories[1][0]:
        imports_rva, imports_size = directories[1]
        if imports_size < 20:
            raise ScanError("Diretório de importações PE truncado.")
        limit = min(imports_size // 20, 256)
        imports_total = sum(len(item["functions"]) for item in metadata["delay_imports"])
        terminated = False
        for index in range(limit):
            descriptor = reader.read(map_rva(imports_rva + index * 20, 20), 20)
            original, _, _, name_rva, first = struct.unpack("<IIIII", descriptor)
            if not any(descriptor):
                terminated = True
                break
            if not name_rva:
                raise ScanError("Nome da biblioteca importada ausente.")
            dll = read_rva_string(reader, map_rva, name_rva)
            functions = read_import_functions(
                reader,
                map_rva,
                original or first,
                metadata["bits"],
                reader.budget.policy.max_binary_entries - imports_total,
            )
            imports_total += len(functions)
            metadata["imports"].append({"library": dll, "functions": functions})
        if not terminated:
            raise ScanError("Diretório de importações PE sem terminador dentro do limite.")
        canonical = ",".join(
            f"{item['library'].lower().removesuffix('.dll')}.{function.lower()}"
            for item in metadata["imports"]
            for function in item["functions"]
        )
        metadata["imports_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()

def _inspect_certificates(
    reader: BinaryReader,
    report: FileReport,
    offset: int,
    size: int,
    sections: list[tuple[int, int]],
    native_path: str | None,
) -> None:
    signature = {
        "present": bool(offset or size),
        "status": "unverified" if offset or size else "unsigned",
        "records": [],
        "safety_guarantee": False,
        "image_digest_only_is_not_signature_validation": True,
    }
    report.metadata["authenticode"] = signature
    if not offset and not size:
        return
    if (
        offset < report.metadata["pe"]["header_size"]
        or size < 8
        or offset % 8
        or offset + size > reader.size
    ):
        signature["status"] = "malformed"
        raise ScanError("Diretório de certificados PE fora dos limites ou desalinhado.")
    if any(offset < end and offset + size > start for start, end in sections):
        signature["status"] = "malformed"
        raise ScanError("Tabela Authenticode sobrepõe uma seção PE.")
    data = reader.read(offset, size)
    cursor = 0
    while cursor < size:
        if len(signature["records"]) >= 32 or cursor + 8 > size:
            raise ScanError("Tabela de certificados PE excede o limite ou está truncada.")
        length, revision, kind = struct.unpack_from("<IHH", data, cursor)
        if length < 8 or cursor + length > size:
            signature["status"] = "malformed"
            raise ScanError("WIN_CERTIFICATE com comprimento inválido.")
        payload = data[cursor + 8 : cursor + length]
        record = {
            "offset": offset + cursor,
            "length": length,
            "revision": revision,
            "type": kind,
            "pkcs7_blob_sha256": hashlib.sha256(payload).hexdigest(),
        }
        signature["records"].append(record)
        if revision != 0x200 or kind != 2:
            _finding(
                report,
                "signature.certificate_type",
                "Tipo de certificado PE não convencional",
                f"Revisão={revision}, tipo={kind}; requer verificação especializada.",
            )
        if kind == 2:
            if len(payload) < 2 or payload[0] != 0x30:
                signature["status"] = "malformed"
                raise ScanError("Conteúdo PKCS#7 sem sequência ASN.1 DER válida.")
            first_length = payload[1]
            if first_length < 128:
                der_end = 2 + first_length
            else:
                length_bytes = first_length & 0x7F
                if not 1 <= length_bytes <= 4 or len(payload) < 2 + length_bytes:
                    raise ScanError("Comprimento DER não suportado ou inválido.")
                der_end = 2 + length_bytes + int.from_bytes(payload[2 : 2 + length_bytes], "big")
            if der_end > len(payload):
                raise ScanError("Objeto PKCS#7 truncado.")
            if any(payload[der_end:]):
                _finding(
                    report,
                    "signature.nonzero_padding",
                    "Dados fora do objeto PKCS#7",
                    "Bytes não nulos foram inseridos após a estrutura assinada; podem explorar diferenças de validação.",
                    Severity.HIGH,
                    offset + cursor + 8 + der_end,
                )
            try:
                record["content_digest"] = read_authenticode_digest(payload, reader.budget)
            except LimitExceeded:
                raise
            except ScanError as error:
                record["content_digest"] = {"status": "unavailable", "reason": str(error)}
                report.mark_incomplete(f"Digest embutido Authenticode não interpretado: {error}")
        aligned_end = (cursor + length + 7) & ~7
        if aligned_end > size or any(data[cursor + length : aligned_end]):
            raise ScanError("Preenchimento WIN_CERTIFICATE inválido.")
        cursor = aligned_end
    digests = [
        record["content_digest"]
        for record in signature["records"]
        if record.get("content_digest", {}).get("status") == "not_compared"
    ]
    if digests:
        try:
            computed = hash_authenticode_image(
                reader,
                report.metadata["pe"],
                offset,
                size,
                {item["algorithm"] for item in digests},
            )
            signature["image_hashes"] = computed
            for item in digests:
                item["calculated_digest"] = computed[item["algorithm"]]
                item["status"] = (
                    "match"
                    if hmac.compare_digest(item["declared_digest"], item["calculated_digest"])
                    else "mismatch"
                )
                if item["status"] == "mismatch":
                    _finding(
                        report,
                        "signature.image_digest_mismatch",
                        "Digest Authenticode divergente",
                        "Os bytes cobertos da imagem não correspondem ao digest declarado no PKCS#7; o conteúdo foi alterado ou a assinatura está malformada.",
                        Severity.HIGH,
                        offset,
                    )
                if item["algorithm"] in {"md5", "sha1"}:
                    _finding(
                        report,
                        "signature.weak_digest",
                        "Algoritmo de assinatura legado",
                        f"O digest usa {item['algorithm'].upper()}, inadequado para novas garantias de integridade.",
                        Severity.LOW,
                        offset,
                    )
        except LimitExceeded:
            raise
        except ScanError as error:
            for item in digests:
                item.update({"status": "unavailable", "reason": str(error)})
            report.mark_incomplete(str(error))
    signature.update(verify_authenticode(reader.stream, native_path))
    if any(item.get("status") == "mismatch" for item in digests):
        signature["status"] = "invalid"
        signature["reason"] = "O digest da imagem diverge do conteúdo declarado na assinatura."
    state = signature["status"]
    if state == "invalid":
        _finding(
            report,
            "signature.invalid",
            "Assinatura digital inválida",
            signature["reason"],
            Severity.HIGH,
            offset,
        )
    elif state == "untrusted":
        _finding(
            report,
            "signature.untrusted",
            "Assinatura sem confiança confirmada",
            signature["reason"],
            Severity.MEDIUM,
            offset,
        )
    elif state == "unverified":
        report.mark_incomplete(signature["reason"])
        _finding(
            report,
            "signature.unverified",
            "Assinatura presente, mas não validada",
            signature["reason"],
            Severity.INFO,
            offset,
        )
    if len(signature["records"]) > 1:
        report.mark_incomplete("Assinaturas PE secundárias não foram verificadas individualmente.")

def _inspect_elf(reader: BinaryReader, report: FileReport) -> None:
    identity = reader.read(0, 16)
    if identity[4] not in (1, 2) or identity[5] not in (1, 2) or identity[6] != 1:
        raise ScanError("Classe, endian ou versão ELF inválida.")
    bits = 32 if identity[4] == 1 else 64
    endian = "<" if identity[5] == 1 else ">"
    values = reader.unpack(endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"), 16)
    (
        kind,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phsize,
        phcount,
        shsize,
        shcount,
        shstr,
    ) = values
    if ehsize != (52 if bits == 32 else 64) or version != 1:
        raise ScanError("Tamanho ou versão do cabeçalho ELF inválido.")
    if phcount == 0xFFFF or shstr == 0xFFFF or (shoff and shcount == 0):
        raise ScanError("Numeração estendida ELF requer parser adicional.")
    if max(phcount, shcount) > reader.budget.policy.max_binary_entries:
        raise ScanError("Quantidade de cabeçalhos ELF excede o limite.")
    if phcount and (phsize != (32 if bits == 32 else 56) or phoff + phsize * phcount > reader.size):
        raise ScanError("Tabela de segmentos ELF fora do arquivo.")
    if shcount and (
        shsize != (40 if bits == 32 else 64)
        or shoff + shsize * shcount > reader.size
        or shstr >= shcount
    ):
        raise ScanError("Tabela de seções ELF fora do arquivo.")
    metadata = {
        "bits": bits,
        "byte_order": "little" if endian == "<" else "big",
        "type": kind,
        "machine": machine,
        "entrypoint": entry,
        "flags": flags,
        "segments": [],
        "section_count": shcount,
    }
    report.metadata["elf"] = metadata
    executable_entry = not entry
    for index in range(phcount):
        values = reader.unpack(endian + ("8I" if bits == 32 else "II6Q"), phoff + index * phsize)
        if bits == 32:
            ptype, offset, virtual, _, file_size, memory_size, protection, alignment = values
        else:
            ptype, protection, offset, virtual, _, file_size, memory_size, alignment = values
        if offset + file_size > reader.size or (ptype == 1 and file_size > memory_size):
            raise ScanError("Segmento ELF fora do arquivo ou maior que a memória declarada.")
        metadata["segments"].append(
            {
                "type": ptype,
                "offset": offset,
                "file_size": file_size,
                "virtual_address": virtual,
                "memory_size": memory_size,
                "flags": protection,
                "alignment": alignment,
            }
        )
        executable_entry |= bool(
            ptype == 1 and protection & 1 and virtual <= entry < virtual + memory_size
        )
        if ptype == 1 and protection & 3 == 3:
            _finding(
                report,
                "elf.writable_executable",
                "Segmento ELF gravável e executável",
                f"Segmento {index} permite escrita e execução.",
                Severity.MEDIUM,
                offset,
            )
        if ptype == 0x6474E551 and protection & 1:
            _finding(
                report,
                "elf.executable_stack",
                "Pilha ELF executável",
                "PT_GNU_STACK solicita execução de memória da pilha.",
                Severity.MEDIUM,
            )
        if ptype == 3:
            raw = reader.read(offset, min(file_size, 4096))
            if not raw.endswith(b"\x00") or file_size > 4096:
                raise ScanError("Caminho de interpretador ELF inválido.")
            metadata["interpreter"] = raw[:-1].decode("utf-8", errors="replace")
    if not executable_entry:
        _finding(
            report,
            "elf.entrypoint_anomaly",
            "Entry point ELF fora de segmento executável",
            "O endereço de entrada não está mapeado em segmento executável.",
            Severity.MEDIUM,
        )
    for index in range(shcount):
        values = reader.unpack(
            endian + ("10I" if bits == 32 else "II4QII2Q"), shoff + index * shsize
        )
        _, section_type, _, _, offset, size, _, _, _, _ = values
        if section_type != 8 and offset + size > reader.size:
            raise ScanError(f"Seção ELF {index} ultrapassa o arquivo.")

def _inspect_macho(reader: BinaryReader, report: FileReport) -> None:
    magic = reader.read(0, 4)
    if report.kind == "java_or_fat_macho":
        report.mark_incomplete(
            "Arquivo Java ou Mach-O universal exige inspeção específica adicional."
        )
        return
    endian = "<" if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
    bits = 64 if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf") else 32
    header_size = 32 if bits == 64 else 28
    _, cpu, subtype, filetype, count, command_size, flags = reader.unpack(endian + "7I", 0)
    if count > reader.budget.policy.max_binary_entries or header_size + command_size > reader.size:
        raise ScanError("Tabela de comandos Mach-O excede os limites.")
    metadata = {
        "bits": bits,
        "cpu": cpu,
        "subtype": subtype,
        "file_type": filetype,
        "flags": flags,
        "libraries": [],
        "segments": [],
    }
    report.metadata["macho"] = metadata
    cursor = header_size
    end = cursor + command_size
    for _ in range(count):
        command, size = reader.unpack(endian + "II", cursor)
        if size < 8 or size % 4 or cursor + size > end:
            raise ScanError("Comando Mach-O truncado ou desalinhado.")
        if command in (1, 0x19):
            segment64 = command == 0x19
            base_size = 72 if segment64 else 56
            data = reader.read(cursor, base_size)
            if size < base_size:
                raise ScanError("Comando de segmento Mach-O truncado.")
            name = data[8:24].rstrip(b"\x00").decode("ascii", errors="replace")
            virtual, virtual_size, offset, file_size, maximum, protection, sections, _ = (
                struct.unpack_from(endian + ("4Q4I" if segment64 else "8I"), data, 24)
            )
            if (
                offset + file_size > reader.size
                or base_size + sections * (80 if segment64 else 68) > size
            ):
                raise ScanError("Segmento ou seções Mach-O fora dos limites.")
            metadata["segments"].append(
                {
                    "name": name,
                    "offset": offset,
                    "size": file_size,
                    "virtual_address": virtual,
                    "virtual_size": virtual_size,
                    "protection": protection,
                    "maximum_protection": maximum,
                }
            )
            if protection & 6 == 6:
                _finding(
                    report,
                    "macho.writable_executable",
                    "Segmento Mach-O gravável e executável",
                    f"Segmento {name!r} permite escrita e execução.",
                    Severity.MEDIUM,
                )
        elif command in (0xC, 0x18, 0x80000018, 0x8000001F, 0x80000023):
            relative = reader.unpack(endian + "I", cursor + 8)[0]
            if not 24 <= relative < size:
                raise ScanError("Nome de biblioteca Mach-O fora do comando.")
            metadata["libraries"].append(
                reader.cstring(cursor + relative, min(size - relative, 4096))
            )
        elif command == 0x1D:
            if size < 16:
                raise ScanError("Comando de assinatura Mach-O truncado.")
            offset, length = reader.unpack(endian + "II", cursor + 8)
            if offset + length > reader.size:
                raise ScanError("Assinatura Mach-O fora do arquivo.")
            metadata["code_signature"] = {"offset": offset, "size": length, "status": "unverified"}
            report.mark_incomplete("Assinatura de código Mach-O não validada criptograficamente.")
        cursor += size
    if cursor != end:
        raise ScanError("Tamanho agregado dos comandos Mach-O inconsistente.")
