import struct
from dataclasses import dataclass
from typing import Any

from .binary_io import BinaryReader
from .policy import LimitExceeded, ScanError

COOKIE_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
MARSHAL_NULL = object()
MARSHAL_PENDING = object()

@dataclass(frozen=True, slots=True)
class PackedEntry:
    name: str
    offset: int
    stored_size: int
    expanded_size: int | None
    compressed: bool
    typecode: str

@dataclass(frozen=True, slots=True)
class CArchive:
    start: int
    end: int
    python_version: int
    python_library: str
    entries: tuple[PackedEntry, ...]
    unindexed_ranges: tuple[tuple[int, int], ...] = ()

def uncovered_ranges(
    start: int, end: int, ranges: list[tuple[int, int]]
) -> tuple[tuple[int, int], ...]:
    cursor = start
    result = []
    for left, right in sorted(ranges):
        if left < cursor or right < left or right > end:
            raise ScanError("Intervalos de pacote sobrepostos ou fora dos limites.")
        if left > cursor:
            result.append((cursor, left))
        cursor = right
    if cursor < end:
        result.append((cursor, end))
    return tuple(result)

class RestrictedMarshalReader:
    def __init__(self, data: bytes, max_items: int) -> None:
        self.data = data
        self.position = 0
        self.max_items = max_items
        self.nodes = 0
        self.references: list[Any] = []

    def take(self, count: int) -> bytes:
        if count < 0 or self.position + count > len(self.data):
            raise ScanError("Metadados PYZ truncados ou com tamanho inválido.")
        value = self.data[self.position : self.position + count]
        self.position += count
        return value

    def integer(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def load(self) -> Any:
        value = self.value()
        if self.position != len(self.data):
            raise ScanError("Dados não interpretados após a tabela PYZ.")
        return value

    def value(self, depth: int = 0) -> Any:
        self.nodes += 1
        if depth > 32 or self.nodes > self.max_items * 12 + 128:
            raise ScanError("A complexidade dos metadados PYZ excede o limite.")
        tag = self.take(1)[0]
        reference = bool(tag & 0x80)
        tag &= 0x7F
        slot = None
        if reference:
            slot = len(self.references)
            self.references.append(MARSHAL_PENDING)
        if tag == ord("0"):
            result = MARSHAL_NULL
        elif tag == ord("N"):
            result = None
        elif tag in (ord("T"), ord("F")):
            result = tag == ord("T")
        elif tag == ord("i"):
            result = self.integer()
        elif tag == ord("I"):
            result = struct.unpack("<q", self.take(8))[0]
        elif tag == ord("l"):
            count = self.integer()
            if abs(count) > 4:
                raise ScanError("Inteiro PYZ excede o limite de 60 bits.")
            result = 0
            for index in range(abs(count)):
                digit = struct.unpack("<H", self.take(2))[0]
                if digit >= 32768:
                    raise ScanError("Dígito de inteiro PYZ inválido.")
                result |= digit << (15 * index)
            if count < 0:
                result = -result
        elif tag in map(ord, "stuazAZ"):
            length = self.take(1)[0] if tag in map(ord, "zZ") else self.integer()
            if not 0 <= length <= 65536:
                raise ScanError("String de metadados PYZ excede o limite.")
            raw = self.take(length)
            result = raw if tag in map(ord, "st") else raw.decode("utf-8", errors="strict")
        elif tag in map(ord, "([)"):
            count = self.take(1)[0] if tag == ord(")") else self.integer()
            if not 0 <= count <= self.max_items:
                raise ScanError("Quantidade de objetos PYZ excede o limite.")
            values = [self.value(depth + 1) for _ in range(count)]
            result = values if tag == ord("[") else tuple(values)
        elif tag == ord("{"):
            result = []
            seen: set[str | bytes] = set()
            while True:
                key = self.value(depth + 1)
                if key is MARSHAL_NULL:
                    break
                if not isinstance(key, (str, bytes)) or key in seen:
                    raise ScanError("Chave PYZ inválida ou duplicada.")
                seen.add(key)
                if len(seen) > self.max_items:
                    raise ScanError("A tabela PYZ excede o limite de entradas.")
                result.append((key, self.value(depth + 1)))
        elif tag == ord("r"):
            index = self.integer()
            if not 0 <= index < len(self.references):
                raise ScanError("Referência PYZ fora da tabela.")
            result = self.references[index]
            if result is MARSHAL_PENDING:
                raise ScanError("Referência PYZ recursiva ou adiantada recusada.")
        else:
            raise ScanError(f"Tipo marshal 0x{tag:02x} recusado; código não é desserializado.")
        if slot is not None:
            self.references[slot] = result
        return result

def read_carchive(reader: BinaryReader, cookie_offset: int) -> CArchive:
    failures = []
    for cookie_size in (88, 24):
        try:
            cookie = reader.read(cookie_offset, cookie_size)
            magic, package_size, toc_offset, toc_size, version = struct.unpack_from(
                "!8sIIII", cookie
            )
            if magic != COOKIE_MAGIC or not 20 <= version <= 399:
                raise ScanError("Cookie MEI inválido.")
            if cookie_size == 24 and version >= 100:
                raise ScanError("Cookie moderno não pode ser reinterpretado como formato legado.")
            end = cookie_offset + cookie_size
            start = end - package_size
            if start < 0 or package_size < cookie_size or toc_size < 0:
                raise ScanError("Tamanho de pacote MEI inconsistente.")
            if toc_offset + toc_size > package_size - cookie_size:
                raise ScanError("Tabela MEI ultrapassa o limite do pacote.")
            library = ""
            if cookie_size == 88:
                raw_library, separator, padding = cookie[24:].partition(b"\x00")
                library = raw_library.decode("ascii", errors="strict")
                if not separator or any(padding):
                    raise ScanError("Preenchimento da biblioteca Python no cookie MEI inválido.")
                if not library or any(ord(character) < 32 for character in library):
                    raise ScanError("Biblioteca Python declarada no cookie MEI inválida.")
            toc = reader.read(start + toc_offset, toc_size)
            cursor = 0
            entries = []
            ranges = []
            while cursor < len(toc):
                reader.budget.check_time()
                if len(entries) >= reader.budget.policy.max_archive_members:
                    raise ScanError("O pacote MEI excede o limite de entradas.")
                if cursor + 18 > len(toc):
                    raise ScanError("Entrada MEI truncada.")
                length, position, stored, expanded, compressed, kind = struct.unpack_from(
                    "!IIIIBc", toc, cursor
                )
                if length < 19 or cursor + length > len(toc) or compressed not in (0, 1):
                    raise ScanError("Comprimento ou flag da entrada MEI inválido.")
                raw_name = toc[cursor + 18 : cursor + length]
                name_end = raw_name.find(b"\x00")
                if name_end < 0 or any(raw_name[name_end:]):
                    raise ScanError("Nome MEI sem terminador ou com preenchimento inconsistente.")
                name = raw_name[:name_end].decode("utf-8", errors="strict")
                if not name:
                    raise ScanError("Nome MEI vazio.")
                typecode = kind.decode("ascii", errors="strict")
                if position + stored > toc_offset:
                    raise ScanError("Conteúdo MEI sobrepõe metadados ou ultrapassa o pacote.")
                if not compressed and stored != expanded:
                    raise ScanError("Tamanhos de entrada MEI não comprimida são inconsistentes.")
                entries.append(
                    PackedEntry(
                        name, start + position, stored, expanded, bool(compressed), typecode
                    )
                )
                if stored:
                    ranges.append((position, position + stored))
                cursor += length
            ranges.sort()
            if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:], strict=False)):
                raise ScanError("Entradas MEI sobrepostas recusadas.")
            gaps = uncovered_ranges(
                0, package_size - cookie_size, [*ranges, (toc_offset, toc_offset + toc_size)]
            )
            return CArchive(
                start,
                end,
                version,
                library,
                tuple(entries),
                tuple((start + left, start + right) for left, right in gaps),
            )
        except LimitExceeded:
            raise
        except (ScanError, UnicodeError, struct.error) as error:
            failures.append(str(error))
    raise ScanError("Cookie PyInstaller/MEI não validado: " + "; ".join(failures))

def read_pyz(reader: BinaryReader) -> tuple[PackedEntry, ...]:
    header = reader.read(0, 12)
    if header[:4] != b"PYZ\x00":
        raise ScanError("Assinatura PYZ inválida.")
    toc_offset = struct.unpack_from("!I", header, 8)[0]
    if not 12 <= toc_offset < reader.size:
        raise ScanError("Offset da tabela PYZ fora do arquivo.")
    raw = reader.read(toc_offset, reader.size - toc_offset)
    table = RestrictedMarshalReader(raw, reader.budget.policy.max_archive_members).load()
    if not isinstance(table, (list, tuple)):
        raise ScanError("A tabela PYZ não é uma sequência de entradas.")
    entries = []
    seen = set()
    ranges = []
    for item in table:
        reader.budget.check_time()
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise ScanError("Entrada PYZ inválida.")
        name, details = item
        if isinstance(name, bytes):
            name = name.decode("utf-8", errors="strict")
        if not isinstance(name, str) or not name or name in seen:
            raise ScanError("Nome de módulo PYZ inválido ou duplicado.")
        seen.add(name)
        if not isinstance(details, (tuple, list)) or len(details) != 3:
            raise ScanError("Metadados de módulo PYZ inválidos.")
        typecode, offset, size = details
        if any(type(value) is not int for value in details) or typecode not in (0, 1, 2, 3):
            raise ScanError("Tipo ou intervalo PYZ inválido.")
        if typecode == 3:
            if size != 0 or not 0 <= offset <= toc_offset:
                raise ScanError("Namespace PYZ com conteúdo ou offset inesperado.")
            continue
        if offset < 12 or size <= 0 or offset + size > toc_offset:
            raise ScanError("Módulo PYZ ultrapassa o limite do conteúdo.")
        ranges.append((offset, offset + size))
        entries.append(PackedEntry(name, offset, size, None, True, str(typecode)))
    ranges.sort()
    if any(left[1] > right[0] for left, right in zip(ranges, ranges[1:], strict=False)):
        raise ScanError("Módulos PYZ sobrepostos recusados.")
    return tuple(entries)
