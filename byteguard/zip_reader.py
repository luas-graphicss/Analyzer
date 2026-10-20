import binascii
import struct
import zipfile

from .binary_io import BinaryReader, DecompressionReader, RangeReader
from .policy import ScanError

class CheckedZipReader:
    def __init__(self, source, member: zipfile.ZipInfo) -> None:
        self.source = source
        self.member = member
        self.total = 0
        self.crc = 0

    def read(self, size: int = 65536) -> bytes:
        if size <= 0:
            return b""
        block = self.source.read(size)
        self.total += len(block)
        self.crc = binascii.crc32(block, self.crc)
        if self.total > self.member.file_size:
            raise ScanError(
                "O ZIP produz mais bytes que o tamanho declarado; conteúdo oculto possível."
            )
        if not block:
            if self.total != self.member.file_size:
                raise ScanError("O tamanho real do membro ZIP diverge dos metadados.")
            if self.crc != self.member.CRC:
                raise ScanError(
                    "O CRC32 do membro ZIP não confere; a integridade não foi confirmada."
                )
        return block

def unindexed_zip_records(
    reader: BinaryReader, members: list[zipfile.ZipInfo], directory_start: int, markers: list[int]
) -> list[int]:
    ranges = []
    for member in sorted(members, key=lambda item: item.header_offset):
        offset = member.header_offset
        fields = reader.unpack("<4s5H3I2H", offset)
        if fields[0] != b"PK\x03\x04":
            raise ScanError("Cabeçalho ZIP referenciado pelo diretório não existe.")
        end = offset + 30 + fields[-2] + fields[-1] + member.compress_size
        if end > directory_start or (ranges and offset < ranges[-1][1]):
            raise ScanError("Regiões ZIP sobrepostas ou que invadem o diretório central.")
        if member.flag_bits & 8:
            signed = end + 4 <= directory_start and reader.read(end, 4) == b"PK\x07\x08"
            end += 16 if signed else 12
            if end > directory_start:
                raise ScanError("Descritor ZIP invade o diretório central.")
        ranges.append((offset, end))
    unused = []
    for offset in markers:
        reader.budget.check_time()
        if offset >= directory_start or any(start <= offset < end for start, end in ranges):
            continue
        if offset + 30 > directory_start:
            unused.append(offset)
            continue
        fields = reader.unpack("<4s5H3I2H", offset)
        plausible = (
            fields[0] == b"PK\x03\x04"
            and 10 <= fields[1] <= 63
            and fields[-2] > 0
            and offset + 30 + fields[-2] + fields[-1] <= directory_start
        )
        if plausible or offset == 0:
            unused.append(offset)
    return unused

def open_checked_zip_member(
    reader: BinaryReader, member: zipfile.ZipInfo, boundary: int
) -> CheckedZipReader:
    offset = member.header_offset
    if offset < 0 or offset + 30 > boundary or boundary > reader.size:
        raise ScanError("Cabeçalho local ZIP fora da região permitida.")
    fields = reader.unpack("<4s5H3I2H", offset)
    magic, _, flags, method, _, _, crc, stored_size, expanded_size, name_size, extra_size = fields
    if magic != b"PK\x03\x04":
        raise ScanError("Assinatura do cabeçalho local ZIP inválida.")
    if flags != member.flag_bits or method != member.compress_type:
        raise ScanError("Método ou flags divergem entre os cabeçalhos ZIP local e central.")
    if flags & ~0x080E:
        raise ScanError("O ZIP utiliza flags de criptografia ou recursos não suportados.")
    if stored_size == 0xFFFFFFFF or expanded_size == 0xFFFFFFFF:
        raise ScanError("Cabeçalho local ZIP64 não suportado pelo leitor limitado.")
    start = offset + 30 + name_size + extra_size
    end = start + member.compress_size
    if start > boundary or end > boundary:
        raise ScanError("Membros ZIP sobrepostos ou dados fora do diretório permitido.")
    raw_name = reader.read(offset + 30, name_size)
    local_name = raw_name.decode("utf-8" if flags & 0x800 else "cp437")
    if "\x00" in local_name or local_name != member.orig_filename:
        raise ScanError("Nome ZIP local ambíguo ou diferente do diretório central.")
    extra = reader.read(offset + 30 + name_size, extra_size)
    cursor = 0
    while cursor < len(extra):
        if cursor + 4 > len(extra):
            raise ScanError("Metadados extras ZIP truncados.")
        _, length = struct.unpack_from("<HH", extra, cursor)
        cursor += 4 + length
        if cursor > len(extra):
            raise ScanError("Metadados extras ZIP excedem o cabeçalho local.")
    expected = (member.CRC, member.compress_size, member.file_size)
    actual = (crc, stored_size, expanded_size)
    if flags & 8:
        if any(value not in (0, target) for value, target in zip(actual, expected, strict=True)):
            raise ScanError("Metadados locais ZIP contradizem o descritor de dados.")
        candidates = [end]
        if end + 4 <= boundary and reader.read(end, 4) == b"PK\x07\x08":
            candidates.insert(0, end + 4)
        if not any(
            position + 12 <= boundary and reader.unpack("<III", position) == expected
            for position in candidates
        ):
            raise ScanError("Descritor de dados ZIP ausente, truncado ou inconsistente.")
    elif actual != expected:
        raise ScanError("CRC ou tamanhos divergem entre os cabeçalhos ZIP local e central.")
    if method == zipfile.ZIP_STORED and member.compress_size != member.file_size:
        raise ScanError("Membro ZIP sem compressão tem tamanhos incompatíveis.")
    source = RangeReader(reader, start, member.compress_size)
    if method == zipfile.ZIP_DEFLATED:
        source = DecompressionReader(source, "deflate")
    elif method == zipfile.ZIP_BZIP2:
        source = DecompressionReader(source, "bzip2")
    elif method != zipfile.ZIP_STORED:
        raise ScanError("Método de compressão ZIP não suportado.")
    return CheckedZipReader(source, member)
