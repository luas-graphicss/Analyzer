import bz2
import lzma
import struct
import zlib
from typing import BinaryIO

from .policy import ScanBudget, ScanError

class BinaryReader:
    def __init__(self, stream: BinaryIO, size: int, budget: ScanBudget) -> None:
        self.stream = stream
        self.size = size
        self.budget = budget

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ScanError(f"Intervalo binário fora do arquivo: offset={offset}, bytes={length}.")
        if length > self.budget.policy.max_metadata_bytes:
            raise ScanError("A leitura excede o limite de metadados por operação.")
        self.budget.consume_inspection(length)
        self.stream.seek(offset)
        result = self.stream.read(length)
        if len(result) != length:
            raise ScanError("Leitura estrutural truncada ou arquivo alterado durante a análise.")
        return result

    def unpack(self, specification: str, offset: int) -> tuple:
        return struct.unpack(specification, self.read(offset, struct.calcsize(specification)))

    def cstring(self, offset: int, maximum: int = 256) -> str:
        data = self.read(offset, min(maximum, self.size - offset))
        end = data.find(b"\x00")
        if end < 0:
            raise ScanError("String binária sem terminador dentro do limite permitido.")
        return data[:end].decode("utf-8", errors="replace")

class RangeReader:
    def __init__(self, reader: BinaryReader, start: int, length: int) -> None:
        if start < 0 or length < 0 or start + length > reader.size:
            raise ScanError("O conteúdo embutido aponta para fora do arquivo.")
        self.reader = reader
        self.start = start
        self.length = length
        self.position = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.length - self.position
        length = min(remaining, size if size >= 0 else self.reader.budget.policy.chunk_size)
        length = min(length, self.reader.budget.policy.max_metadata_bytes)
        data = self.reader.read(self.start + self.position, length)
        self.position += length
        return data

class DecompressionReader:
    def __init__(self, source: BinaryIO | RangeReader, codec: str = "zlib") -> None:
        self.source = source
        self.codec = codec
        self.pending = b""
        self.finished = False
        if codec in {"zlib", "deflate"}:
            self.decoder = zlib.decompressobj(-15 if codec == "deflate" else 15)
        elif codec == "bzip2":
            self.decoder = bz2.BZ2Decompressor()
        elif codec == "xz":
            self.decoder = lzma.LZMADecompressor(memlimit=64 * 1024 * 1024)
        else:
            raise ValueError("Codec de descompressão não suportado.")

    def read(self, size: int = 65536) -> bytes:
        if size <= 0 or self.finished:
            return b""
        output = bytearray()
        while len(output) < size:
            if self.decoder.eof:
                trailing = self.decoder.unused_data + self.source.read(1)
                if trailing:
                    raise ScanError(
                        "Há dados adicionais após o fluxo comprimido; não foram ignorados."
                    )
                self.finished = True
                break
            if self.codec in {"zlib", "deflate"}:
                block = self.pending or self.source.read(65536)
            elif self.decoder.needs_input:
                block = self.source.read(65536)
            else:
                block = b""
            if not block and (self.codec in {"zlib", "deflate"} or self.decoder.needs_input):
                raise ScanError("Fluxo comprimido truncado, corrompido ou criptografado.")
            try:
                decoded = self.decoder.decompress(block, size - len(output))
            except (zlib.error, lzma.LZMAError, EOFError, OSError) as error:
                raise ScanError(f"Falha ao descomprimir conteúdo {self.codec}: {error}") from error
            output.extend(decoded)
            if self.codec in {"zlib", "deflate"}:
                self.pending = self.decoder.unconsumed_tail
        return bytes(output)
