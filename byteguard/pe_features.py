from collections.abc import Callable

from .binary_io import BinaryReader
from .policy import LimitExceeded, ScanError

MapRVA = Callable[[int, int], int]

def read_rva_string(reader: BinaryReader, map_rva: MapRVA, rva: int) -> str:
    value = bytearray()
    for index in range(4096):
        character = reader.read(map_rva(rva + index, 1), 1)
        if character == b"\x00":
            if not value:
                raise ScanError("Nome PE vazio.")
            return value.decode("utf-8", errors="replace")
        value.extend(character)
    raise ScanError("Nome PE sem terminador dentro do limite.")

def read_import_functions(
    reader: BinaryReader,
    map_rva: MapRVA,
    thunk: int,
    bits: int,
    remaining: int,
    image_base: int = 0,
) -> list[str]:
    if not thunk:
        raise ScanError("Tabela de funções PE ausente.")
    width = bits // 8
    ordinal_mask = 1 << (bits - 1)
    result = []
    for index in range(remaining + 1):
        value = reader.unpack("<I" if bits == 32 else "<Q", map_rva(thunk + index * width, width))[
            0
        ]
        if not value:
            return result
        if len(result) >= remaining:
            raise LimitExceeded("O limite cumulativo de funções importadas foi atingido.")
        if value & ordinal_mask:
            if value & ~(ordinal_mask | 0xFFFF):
                raise ScanError("Importação ordinal PE possui bits reservados ativos.")
            result.append(f"ordinal:{value & 0xFFFF}")
        else:
            result.append(read_rva_string(reader, map_rva, value - image_base + 2))
    raise ScanError("Tabela de importações PE sem terminador.")

def read_delay_imports(
    reader: BinaryReader,
    map_rva: MapRVA,
    rva: int,
    size: int,
    bits: int,
    image_base: int,
) -> list[dict]:
    if size < 32:
        raise ScanError("Diretório de importações adiadas truncado.")
    imports = []
    remaining = reader.budget.policy.max_binary_entries
    for index in range(min(size // 32, reader.budget.policy.max_binary_entries)):
        values = reader.unpack("<8I", map_rva(rva + index * 32, 32))
        if not any(values):
            return imports
        attributes, name, _, iat, names, _, _, timestamp = values
        if attributes not in (0, 1) or not name or not names or not iat:
            raise ScanError("Descritor de importação adiada inválido.")
        base = 0 if attributes else image_base
        library = read_rva_string(reader, map_rva, name - base)
        functions = read_import_functions(reader, map_rva, names - base, bits, remaining, base)
        remaining -= len(functions)
        imports.append({"library": library, "functions": functions, "timestamp": timestamp})
    raise ScanError("Importações adiadas sem terminador dentro do limite.")

def read_tls(
    reader: BinaryReader,
    map_rva: MapRVA,
    rva: int,
    size: int,
    bits: int,
    image_base: int,
    virtual_ranges: list[tuple[int, int]],
) -> dict:
    required = 24 if bits == 32 else 40
    if size < required:
        raise ScanError("Diretório TLS PE truncado.")
    start, end, index, callbacks, zero_fill, flags = reader.unpack(
        "<6I" if bits == 32 else "<4Q2I", map_rva(rva, required)
    )
    if end < start or (start and start < image_base):
        raise ScanError("Intervalo de inicialização TLS inválido.")
    if end > start:
        map_rva(start - image_base, end - start)
    if (
        index
        and sum(
            left <= index - image_base and index - image_base + 4 <= right
            for left, right in virtual_ranges
        )
        != 1
    ):
        raise ScanError("Índice TLS fora de uma região virtual inequívoca.")
    result = {
        "rva": rva,
        "size": size,
        "template_size": end - start,
        "index_rva": index - image_base if index else None,
        "zero_fill": zero_fill,
        "flags": flags,
        "callbacks": [],
        "callbacks_executed": False,
    }
    if not callbacks:
        return result
    width = bits // 8
    for position in range(reader.budget.policy.max_binary_entries + 1):
        value = reader.unpack(
            "<I" if bits == 32 else "<Q",
            map_rva(callbacks - image_base + position * width, width),
        )[0]
        if not value:
            return result
        if len(result["callbacks"]) >= reader.budget.policy.max_binary_entries:
            raise LimitExceeded("O limite de callbacks TLS foi atingido.")
        callback_rva = value - image_base
        result["callbacks"].append(
            {"virtual_address": value, "rva": callback_rva, "offset": map_rva(callback_rva, 1)}
        )
    raise LimitExceeded("A lista de callbacks TLS excede o limite ou não possui terminador.")

def read_resources(
    reader: BinaryReader,
    map_rva: MapRVA,
    rva: int,
    size: int,
    output: list[dict],
) -> None:
    visited: set[int] = set()
    entry_count = 0

    def read(relative: int, length: int) -> bytes:
        if relative < 0 or relative + length > size:
            raise ScanError("Metadados de recurso PE ultrapassam seu diretório.")
        return reader.read(map_rva(rva + relative, length), length)

    def name(value: int) -> str | int:
        if not value & 0x80000000:
            return value
        offset = value & 0x7FFFFFFF
        length = int.from_bytes(read(offset, 2), "little")
        if length > 1024:
            raise LimitExceeded("Nome de recurso PE excessivamente longo.")
        return read(offset + 2, length * 2).decode("utf-16-le", errors="strict")

    def visit(relative: int, path: tuple[str | int, ...]) -> None:
        nonlocal entry_count
        reader.budget.check_time()
        if len(path) > 8 or relative in visited:
            raise ScanError("Árvore de recursos PE recursiva ou ambígua.")
        visited.add(relative)
        header = read(relative, 16)
        named = int.from_bytes(header[12:14], "little")
        numbered = int.from_bytes(header[14:16], "little")
        entry_count += named + numbered
        if entry_count > reader.budget.policy.max_binary_entries:
            raise LimitExceeded("O limite cumulativo de entradas de recursos PE foi atingido.")
        labels: set[str | int] = set()
        for index in range(named + numbered):
            entry = read(relative + 16 + index * 8, 8)
            identifier = int.from_bytes(entry[:4], "little")
            target = int.from_bytes(entry[4:], "little")
            if bool(identifier & 0x80000000) != (index < named):
                raise ScanError("Nomes e IDs de recursos PE contradizem o diretório.")
            label = name(identifier)
            if label in labels:
                raise ScanError("Identificador de recurso PE duplicado.")
            labels.add(label)
            next_path = (*path, label)
            if target & 0x80000000:
                visit(target & 0x7FFFFFFF, next_path)
                continue
            description = read(target, 16)
            data_rva = int.from_bytes(description[:4], "little")
            length = int.from_bytes(description[4:8], "little")
            codepage = int.from_bytes(description[8:12], "little")
            if any(description[12:]):
                raise ScanError("Campo reservado de recurso PE não é zero.")
            offset = map_rva(data_rva, length)
            output.append(
                {
                    "path": list(next_path),
                    "offset": offset,
                    "size": length,
                    "codepage": codepage,
                    "scanned": False,
                }
            )

    visit(0, ())
