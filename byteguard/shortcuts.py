import io
import re
import struct
from collections.abc import Callable

from .binary_io import BinaryReader, RangeReader
from .models import FileReport, Finding, Severity
from .policy import ScanError

LINK_CLSID = bytes.fromhex("0114020000000000c000000000000046")
STRING_FIELDS = (
    (4, "description"),
    (8, "relative_path"),
    (16, "working_directory"),
    (32, "arguments"),
    (64, "icon_location"),
)
TARGET_FIELDS = (
    "local_path_unicode",
    "local_path",
    "relative_path",
    "environment_target",
    "network_name_unicode",
    "network_name",
)
LAUNCHER = re.compile(
    r"(?:^|[\\/\s\"\'])((?:powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msbuild|installutil|certutil|bitsadmin)(?:\.exe)?)(?=$|[\s\"\'])",
    re.IGNORECASE,
)
ENCODED_ARGUMENT = re.compile(r"(?:^|\s)-(?:e|ec|enc|encodedcommand)\s+\S+", re.IGNORECASE)
REMOTE = re.compile(r"^(?:\\\\|//|(?:https?|ftp):)", re.IGNORECASE)

def remote_reference(value: str) -> bool:
    target = value.strip().strip('"').casefold()
    for prefix in ("\\\\?\\", "\\\\.\\", "\\??\\"):
        if target.startswith(prefix):
            return target[len(prefix) :].startswith("unc\\")
    if target.startswith("file:"):
        from urllib.parse import urlsplit

        try:
            return urlsplit(target).hostname not in (None, "", "localhost", "127.0.0.1", "::1")
        except ValueError:
            return True
    return bool(REMOTE.match(target))

class ShortcutInspector:
    def __init__(self, reader: BinaryReader, report: FileReport) -> None:
        self.reader = reader
        self.report = report
        self.count = 0
        self.flags = 0
        self.fields: dict[str, str] = {}
        self.offsets: dict[str, int] = {}
        self.blocks: set[int] = set()
        self.metadata = {
            "fields": self.fields,
            "field_offsets": self.offsets,
            "extra_blocks": [],
            "target_resolved": False,
            "executed": False,
            "network_accessed": False,
            "ansi_encoding": "latin-1 byte-preserving; actual Windows code page not assumed",
        }
        report.metadata["lnk"] = self.metadata
        self.trailing: tuple[int, int] | None = None

    def step(self) -> None:
        self.reader.budget.check_time()
        self.count += 1
        if self.count > self.reader.budget.policy.max_binary_entries:
            raise ScanError("O limite de entradas estruturais LNK foi atingido.")

    def finding(
        self,
        rule: str,
        title: str,
        detail: str,
        severity: Severity,
        offset: int,
        evidence: tuple[str, ...] = (),
    ) -> None:
        self.report.findings.append(
            Finding(rule, severity, title, detail, self.report.name, evidence, 0.85, offset)
        )

    def decode(self, value: bytes, unicode: bool) -> str:
        if unicode:
            try:
                result = value.decode("utf-16le")
            except UnicodeDecodeError as error:
                raise ScanError("String UTF-16 de atalho inválida ou truncada.") from error
        else:
            result = value.decode("latin-1")
            if any(byte >= 128 for byte in value):
                self.report.mark_incomplete(
                    "String ANSI LNK contém bytes não ASCII; a página de código original é desconhecida."
                )
        if "\x00" in result:
            self.report.mark_incomplete(
                "String LNK contada contém NUL interno; a interpretação do destino é ambígua."
            )
        return result

    def cstring(
        self, data: bytes, offset: int, minimum: int, unicode: bool = False, end: int | None = None
    ) -> str:
        self.step()
        end = len(data) if end is None else end
        if not minimum <= offset < end <= len(data):
            raise ScanError("Offset de string LNK aponta para fora do bloco ou para seu cabeçalho.")
        raw = data[offset:end]
        if unicode:
            terminal = next(
                (index for index in range(0, len(raw) - 1, 2) if raw[index : index + 2] == b"\0\0"),
                -1,
            )
        else:
            terminal = raw.find(b"\0")
        if terminal < 0:
            raise ScanError("String LNK sem terminador dentro do bloco declarado.")
        return self.decode(raw[:terminal], unicode)

    def field(self, name: str, value: str, offset: int) -> None:
        self.fields[name] = value
        self.offsets[name] = offset

    def inspect(self) -> None:
        header = self.reader.read(0, 76)
        if struct.unpack_from("<I", header)[0] != 76 or header[4:20] != LINK_CLSID:
            raise ScanError("Cabeçalho ou CLSID Shell Link inválido.")
        self.flags, attributes = struct.unpack_from("<II", header, 20)
        self.metadata.update(
            {
                "flags": f"0x{self.flags:08x}",
                "file_attributes": f"0x{attributes:08x}",
                "creation_filetime": struct.unpack_from("<Q", header, 28)[0],
                "access_filetime": struct.unpack_from("<Q", header, 36)[0],
                "write_filetime": struct.unpack_from("<Q", header, 44)[0],
                "claimed_target_size": struct.unpack_from("<I", header, 52)[0],
                "show_command": struct.unpack_from("<I", header, 60)[0],
                "unicode": bool(self.flags & 128),
            }
        )
        if any(header[66:76]) or self.flags & 0xF8010800:
            self.report.mark_incomplete("Atalho contém campos reservados ou flags desconhecidas.")
        if self.flags & 0x102 == 0x102:
            self.report.mark_incomplete(
                "HasLinkInfo e ForceNoLinkInfo coexistem; os destinos declarados não são uma resolução confiável."
            )
        cursor = 76
        if self.flags & 1:
            size = self.reader.unpack("<H", cursor)[0]
            content = self.reader.read(cursor + 2, size)
            self.id_list(content, cursor + 2)
            cursor += size + 2
        if self.flags & 2:
            size = self.reader.unpack("<I", cursor)[0]
            if size < 28:
                raise ScanError("LinkInfo menor que o cabeçalho obrigatório.")
            self.link_info(self.reader.read(cursor, size), cursor)
            cursor += size
        for flag, name in STRING_FIELDS:
            if self.flags & flag:
                self.step()
                characters = self.reader.unpack("<H", cursor)[0]
                size = characters * (2 if self.flags & 128 else 1)
                value = self.decode(self.reader.read(cursor + 2, size), bool(self.flags & 128))
                self.field(name, value, cursor + 2)
                cursor += size + 2
        self.extra_data(cursor)
        for flag, signature in ((0x200, 0xA0000001), (0x1000, 0xA0000006), (0x4000, 0xA0000007)):
            if self.flags & flag and signature not in self.blocks:
                self.report.mark_incomplete("Flag LNK declara um bloco de extensão ausente.")

    def id_list(self, data: bytes, offset: int) -> None:
        cursor = 0
        count = 0
        while cursor + 2 <= len(data):
            self.step()
            size = struct.unpack_from("<H", data, cursor)[0]
            if size == 0:
                if cursor + 2 != len(data):
                    raise ScanError("IDList LNK contém bytes depois de seu terminador.")
                self.metadata["id_list"] = {"offset": offset, "size": len(data), "items": count}
                if count:
                    self.report.mark_incomplete(
                        "Itens Shell IDList foram delimitados, mas não resolvidos ou interpretados semanticamente."
                    )
                return
            if size < 2 or cursor + size > len(data):
                raise ScanError("Item Shell IDList excede os limites declarados.")
            count += 1
            cursor += size
        raise ScanError("Shell IDList sem terminador válido.")

    def link_info(self, data: bytes, offset: int) -> None:
        size, header_size, flags, volume, local, network, suffix = struct.unpack_from("<7I", data)
        if header_size not in (28, 36) or header_size > size:
            raise ScanError("Tamanho de cabeçalho LinkInfo não suportado.")
        if flags & ~3 or not flags:
            raise ScanError("Flags LinkInfo inválidas ou não suportadas.")
        self.metadata["link_info"] = {"offset": offset, "size": size, "flags": flags}
        self.field("common_suffix", self.cstring(data, suffix, header_size), offset + suffix)
        if flags & 1:
            if not header_size <= volume <= size - 16:
                raise ScanError("VolumeID fora do LinkInfo.")
            volume_size, drive_type, serial, label_offset = struct.unpack_from("<4I", data, volume)
            if volume_size < 16 or volume + volume_size > size:
                raise ScanError("VolumeID truncado.")
            raw = data[volume : volume + volume_size]
            unicode = label_offset == 20
            if unicode:
                if volume_size < 20:
                    raise ScanError("VolumeID Unicode truncado.")
                label_offset = struct.unpack_from("<I", raw, 16)[0]
            label = self.cstring(raw, label_offset, 20 if unicode else 16, unicode)
            self.metadata["volume"] = {
                "drive_type": drive_type,
                "serial": f"{serial:08x}",
                "label": label,
            }
            self.field("local_path", self.cstring(data, local, header_size), offset + local)
        if flags & 2:
            self.network(data, network, header_size, offset)
        if header_size == 36:
            local_unicode, suffix_unicode = struct.unpack_from("<II", data, 28)
            if flags & 1 and local_unicode:
                self.field(
                    "local_path_unicode",
                    self.cstring(data, local_unicode, header_size, True),
                    offset + local_unicode,
                )
            if suffix_unicode:
                self.field(
                    "common_suffix_unicode",
                    self.cstring(data, suffix_unicode, header_size, True),
                    offset + suffix_unicode,
                )
        self.compare_alternates("local_path", "local_path_unicode")
        self.compare_alternates("common_suffix", "common_suffix_unicode")

    def network(self, data: bytes, start: int, minimum: int, offset: int) -> None:
        if not minimum <= start <= len(data) - 20:
            raise ScanError("CommonNetworkRelativeLink fora do LinkInfo.")
        size, flags, name, device, provider = struct.unpack_from("<5I", data, start)
        if size < 20 or start + size > len(data) or flags & ~3:
            raise ScanError("CommonNetworkRelativeLink inválido ou truncado.")
        raw = data[start : start + size]
        wide = name > 20
        minimum = 28 if wide else 20
        if size < minimum:
            raise ScanError("Cabeçalho Unicode de rede truncado.")
        self.field("network_name", self.cstring(raw, name, minimum), offset + start + name)
        if flags & 1:
            self.field(
                "network_device", self.cstring(raw, device, minimum), offset + start + device
            )
        if wide:
            name_unicode, device_unicode = struct.unpack_from("<II", raw, 20)
            self.field(
                "network_name_unicode",
                self.cstring(raw, name_unicode, minimum, True),
                offset + start + name_unicode,
            )
            if flags & 1:
                self.field(
                    "network_device_unicode",
                    self.cstring(raw, device_unicode, minimum, True),
                    offset + start + device_unicode,
                )
        self.metadata["network_provider"] = provider if flags & 2 else None
        self.compare_alternates("network_name", "network_name_unicode")

    def compare_alternates(self, narrow: str, wide: str) -> None:
        if (
            narrow in self.fields
            and wide in self.fields
            and self.fields[narrow] != self.fields[wide]
        ):
            self.report.mark_incomplete(
                "Representações ANSI e Unicode LNK divergem; leitores podem usar destinos diferentes."
            )
            self.finding(
                "lnk.conflicting_paths",
                "Destinos ANSI e Unicode divergentes",
                "As duas representações foram preservadas; nenhum destino foi acessado.",
                Severity.MEDIUM,
                self.offsets[wide],
                (self.fields[narrow], self.fields[wide]),
            )

    def extra_data(self, cursor: int) -> None:
        while cursor + 4 <= self.reader.size:
            self.step()
            size = self.reader.unpack("<I", cursor)[0]
            if size < 4:
                self.metadata["terminal_offset"] = cursor
                if cursor + 4 < self.reader.size:
                    self.trailing = (cursor + 4, self.reader.size - cursor - 4)
                    self.metadata["trailing_data"] = {
                        "offset": self.trailing[0],
                        "size": self.trailing[1],
                    }
                    self.report.mark_incomplete(
                        "Há bytes após o terminador LNK; não fazem parte da estrutura validada."
                    )
                    self.finding(
                        "lnk.trailing_data",
                        "Conteúdo após o fim do atalho",
                        "A cauda será inspecionada separadamente dentro dos limites de payload.",
                        Severity.MEDIUM,
                        cursor + 4,
                    )
                return
            if size < 8 or cursor + size > self.reader.size:
                raise ScanError("Bloco ExtraData LNK fora dos limites.")
            signature = self.reader.unpack("<I", cursor + 4)[0]
            duplicate = signature in self.blocks
            self.blocks.add(signature)
            self.metadata["extra_blocks"].append(
                {"signature": f"0x{signature:08x}", "offset": cursor, "size": size}
            )
            if duplicate:
                self.report.mark_incomplete(
                    "Blocos ExtraData LNK duplicados tornam a interpretação ambígua."
                )
                self.finding(
                    "lnk.duplicate_block",
                    "Bloco de atalho duplicado",
                    "Múltiplos blocos da mesma extensão podem declarar valores conflitantes.",
                    Severity.MEDIUM,
                    cursor,
                )
            if signature in {0xA0000001, 0xA0000007}:
                if size != 788:
                    raise ScanError("Bloco de ambiente ou ícone LNK com tamanho inválido.")
                raw = self.reader.read(cursor, size)
                name = "environment_target" if signature == 0xA0000001 else "environment_icon"
                if duplicate:
                    name += f"_duplicate_{len(self.metadata['extra_blocks'])}"
                self.field(name + "_ansi", self.cstring(raw, 8, 8, end=268), cursor + 8)
                self.field(name, self.cstring(raw, 268, 268, True), cursor + 268)
                if not self.fields[name]:
                    self.fields[name] = self.fields[name + "_ansi"]
                    self.offsets[name] = cursor + 8
                self.compare_alternates(name + "_ansi", name)
            elif signature == 0xA0000003:
                if size != 96:
                    raise ScanError("TrackerDataBlock LNK com tamanho inválido.")
                raw = self.reader.read(cursor, size)
                length, version = struct.unpack_from("<II", raw, 8)
                if length != 88 or version != 0:
                    raise ScanError("TrackerDataBlock LNK não suportado.")
                self.metadata["tracker"] = {
                    "machine_id": self.cstring(raw, 16, 16, end=32),
                    "droid_hex": raw[32:].hex(),
                    "resolved": False,
                }
            else:
                self.report.mark_incomplete(
                    f"Bloco ExtraData 0x{signature:08x} apenas delimitado; sem interpretação semântica."
                )
            cursor += size
        raise ScanError("Atalho sem bloco terminal ExtraData.")

    def analyze_fields(self) -> None:
        targets = [
            (name, value)
            for name, value in self.fields.items()
            if name in TARGET_FIELDS or name.startswith("environment_target")
        ]
        launchers = [(name, value, LAUNCHER.search(value)) for name, value in targets]
        launchers = [(name, value, match) for name, value, match in launchers if match]
        arguments = self.fields.get("arguments", "")
        if launchers:
            name, target, match = launchers[0]
            self.finding(
                "lnk.command_launcher",
                "Atalho aponta para interpretador ou utilitário sensível",
                "A presença é contextual, não um veredito de malware. Destino e argumentos são inspecionados sem execução.",
                Severity.MEDIUM,
                self.offsets[name],
                (target, arguments),
            )
            if any(
                match.group(1).casefold().removesuffix(".exe") in {"powershell", "pwsh"}
                for _, _, match in launchers
            ) and ENCODED_ARGUMENT.search(arguments):
                self.finding(
                    "lnk.encoded_command",
                    "Atalho com comando PowerShell codificado",
                    "A combinação de destino e argumento solicita um comando codificado. O texto é decodificado apenas como dados, dentro dos limites.",
                    Severity.HIGH,
                    self.offsets.get("arguments", 0),
                    (arguments,),
                )
        for name, value in self.fields.items():
            if name == "description" or not remote_reference(value):
                continue
            icon = "icon" in name
            self.finding(
                "lnk.remote_icon" if icon else "lnk.remote_reference",
                "Ícone remoto declarado no atalho"
                if icon
                else "Referência remota declarada no atalho",
                "A abertura no Windows pode acessar uma origem remota. ByteGuard não resolve nomes, não monta compartilhamentos e não segue a referência.",
                Severity.MEDIUM,
                self.offsets[name],
                (value,),
            )

def inspect_shortcut(
    reader: BinaryReader, report: FileReport, depth: int, inspect_member: Callable
) -> None:
    if report.kind != "lnk":
        return
    inspector = ShortcutInspector(reader, report)
    try:
        inspector.inspect()
    except (ScanError, OSError, struct.error, UnicodeError, ValueError) as error:
        report.mark_incomplete(f"Estrutura LNK incompleta: {error}")
        inspector.finding(
            "lnk.structure_incomplete",
            "Estrutura de atalho não validada por completo",
            str(error),
            Severity.LOW,
            0,
        )
    inspector.analyze_fields()
    try:
        arguments = inspector.fields.get("arguments")
        if arguments:
            targets = [
                value
                for name, value in inspector.fields.items()
                if name in TARGET_FIELDS or name.startswith("environment_target")
            ]
            payload = ("\n".join(targets) + " " + arguments).encode("utf-8")
            inspect_member(
                io.BytesIO(payload),
                report,
                "lnk-command.txt",
                depth,
                len(payload),
                None,
                origin={
                    "container": "lnk_string_data",
                    "parent_offset": inspector.offsets["arguments"],
                    "synthetic_text": True,
                    "executed": False,
                },
            )
        if inspector.trailing:
            start, size = inspector.trailing
            inspect_member(
                RangeReader(reader, start, size),
                report,
                "lnk-trailing.bin",
                depth,
                size,
                None,
                origin={"container": "lnk_trailing", "parent_offset": start, "executed": False},
            )
    except (ScanError, OSError) as error:
        report.mark_incomplete(f"Conteúdo derivado do atalho não inspecionado: {error}")
