import re
from collections.abc import Iterable
from pathlib import PurePosixPath

from .models import FileContext, Finding, Severity

MAGIC_PREFIXES = (
    (b"PYZ\x00", "pyz"),
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"dex\n", "dex"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"\x00asm", "wasm"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\xce\xfa\xed\xfe", "macho"),
    (b"\xfe\xed\xfa\xcf", "macho"),
    (b"\xfe\xed\xfa\xce", "macho"),
    (b"\xca\xfe\xba\xbe", "java_or_fat_macho"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)

EXECUTABLE_EXTENSIONS = {
    "pe": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".efi", ".com", ".bin"},
    "elf": {"", ".elf", ".so", ".bin", ".o"},
    "macho": {"", ".dylib", ".bundle", ".bin", ".o"},
}

DISGUISED_EXTENSION = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt)\.(?:exe|scr|com|bat|cmd|js|vbs|ps1|lnk)$",
    re.IGNORECASE,
)

def detect_format(head: bytes) -> str:
    if not head:
        return "empty"
    for signature, kind in MAGIC_PREFIXES:
        if head.startswith(signature):
            return kind
    zlib_header = (
        len(head) >= 2
        and head[0] & 15 == 8
        and head[0] >> 4 <= 7
        and int.from_bytes(head[:2], "big") % 31 == 0
    )
    if len(head) >= 263 and head[257:262] == b"ustar":
        return "tar"
    if head.startswith(b"#!"):
        return "script"
    if (
        len(head) >= 4
        and head[2:4] == b"\r\n"
        and 3000 <= int.from_bytes(head[:2], "little") <= 4000
    ):
        return "python_bytecode"
    sample = head[:8192]
    try:
        text = sample.decode(
            "utf-16" if sample.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        )
    except UnicodeDecodeError:
        return "zlib" if zlib_header else "unknown"
    if (
        text
        and sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text)
        > 0.95
    ):
        return "xml" if text.lstrip().startswith("<?xml") else "text"
    return "zlib" if zlib_header else "unknown"

def analyze_structure(context: FileContext) -> Iterable[Finding]:
    name = PurePosixPath(context.name.replace("\\", "/")).name
    suffix = PurePosixPath(name).suffix.lower()
    allowed = EXECUTABLE_EXTENSIONS.get(context.kind)
    if allowed is not None and suffix not in allowed:
        yield Finding(
            "file.executable_masquerade",
            Severity.MEDIUM,
            "Executable content does not match the extension",
            "The file has an executable header but an unexpected filename extension.",
            context.name,
            (f"detected={context.kind}", f"extension={suffix or '(none)'}"),
            0.9,
        )
    if context.kind == "lnk" and suffix != ".lnk":
        yield Finding(
            "file.shortcut_masquerade",
            Severity.MEDIUM,
            "Atalho Windows com extensão diferente",
            "Os bytes identificam um Shell Link; a extensão pode ocultar que o arquivo referencia outro alvo.",
            context.name,
            (f"extensão={suffix or '(nenhuma)'}",),
            0.95,
        )
    if DISGUISED_EXTENSION.search(name):
        yield Finding(
            "file.double_extension",
            Severity.MEDIUM,
            "Disguised executable extension",
            "The name combines a document or image extension with an executable or script extension.",
            context.name,
            (name,),
            0.85,
        )
    if any(character in name for character in "\u202a\u202b\u202d\u202e\u2066\u2067\u2068\u2069"):
        yield Finding(
            "file.direction_override",
            Severity.MEDIUM,
            "Bidirectional filename controls",
            "Unicode directional controls can visually conceal the true filename or extension.",
            context.name,
            (ascii(name),),
            0.85,
        )
    if (
        context.size >= 16384
        and context.entropy >= 7.8
        and context.kind in {"pe", "elf", "macho", "unknown"}
    ):
        yield Finding(
            "file.high_entropy",
            Severity.LOW,
            "High-entropy binary content",
            "The byte distribution resembles compressed or encrypted content. Entropy alone is not evidence of malware.",
            context.name,
            (f"entropy={context.entropy:.4f} bits/byte",),
            0.4,
        )
    if ":" in name and not re.match(r"^[a-zA-Z]:[^:]", name):
        yield Finding(
            "file.alternate_stream_name",
            Severity.MEDIUM,
            "Nome sugere fluxo alternativo NTFS",
            "Dois-pontos podem indicar um Alternate Data Stream ou causar diferenças entre plataformas.",
            context.name,
            (name,),
            0.8,
        )
