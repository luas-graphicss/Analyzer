import base64
import binascii
import ipaddress
import math
import re
import sys
from array import array
from collections import Counter
from dataclasses import dataclass

from .policy import LimitExceeded, ScanBudget
from .pyinstaller import COOKIE_MAGIC
from .signatures import WIDE_TEXT

MARKERS = {
    "pyinstaller": COOKIE_MAGIC,
    "pyz": b"PYZ\x00",
    "zip": b"PK\x03\x04",
    "pe": b"MZ",
    "elf": b"\x7fELF",
    "pdf": b"%PDF-",
}
URL_PATTERN = re.compile(
    rb"\b(?:https?|ftp)://[a-z0-9][a-z0-9.:@%_~/?#=&+;,!()\-]{3,1024}", re.IGNORECASE
)
IP_PATTERN = re.compile(rb"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
BASE64_PATTERN = re.compile(
    rb"(?:-(?:encodedcommand|enc)\b|(?:frombase64string|b64decode|atob|base64_decode)\s*\()\s*[\"']?([a-z0-9+/_-]{24,16384}={0,2})",
    re.IGNORECASE,
)
HEX_PATTERN = re.compile(
    rb"(?:fromhex|hex2bin)\s*\(\s*[\"']([0-9a-f]{32,16384})[\"']", re.IGNORECASE
)

@dataclass(frozen=True, slots=True)
class DecodedPayload:
    offset: int
    encoding: str
    content: bytes

def entropy(counts: Counter[int], size: int) -> float:
    return (
        round(-sum((value / size) * math.log2(value / size) for value in counts.values()), 6)
        if size
        else 0.0
    )

class ContentInspector:
    def __init__(self, budget: ScanBudget, allow_decode: bool = True) -> None:
        self.budget = budget
        self.policy = budget.policy
        self.allow_decode = allow_decode
        self.counts: Counter[int] = Counter()
        self.size = 0
        self.first = b""
        self.last = b""
        self.tail = b""
        self.block = bytearray()
        self.block_offset = 0
        self.blocks = 0
        self.high_entropy_blocks: list[dict] = []
        self.markers: dict[str, list[int]] = {name: [] for name in MARKERS}
        self.marker_counts: dict[str, int] = {name: 0 for name in MARKERS}
        self.indicators: list[dict] = []
        self.indicator_keys: set[tuple[str, str]] = set()
        self.indicators_truncated = False
        self.decoded: list[DecodedPayload] = []
        self.decoded_keys: set[tuple[str, int]] = set()
        self.warnings: list[str] = []
        self.decode_disabled = False
        self.longest_null_run = 0
        self.trailing_nulls = 0
        self.word_sum = 0
        self.word_tail = b""

    def feed(self, data: bytes, offset: int) -> None:
        words = self.word_tail + data
        even_size = len(words) & ~1
        values = array("H")
        values.frombytes(words[:even_size])
        if sys.byteorder != "little":
            values.byteswap()
        self.word_sum += sum(values)
        self.word_tail = words[even_size:]
        self.counts.update(data)
        self.size += len(data)
        if len(self.first) < 64:
            self.first += data[: 64 - len(self.first)]
        self.last = (self.last + data)[-64:]
        for match in re.finditer(rb"\x00+", data):
            length = (
                match.end() - match.start() + (self.trailing_nulls if match.start() == 0 else 0)
            )
            self.longest_null_run = max(self.longest_null_run, length)
        trailing = len(data) - len(data.rstrip(b"\x00"))
        self.trailing_nulls = self.trailing_nulls + trailing if trailing == len(data) else trailing
        self.block.extend(data)
        cursor = 0
        while len(self.block) - cursor >= 65536:
            self._record_block(bytes(self.block[cursor : cursor + 65536]))
            cursor += 65536
        if cursor:
            del self.block[:cursor]
        window = self.tail + data
        base = offset - len(self.tail)
        for kind, marker in MARKERS.items():
            start = max(0, len(self.tail) - len(marker) + 1)
            self.marker_counts[kind] += window.count(marker, start)
            available = self.policy.max_embedded_markers - len(self.markers[kind])
            for _ in range(max(0, available)):
                position = window.find(marker, start)
                if position < 0:
                    break
                self.markers[kind].append(base + position)
                start = position + len(marker)
        self._indicators(window, base)
        if not self.decode_disabled:
            self._decode(window, base, offset)
        if b"\x00" in window:
            for match in WIDE_TEXT.finditer(window):
                value = match.group()
                shift = 1 if value[0] == 0 else 0
                view = value[shift::2]
                view_base = base + match.start() + shift
                terminated = match.end() < len(window)
                self._indicators(view, view_base, 2, final=terminated)
                if not self.decode_disabled:
                    self._decode(view, view_base, offset, 2, final=terminated)
        self.tail = window[-65536:]

    def _record_block(self, block: bytes) -> None:
        value = entropy(Counter(block), len(block))
        self.blocks += 1
        if len(block) >= 1024 and value >= 7.5:
            self.high_entropy_blocks.append(
                {"offset": self.block_offset, "size": len(block), "entropy": value}
            )
            self.high_entropy_blocks.sort(key=lambda item: item["entropy"], reverse=True)
            del self.high_entropy_blocks[32:]
        self.block_offset += len(block)

    def _indicators(self, data: bytes, base: int, stride: int = 1, final: bool = False) -> None:
        if self.indicators_truncated:
            return
        for kind, pattern in (("url", URL_PATTERN), ("ipv4", IP_PATTERN)):
            for match in pattern.finditer(data):
                if not final and match.end() == len(data):
                    continue
                value = match.group().decode("ascii").rstrip(".,;)")
                if kind == "ipv4":
                    try:
                        address = ipaddress.ip_address(value)
                    except ValueError:
                        continue
                    scope = "public" if address.is_global else "non_public"
                else:
                    scope = "not_resolved"
                key = (kind, value)
                if key in self.indicator_keys:
                    continue
                if len(self.indicators) >= self.policy.max_indicators:
                    self.indicators_truncated = True
                    return
                self.indicator_keys.add(key)
                self.indicators.append(
                    {
                        "type": kind,
                        "value": value,
                        "offset": base + match.start() * stride,
                        "scope": scope,
                        "reputation_checked": False,
                    }
                )

    def _decode(
        self, window: bytes, base: int, offset: int, stride: int = 1, final: bool = False
    ) -> None:
        for encoding, pattern in (("base64", BASE64_PATTERN), ("hex", HEX_PATTERN)):
            for match in pattern.finditer(window):
                if base + match.end() * stride <= offset:
                    continue
                value = match.group(1)
                if not final and match.end(1) == len(window) and len(value) < 16384:
                    continue
                self.budget.check_time()
                key = (encoding, base + match.start(1) * stride)
                if key in self.decoded_keys:
                    continue
                self.decoded_keys.add(key)
                if not self.allow_decode:
                    self.warnings.append(
                        "Payload codificado não expandido: limite de profundidade atingido."
                    )
                    self.decode_disabled = True
                    return
                if len(self.decoded_keys) > self.policy.max_indicators or len(value) == 16384:
                    self.warnings.append(
                        "Limite de candidatos ou tamanho de payload codificado atingido."
                    )
                    self.decode_disabled = True
                    return
                try:
                    decoded = (
                        base64.b64decode(value, altchars=b"-_", validate=True)
                        if encoding == "base64"
                        else bytes.fromhex(value.decode("ascii"))
                    )
                except (binascii.Error, ValueError):
                    continue
                if not decoded:
                    continue
                try:
                    self.budget.consume_decoded(len(decoded))
                except LimitExceeded as error:
                    self.warnings.append(str(error))
                    self.decode_disabled = True
                    return
                self.decoded.append(
                    DecodedPayload(base + match.start(1) * stride, encoding, decoded)
                )

    def finish(self) -> dict:
        base = self.size - len(self.tail)
        self._indicators(self.tail, base, final=True)
        try:
            if not self.decode_disabled:
                self._decode(self.tail, base, base, final=True)
            for match in WIDE_TEXT.finditer(self.tail):
                value = match.group()
                shift = 1 if value[0] == 0 else 0
                view = value[shift::2]
                position = base + match.start() + shift
                self._indicators(view, position, 2, final=True)
                if not self.decode_disabled:
                    self._decode(view, position, base, 2, final=True)
        except LimitExceeded as error:
            self.warnings.append(str(error))
            self.decode_disabled = True
        if self.block:
            self._record_block(bytes(self.block))
            self.block.clear()
        if self.marker_counts["pyinstaller"] > self.policy.max_embedded_markers:
            self.warnings.append(
                "Limite de candidatos de cookie MEI atingido; a inspeção de pacotes é parcial."
            )
        if self.indicators_truncated:
            self.warnings.append(
                "O limite de indicadores extraídos foi atingido; a listagem é parcial."
            )
        return {
            "byte_profile": {
                "bytes_profiled": self.size,
                "little_endian_word_sum": self.word_sum
                + (self.word_tail[0] if self.word_tail else 0),
                "histogram": [self.counts.get(index, 0) for index in range(256)],
                "unique_byte_values": len(self.counts),
                "null_bytes": self.counts.get(0, 0),
                "longest_null_run": self.longest_null_run,
                "printable_ratio": round(
                    sum(self.counts.get(value, 0) for value in (*range(32, 127), 9, 10, 13))
                    / self.size,
                    6,
                )
                if self.size
                else 0.0,
                "first_64_bytes_hex": self.first.hex(" "),
                "last_64_bytes_hex": self.last.hex(" "),
                "entropy_blocks_scanned": self.blocks,
                "highest_entropy_blocks": self.high_entropy_blocks,
            },
            "magic_markers": {
                name: {
                    "count": self.marker_counts[name],
                    "offsets": offsets,
                    "truncated": self.marker_counts[name] > len(offsets),
                }
                for name, offsets in self.markers.items()
                if self.marker_counts[name]
            },
            "indicators_truncated": self.indicators_truncated,
            "decoded_payload_count": len(self.decoded),
        }
