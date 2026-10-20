import math
import re
from dataclasses import dataclass

from .policy import LimitExceeded, ScanBudget, ScanError

PDF_SPACE = b"\x00\t\n\x0c\r "
PDF_DELIMITERS = PDF_SPACE + b"()<>[]{}/%"
NUMBER = re.compile(rb"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)")
NAME_ESCAPE = re.compile(rb"#([0-9a-fA-F]{2})")
LINE_END = re.compile(rb"[\r\n]")

class PDFName(str):
    pass

@dataclass(frozen=True, slots=True)
class PDFReference:
    number: int
    generation: int

@dataclass(frozen=True, slots=True)
class PDFToken:
    kind: str
    value: object
    offset: int

class PDFParser:
    def __init__(self, data: bytes, budget: ScanBudget) -> None:
        self.data = data
        self.budget = budget
        self.position = 0
        self.pending: list[PDFToken] = []

    def _string_limit(self, length: int) -> None:
        if length > min(
            self.budget.policy.max_member_bytes,
            self.budget.policy.max_decoded_bytes - self.budget.decoded_bytes,
        ):
            raise LimitExceeded("String PDF excede o orçamento de decodificação.")
        if length % 1024 == 0:
            self.budget.check_time()

    def _literal(self) -> bytes:
        output = bytearray()
        depth = 1
        escapes = {110: 10, 114: 13, 116: 9, 98: 8, 102: 12}
        while self.position < len(self.data):
            if self.position % 4096 == 0:
                self.budget.check_time()
            value = self.data[self.position]
            self.position += 1
            if value == 92:
                if self.position >= len(self.data):
                    break
                value = self.data[self.position]
                self.position += 1
                if value in (10, 13):
                    if value == 13 and self.data[self.position : self.position + 1] == b"\n":
                        self.position += 1
                    continue
                if 48 <= value <= 55:
                    digits = bytes([value])
                    for _ in range(2):
                        following = self.data[self.position : self.position + 1]
                        if following and 48 <= following[0] <= 55:
                            digits += following
                            self.position += 1
                        else:
                            break
                    value = int(digits, 8) & 0xFF
                else:
                    value = escapes.get(value, value)
            elif value == 40:
                depth += 1
                if depth > 32:
                    raise LimitExceeded("Parênteses PDF excedem a profundidade permitida.")
            elif value == 41:
                depth -= 1
                if depth == 0:
                    self.budget.consume_decoded(len(output))
                    return bytes(output)
            elif value == 13:
                value = 10
                if self.data[self.position : self.position + 1] == b"\n":
                    self.position += 1
            output.append(value)
            self._string_limit(len(output))
        raise ScanError("String literal PDF sem fechamento.")

    def _hexadecimal(self) -> bytes:
        end = self.data.find(b">", self.position)
        if end < 0:
            raise ScanError("String hexadecimal PDF sem fechamento.")
        value = bytes(
            character for character in self.data[self.position : end] if character not in PDF_SPACE
        )
        self._string_limit((len(value) + 1) // 2)
        if len(value) % 2:
            value += b"0"
        try:
            decoded = bytes.fromhex(value.decode("ascii"))
        except (ValueError, UnicodeError) as error:
            raise ScanError("String hexadecimal PDF inválida.") from error
        self.position = end + 1
        self.budget.consume_decoded(len(decoded))
        return decoded

    def _token(self) -> PDFToken:
        data = self.data
        while self.position < len(data):
            if self.position % 4096 == 0:
                self.budget.check_time()
            character = data[self.position]
            if character in PDF_SPACE:
                self.position += 1
                continue
            if character == 37:
                end = LINE_END.search(data, self.position)
                self.position = end.end() if end else len(data)
                continue
            break
        offset = self.position
        if offset >= len(data):
            return PDFToken("eof", None, offset)
        self.budget.consume_document_tokens()
        pair = data[offset : offset + 2]
        if pair in (b"<<", b">>"):
            self.position += 2
            return PDFToken(pair.decode(), pair.decode(), offset)
        character = data[offset]
        self.position += 1
        if character in (91, 93):
            return PDFToken(chr(character), chr(character), offset)
        if character == 40:
            return PDFToken("string", self._literal(), offset)
        if character == 60:
            return PDFToken("string", self._hexadecimal(), offset)
        if character in (41, 62, 123, 125):
            raise ScanError("Delimitador PDF isolado ou não suportado.")
        start = self.position if character == 47 else offset
        while self.position < len(data) and data[self.position] not in PDF_DELIMITERS:
            self.position += 1
            if self.position - start > 1024:
                raise LimitExceeded("Token PDF excessivamente longo.")
        raw = data[start : self.position]
        if character == 47:
            if re.search(rb"#(?![0-9a-fA-F]{2})", raw):
                raise ScanError("Escape de nome PDF inválido.")
            value = NAME_ESCAPE.sub(lambda match: bytes([int(match.group(1), 16)]), raw)
            return PDFToken("name", PDFName(value.decode("latin-1")), offset)
        if NUMBER.fullmatch(raw):
            if len(raw) > 64:
                raise ScanError("Número PDF excessivamente longo.")
            value = float(raw) if b"." in raw else int(raw)
            if not math.isfinite(value):
                raise ScanError("Número PDF não finito.")
            return PDFToken("number", value, offset)
        return PDFToken("word", raw.decode("latin-1"), offset)

    def peek(self, index: int = 0) -> PDFToken:
        while len(self.pending) <= index:
            self.pending.append(self._token())
        return self.pending[index]

    def take(self) -> PDFToken:
        return self.pending.pop(0) if self.pending else self._token()

    def seek(self, offset: int) -> None:
        if not 0 <= offset <= len(self.data):
            raise ScanError("Offset PDF fora do documento.")
        self.pending.clear()
        self.position = offset

    def value(self, token: PDFToken | None = None, depth: int = 0):
        if depth > 32:
            raise LimitExceeded("A estrutura PDF excede a profundidade permitida.")
        token = token or self.take()
        if token.kind == "<<":
            result = {}
            while self.peek().kind != ">>":
                key = self.take()
                if key.kind != "name" or key.value in result:
                    raise ScanError("Chave PDF inválida ou duplicada; interpretação ambígua.")
                result[key.value] = self.value(depth=depth + 1)
            self.take()
            return result
        if token.kind == "[":
            result = []
            while self.peek().kind != "]":
                result.append(self.value(depth=depth + 1))
            self.take()
            return result
        if token.kind == "number":
            if type(token.value) is int and self.peek().kind == "number":
                generation = self.peek().value
                if type(generation) is int and self.peek(1).value == "R":
                    self.take()
                    self.take()
                    if token.value < 0 or not 0 <= generation <= 65535:
                        raise ScanError("Referência indireta PDF inválida.")
                    return PDFReference(token.value, generation)
            return token.value
        if token.kind in {"name", "string"}:
            return token.value
        if token.kind == "word" and token.value in {"true", "false", "null"}:
            return {"true": True, "false": False, "null": None}[token.value]
        raise ScanError("Valor PDF ausente, truncado ou não suportado.")
