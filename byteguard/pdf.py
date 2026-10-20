import base64
import io
import re
from collections.abc import Callable

from .binary_io import DecompressionReader
from .models import FileReport, Finding, Severity
from .pdf_tokens import PDF_DELIMITERS, PDF_SPACE, PDFName, PDFParser, PDFReference
from .policy import LimitExceeded, ScanBudget, ScanError

ENDSTREAM = re.compile(rb"[\r\n]endstream(?=[\x00\t\n\x0c\r ()<>\[\]{}/%]|$)")
PDF_RULES = {
    "JavaScript": ("pdf.javascript", Severity.MEDIUM, "Referência JavaScript no PDF"),
    "JS": ("pdf.javascript", Severity.MEDIUM, "Referência JavaScript no PDF"),
    "OpenAction": ("pdf.automatic_action", Severity.LOW, "Ação automática no PDF"),
    "AA": ("pdf.automatic_action", Severity.LOW, "Ação automática no PDF"),
    "Launch": ("pdf.launch", Severity.HIGH, "Ação PDF para iniciar aplicativo"),
    "EmbeddedFile": ("pdf.embedded_file", Severity.LOW, "Arquivo anexado ao PDF"),
    "XFA": ("pdf.xfa", Severity.MEDIUM, "Formulário XFA no PDF"),
    "RichMedia": ("pdf.rich_media", Severity.MEDIUM, "Conteúdo RichMedia no PDF"),
}

class PDFInspector:
    def __init__(
        self,
        data: bytes,
        report: FileReport,
        depth: int,
        budget: ScanBudget,
        scan_payload: Callable,
    ):
        self.data = data
        self.report = report
        self.depth = depth
        self.budget = budget
        self.policy = budget.policy
        self.scan_payload = scan_payload
        self.seen: set[str] = set()
        self.objects: dict[PDFReference, object] = {}
        self.streams: list[tuple[dict, int, int, str]] = []
        self.scripts: list[tuple[bytes, int]] = []
        self.metadata = {
            "objects": 0,
            "streams": 0,
            "decoded_streams": 0,
            "object_streams": 0,
            "encrypted": False,
            "cross_references_resolved": False,
            "javascript_executed": False,
            "supported_filters": [
                "FlateDecode",
                "ASCIIHexDecode",
                "ASCII85Decode",
                "RunLengthDecode",
            ],
        }

    def _inspect_value(self, value, offset: int):
        stack = [value]
        while stack:
            item = stack.pop()
            self.budget.check_time()
            if isinstance(item, dict):
                if "Encrypt" in item:
                    self.metadata["encrypted"] = True
                script = item.get("JS")
                if isinstance(script, bytes):
                    if len(self.scripts) >= self.policy.max_archive_members:
                        raise LimitExceeded("O limite de scripts internos PDF foi atingido.")
                    self.scripts.append((script, offset))
                stack.extend(item.keys())
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, PDFName) and item in PDF_RULES:
                rule, severity, title = PDF_RULES[item]
                if rule not in self.seen:
                    self.seen.add(rule)
                    self.report.findings.append(
                        Finding(
                            rule,
                            severity,
                            title,
                            "Nome PDF reconhecido após decodificar escapes. O recurso pode ser legítimo e não foi executado.",
                            self.report.name,
                            (f"/{item}",),
                            0.9,
                            offset,
                        )
                    )

    def _endstream(self, start: int, length: int) -> int:
        if type(length) is not int or length < 0 or start + length > len(self.data):
            raise ScanError("O comprimento do stream PDF aponta para fora do documento.")
        position = start + length
        for _ in range(32):
            if position < len(self.data) and self.data[position] in PDF_SPACE:
                position += 1
            else:
                break
        end = position + 9
        if self.data[position:end] != b"endstream" or (
            end < len(self.data) and self.data[end] not in PDF_DELIMITERS
        ):
            raise ScanError("O comprimento PDF não coincide com o marcador endstream.")
        return end

    def _read_stream(self, parser: PDFParser, dictionary: dict, name: str):
        parser.take()
        start = parser.position
        if self.data[start : start + 2] == b"\r\n":
            start += 2
        elif self.data[start : start + 1] in (b"\n", b"\r"):
            start += 1
        else:
            raise ScanError("Stream PDF sem a quebra de linha obrigatória.")
        length = dictionary.get("Length")
        resolved = self.objects.get(length) if isinstance(length, PDFReference) else length
        if type(resolved) is int:
            end = self._endstream(start, resolved)
        elif isinstance(length, PDFReference):
            marker = ENDSTREAM.search(self.data, start)
            if marker is None:
                raise ScanError("Stream PDF indireto sem marcador de fechamento.")
            end = marker.end()
        else:
            raise ScanError("Stream PDF sem comprimento inteiro ou referência válida.")
        if len(self.streams) >= self.policy.max_archive_members:
            raise LimitExceeded("O limite de streams PDF foi atingido.")
        self.streams.append((dictionary, start, end, name))
        self.metadata["streams"] += 1
        parser.seek(end)

    def _account(self, output: bytearray, block: bytes, compressed_size: int):
        if len(output) + len(block) > self.policy.max_member_bytes:
            raise LimitExceeded("Stream PDF excede o tamanho permitido.")
        self.budget.consume_expanded(len(block))
        self.budget.consume_decoded(len(block))
        if (len(output) + len(block)) / max(1, compressed_size) > self.policy.max_compression_ratio:
            raise LimitExceeded("Stream PDF excede a razão de compressão permitida.")
        output.extend(block)

    def _decode_filter(self, data: bytes, name: str) -> bytes:
        output = bytearray()
        if name in {"FlateDecode", "Fl"}:
            source = DecompressionReader(io.BytesIO(data))
            while True:
                remaining = min(
                    self.policy.max_member_bytes - len(output),
                    self.policy.max_decoded_bytes - self.budget.decoded_bytes,
                    self.policy.max_expanded_bytes - self.budget.expanded_bytes,
                )
                block = source.read(min(self.policy.chunk_size, max(1, remaining + 1)))
                if not block:
                    break
                self._account(output, block, len(data))
        elif name in {"ASCIIHexDecode", "AHx", "ASCII85Decode", "A85"}:
            clean = bytes(character for character in data if character not in PDF_SPACE)
            if name in {"ASCIIHexDecode", "AHx"}:
                if not clean.endswith(b">"):
                    raise ScanError("ASCIIHex PDF sem terminador.")
                value = clean[:-1]
                if len(value) % 2:
                    value += b"0"
                estimate = len(value) // 2
            else:
                if not clean.endswith(b"~>"):
                    raise ScanError("ASCII85 PDF sem terminador.")
                value = clean
                estimate = len(value) * 4
            if estimate > min(
                self.policy.max_member_bytes,
                self.policy.max_decoded_bytes - self.budget.decoded_bytes,
            ):
                raise LimitExceeded("Filtro textual PDF excede o orçamento de saída.")
            try:
                decoded = (
                    bytes.fromhex(value.decode("ascii"))
                    if name in {"ASCIIHexDecode", "AHx"}
                    else base64.a85decode(value, adobe=True)
                )
            except (ValueError, UnicodeError) as error:
                raise ScanError("Codificação textual PDF inválida.") from error
            self._account(output, decoded, len(data))
        elif name in {"RunLengthDecode", "RL"}:
            cursor = 0
            ended = False
            while cursor < len(data):
                self.budget.check_time()
                control = data[cursor]
                cursor += 1
                if control == 128:
                    ended = True
                    if data[cursor:].strip(PDF_SPACE):
                        raise ScanError("Dados adicionais após RunLength PDF.")
                    break
                length = control + 1 if control < 128 else 1
                if cursor + length > len(data):
                    raise ScanError("RunLength PDF truncado.")
                block = data[cursor : cursor + length]
                cursor += length
                if control > 128:
                    block *= 257 - control
                self._account(output, block, len(data))
            if not ended:
                raise ScanError("RunLength PDF sem terminador.")
        else:
            raise ScanError(f"Filtro PDF não suportado: {name}.")
        return bytes(output)

    def _filters(self, dictionary: dict) -> list[str]:
        filters = dictionary.get("Filter", [])
        filters = [filters] if isinstance(filters, PDFName) else filters
        if (
            not isinstance(filters, list)
            or len(filters) > 4
            or any(not isinstance(item, PDFName) for item in filters)
        ):
            raise ScanError("Cadeia de filtros PDF indireta, inválida ou excessiva.")
        parameters = dictionary.get("DecodeParms")
        parameters = parameters if isinstance(parameters, list) else [parameters]
        for value in parameters:
            if value is not None and (
                not isinstance(value, dict)
                or type(value.get("Predictor", 1)) is not int
                or value.get("Predictor", 1) != 1
            ):
                raise ScanError("Parâmetros de predição ou decodificação PDF não suportados.")
        return filters

    def _object_stream(self, data: bytes, dictionary: dict, offset: int):
        count, start = dictionary.get("N"), dictionary.get("First")
        if (
            type(count) is not int
            or type(start) is not int
            or not 0 <= count <= self.policy.max_binary_entries
            or not 0 <= start <= len(data)
        ):
            raise ScanError("Tabela de objetos PDF comprimidos inválida.")
        parser = PDFParser(data[:start], self.budget)
        entries = []
        identifiers = set()
        for _ in range(count):
            number, position = parser.take(), parser.take()
            if (
                number.kind != "number"
                or position.kind != "number"
                or type(number.value) is not int
                or type(position.value) is not int
            ):
                raise ScanError("Índice de objetos PDF não contém pares de inteiros.")
            if (
                number.value < 0
                or number.value in identifiers
                or not 0 <= position.value < len(data) - start
            ):
                raise ScanError("Objeto PDF duplicado ou fora do stream.")
            if entries and position.value <= entries[-1][1]:
                raise ScanError("Offsets de objetos PDF não são estritamente crescentes.")
            identifiers.add(number.value)
            entries.append((number.value, position.value))
        if parser.take().kind != "eof" or (entries and entries[0][1] != 0):
            raise ScanError("Cabeçalho de objetos PDF possui dados não interpretados.")
        for index, (_, position) in enumerate(entries):
            end = start + entries[index + 1][1] if index + 1 < len(entries) else len(data)
            parser = PDFParser(data[start + position : end], self.budget)
            value = parser.value()
            self._inspect_value(value, offset)
            if parser.take().kind != "eof":
                raise ScanError("Objeto PDF comprimido contém dados extras não interpretados.")
        self.metadata["object_streams"] += 1

    def inspect(self):
        self.report.metadata["pdf"] = self.metadata
        self.report.findings[:] = [
            finding for finding in self.report.findings if not finding.rule_id.startswith("pdf.")
        ]
        parser = PDFParser(self.data, self.budget)
        while (token := parser.take()).kind != "eof":
            if (
                token.kind == "number"
                and type(token.value) is int
                and parser.peek().kind == "number"
                and parser.peek(1).value == "obj"
            ):
                generation = parser.take().value
                parser.take()
                if token.value < 0 or type(generation) is not int or not 0 <= generation <= 65535:
                    raise ScanError("Identificador de objeto PDF inválido.")
                reference = PDFReference(token.value, generation)
                if reference in self.objects:
                    self.report.mark_incomplete(
                        "Há revisões ou IDs de objetos PDF repetidos; a tabela xref não é resolvida."
                    )
                self.metadata["objects"] += 1
                if self.metadata["objects"] > self.policy.max_binary_entries:
                    raise LimitExceeded("O limite de objetos PDF foi atingido.")
                value = parser.value()
                self.objects[reference] = value
                self._inspect_value(value, token.offset)
                if isinstance(value, dict) and parser.peek().value == "stream":
                    self._read_stream(parser, value, f"{token.value}-{generation}")
                if parser.peek().value == "endobj":
                    parser.take()
                else:
                    self.report.mark_incomplete("Objeto PDF sem fechamento endobj explícito.")
            elif token.kind in {"<<", "["}:
                value = parser.value(token)
                self._inspect_value(value, token.offset)
                if isinstance(value, dict) and parser.peek().value == "stream":
                    raise ScanError("Stream PDF fora de objeto indireto.")
            elif token.value == "stream":
                raise ScanError("Stream PDF sem dicionário interpretável.")
        eof = self.data.rfind(b"%%EOF")
        if eof < 0 or self.data[eof + 5 :].strip(PDF_SPACE):
            self.report.mark_incomplete("O PDF não termina em um marcador EOF íntegro.")
        if not self.metadata["objects"]:
            self.report.mark_incomplete("Nenhum objeto indireto PDF foi validado.")
        if self.metadata["encrypted"]:
            self.report.mark_incomplete(
                "PDF criptografado: o conteúdo protegido não foi decifrado."
            )
            return
        for dictionary, start, end, name in self.streams:
            self.budget.check_time()
            try:
                length = dictionary.get("Length")
                length = self.objects.get(length) if isinstance(length, PDFReference) else length
                if type(length) is not int or self._endstream(start, length) != end:
                    raise ScanError("Comprimento indireto PDF não resolvido ou ambíguo.")
                if self.depth >= self.policy.max_depth:
                    raise LimitExceeded(
                        "O limite de profundidade impede a inspeção de streams PDF."
                    )
                filters = self._filters(dictionary)
                value = self.data[start : start + length]
                for filter_name in filters:
                    value = self._decode_filter(value, filter_name)
                if dictionary.get("Type") == "ObjStm":
                    self._object_stream(value, dictionary, start)
                child = self.scan_payload(
                    io.BytesIO(value),
                    self.report,
                    f"pdf-object-{name}.bin",
                    self.depth,
                    len(value),
                    length,
                    origin={
                        "container": "pdf",
                        "object": name,
                        "parent_offset": start,
                        "filters": list(filters),
                        "executed": False,
                    },
                )
                if child is not None:
                    self.metadata["decoded_streams"] += 1
            except LimitExceeded:
                raise
            except ScanError as error:
                self.report.mark_incomplete(f"Stream PDF {name}: {error}")
        for index, (script, offset) in enumerate(self.scripts):
            self.scan_payload(
                io.BytesIO(script),
                self.report,
                f"pdf-javascript-{index}.js",
                self.depth,
                len(script),
                None,
                origin={
                    "container": "pdf",
                    "kind": "javascript_literal",
                    "parent_offset": offset,
                    "executed": False,
                },
            )
        self.report.metadata["semantic_analysis"] = "bounded_pdf_objects_and_streams"
