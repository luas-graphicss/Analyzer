from collections.abc import Callable

from .binary_io import BinaryReader
from .models import FileReport
from .office import inspect_xml
from .pdf import PDFInspector
from .policy import LimitExceeded, ScanError

def inspect_document(
    reader: BinaryReader, report: FileReport, depth: int, scan_payload: Callable
) -> None:
    xml = report.kind == "xml" or (
        report.kind in {"text", "unknown"} and report.name.casefold().endswith((".xml", ".rels"))
    )
    if report.kind != "pdf" and not xml:
        return
    try:
        if reader.size > reader.budget.policy.max_document_bytes:
            raise LimitExceeded(
                "O documento excede o limite de inspeção estrutural; os hashes continuam cobrindo os bytes lidos."
            )
        data = bytearray()
        while len(data) < reader.size:
            length = min(
                reader.budget.policy.chunk_size,
                reader.budget.policy.max_metadata_bytes,
                reader.size - len(data),
            )
            data.extend(reader.read(len(data), length))
        if report.kind == "pdf":
            PDFInspector(bytes(data), report, depth, reader.budget, scan_payload).inspect()
        else:
            inspect_xml(bytes(data), report, reader.budget)
    except (ScanError, OSError, ValueError, UnicodeError) as error:
        report.mark_incomplete(f"Inspeção documental incompleta: {error}")
