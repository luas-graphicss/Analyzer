import math
import time
from dataclasses import dataclass, field

class ScanError(Exception):
    pass

class LimitExceeded(ScanError):
    pass

@dataclass(frozen=True, slots=True)
class ScanPolicy:
    chunk_size: int = 1024 * 1024
    max_file_bytes: int = 256 * 1024 * 1024
    max_member_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_archive_members: int = 1000
    max_files: int = 1000
    max_depth: int = 3
    max_compression_ratio: float = 200.0
    timeout_seconds: float = 90.0
    header_bytes: int = 1024 * 1024
    max_zip_directory_bytes: int = 2 * 1024 * 1024
    max_metadata_bytes: int = 4 * 1024 * 1024
    max_inspection_bytes: int = 512 * 1024 * 1024
    max_expanded_bytes: int = 512 * 1024 * 1024
    max_decoded_bytes: int = 4 * 1024 * 1024
    max_indicators: int = 128
    max_findings_per_file: int = 256
    max_embedded_markers: int = 1024
    max_binary_entries: int = 4096
    max_memory_mb: int = 768
    max_document_bytes: int = 16 * 1024 * 1024
    max_document_tokens: int = 100000
    max_report_bytes: int = 16 * 1024 * 1024

    def __post_init__(self) -> None:
        positive_integers = (
            self.max_file_bytes,
            self.max_member_bytes,
            self.max_total_bytes,
            self.max_archive_members,
            self.max_files,
            self.header_bytes,
            self.max_zip_directory_bytes,
            self.max_metadata_bytes,
            self.max_inspection_bytes,
            self.max_expanded_bytes,
            self.max_decoded_bytes,
            self.max_indicators,
            self.max_findings_per_file,
            self.max_embedded_markers,
            self.max_binary_entries,
            self.max_memory_mb,
            self.max_document_bytes,
            self.max_document_tokens,
            self.max_report_bytes,
        )
        if any(type(value) is not int or value <= 0 for value in positive_integers):
            raise ValueError("Size and count limits must be positive integers.")
        if type(self.chunk_size) is not int or not 1024 <= self.chunk_size <= 8 * 1024 * 1024:
            raise ValueError("Chunk size must be between 1 KiB and 8 MiB.")
        if type(self.max_depth) is not int or not 0 <= self.max_depth <= 10:
            raise ValueError("Archive depth must be between 0 and 10.")
        if (
            type(self.timeout_seconds) not in (int, float)
            or not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
        ):
            raise ValueError("Timeout must be finite and greater than zero.")
        if (
            type(self.max_compression_ratio) not in (int, float)
            or not math.isfinite(self.max_compression_ratio)
            or self.max_compression_ratio < 1
        ):
            raise ValueError("Compression ratio limit must be finite and at least one.")

@dataclass(slots=True)
class ScanBudget:
    policy: ScanPolicy
    started: float = field(default_factory=time.monotonic)
    bytes_scanned: int = 0
    files_scanned: int = 0
    expanded_bytes: int = 0
    inspection_bytes: int = 0
    decoded_bytes: int = 0
    document_tokens: int = 0

    @property
    def remaining_bytes(self) -> int:
        return self.policy.max_total_bytes - self.bytes_scanned

    def check_time(self) -> None:
        if time.monotonic() - self.started >= self.policy.timeout_seconds:
            raise LimitExceeded("The scan time limit was reached; analysis is incomplete.")

    def check_file_capacity(self) -> None:
        self.check_time()
        if self.files_scanned >= self.policy.max_files:
            raise LimitExceeded("The total file count limit was reached.")

    def register_file(self) -> None:
        self.check_file_capacity()
        self.files_scanned += 1

    def consume(self, amount: int) -> None:
        self.check_time()
        if amount > self.remaining_bytes:
            raise LimitExceeded("The cumulative byte budget was reached.")
        if amount < 0:
            raise ValueError("Byte counts cannot be negative.")
        self.bytes_scanned += amount

    def consume_expanded(self, amount: int) -> None:
        self.check_time()
        if amount < 0 or self.expanded_bytes + amount > self.policy.max_expanded_bytes:
            raise LimitExceeded("O limite cumulativo de descompressão foi atingido.")
        self.expanded_bytes += amount

    def consume_inspection(self, amount: int) -> None:
        self.check_time()
        if amount < 0 or self.inspection_bytes + amount > self.policy.max_inspection_bytes:
            raise LimitExceeded("O limite de leituras estruturais foi atingido.")
        self.inspection_bytes += amount

    def consume_document_tokens(self, amount: int = 1) -> None:
        self.check_time()
        if amount < 0 or self.document_tokens + amount > self.policy.max_document_tokens:
            raise LimitExceeded(
                "O limite cumulativo de elementos e tokens documentais foi atingido."
            )
        self.document_tokens += amount

    def consume_decoded(self, amount: int) -> None:
        self.check_time()
        if amount < 0 or self.decoded_bytes + amount > self.policy.max_decoded_bytes:
            raise LimitExceeded("O limite cumulativo de conteúdo decodificado foi atingido.")
        self.decoded_bytes += amount
