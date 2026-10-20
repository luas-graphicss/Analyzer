import argparse
import sys
from pathlib import Path

from .models import ENGINE_VERSION, RISK_LEVELS
from .policy import ScanError, ScanPolicy
from .reporting import load_hash_list, render_json, render_text, safe_text, save_report
from .sarif import render_sarif
from .worker import scan_isolated

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="byteguard",
        description="Analise arquivos offline sem executá-los. Usa somente a biblioteca padrão do Python.",
        epilog=(
            "Exemplos: python -m byteguard arquivo.pdf | "
            "python -m byteguard arquivo.zip --format json --output relatorio.json | "
            "python -m byteguard --gui. Códigos: 0=abaixo do limiar, 1=limiar atingido, "
            "2=análise incompleta ou erro, 130=interrupção. Ausência de alertas não comprova segurança."
        ),
    )
    parser.add_argument("file", nargs="?", type=Path, help="Arquivo regular a analisar")
    parser.add_argument("--gui", action="store_true", help="Abrir a interface desktop local")
    parser.add_argument("--version", action="version", version=f"ByteGuard {ENGINE_VERSION}")
    parser.add_argument(
        "--expected-sha256", help="SHA-256 de uma fonte confiável para comparar a integridade"
    )
    parser.add_argument(
        "--max-member-mb", type=int, default=64, help="Limite por membro descomprimido em MiB"
    )
    parser.add_argument(
        "--max-total-mb", type=int, default=512, help="Limite cumulativo de bytes analisados em MiB"
    )
    parser.add_argument(
        "--max-expanded-mb", type=int, default=512, help="Limite cumulativo de descompressão em MiB"
    )
    parser.add_argument(
        "--max-decoded-mb", type=int, default=4, help="Limite cumulativo de decodificação em MiB"
    )
    parser.add_argument(
        "--max-document-mb", type=int, default=16, help="Limite por documento PDF/XML em MiB"
    )
    parser.add_argument(
        "--max-document-tokens",
        type=int,
        default=100000,
        help="Limite global de elementos e tokens PDF/XML",
    )
    parser.add_argument(
        "--max-report-mb",
        type=int,
        default=16,
        help="Limite do relatório transportado pelo worker em MiB",
    )
    parser.add_argument(
        "--max-files", type=int, default=1000, help="Quantidade máxima de arquivos e payloads"
    )
    parser.add_argument(
        "--max-members", type=int, default=1000, help="Quantidade máxima de entradas por contêiner"
    )
    parser.add_argument(
        "--max-memory-mb",
        type=int,
        default=768,
        help="Limite de memória do worker nos sistemas que suportam RLIMIT_AS",
    )
    parser.add_argument(
        "--max-ratio", type=float, default=200, help="Razão máxima de descompressão"
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Formato do relatório; SARIF 2.1.0 para ferramentas de segurança",
    )
    parser.add_argument(
        "--output", type=Path, help="Criar novo relatório sem sobrescrever arquivos existentes"
    )
    parser.add_argument(
        "--hash-list",
        type=Path,
        help="Lista de bloqueio UTF-8: um SHA-256 por linha; aceita comentários #",
    )
    parser.add_argument(
        "--max-file-mb",
        type=int,
        default=256,
        help="Tamanho máximo de entrada em MiB (padrão: 256)",
    )
    parser.add_argument(
        "--max-depth", type=int, default=3, help="Profundidade de contêineres de 0 a 10 (padrão: 3)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=90,
        help="Prazo máximo do processo em segundos (padrão: 90)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "moderate", "high", "critical"),
        default="high",
        help="Limiar de risco para retornar código 1",
    )
    return parser

def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    if arguments.gui and arguments.file is not None:
        parser.error("Use um arquivo ou --gui, não ambos.")
    if arguments.file is None and not arguments.gui:
        parser.error("Informe um arquivo ou use --gui.")
    try:
        policy = ScanPolicy(
            max_file_bytes=arguments.max_file_mb * 1024 * 1024,
            max_member_bytes=arguments.max_member_mb * 1024 * 1024,
            max_total_bytes=arguments.max_total_mb * 1024 * 1024,
            max_expanded_bytes=arguments.max_expanded_mb * 1024 * 1024,
            max_decoded_bytes=arguments.max_decoded_mb * 1024 * 1024,
            max_document_bytes=arguments.max_document_mb * 1024 * 1024,
            max_document_tokens=arguments.max_document_tokens,
            max_report_bytes=arguments.max_report_mb * 1024 * 1024,
            max_files=arguments.max_files,
            max_archive_members=arguments.max_members,
            max_memory_mb=arguments.max_memory_mb,
            max_compression_ratio=arguments.max_ratio,
            max_depth=arguments.max_depth,
            timeout_seconds=arguments.timeout,
        )
        hashes = load_hash_list(arguments.hash_list) if arguments.hash_list else frozenset()
        if arguments.gui:
            from .gui import main as start_gui

            return start_gui(policy, hashes, arguments.expected_sha256)
        if arguments.output is not None and arguments.output.exists():
            raise ScanError("O arquivo de saída já existe; escolha um novo caminho.")
        report = scan_isolated(arguments.file, policy, hashes, arguments.expected_sha256)
        renderer = {"json": render_json, "text": render_text, "sarif": render_sarif}[
            arguments.format
        ]
        content = renderer(report)
        if arguments.output:
            save_report(arguments.output, content)
        else:
            sys.stdout.write(content)
        if not report.complete:
            return 2
        return int(RISK_LEVELS.get(report.risk, 0) >= RISK_LEVELS[arguments.fail_on])
    except (OSError, ScanError, ValueError) as error:
        print(f"ByteGuard: {safe_text(str(error))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(
            "ByteGuard: análise interrompida; nenhum veredito de segurança foi emitido.",
            file=sys.stderr,
        )
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
