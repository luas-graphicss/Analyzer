import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from .models import FileContext, Finding, Severity

class StreamingAnalyzer(Protocol):
    def feed(self, data: bytes, offset: int) -> None: ...

    def finish(self, context: FileContext) -> Iterable[Finding]: ...

@dataclass(frozen=True, slots=True)
class SignatureRule:
    rule_id: str
    title: str
    severity: Severity
    required: frozenset[str]
    description: str
    confidence: float = 0.8
    kinds: frozenset[str] = frozenset()

EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

TOKEN_EXPRESSIONS = {
    "eicar": re.escape(EICAR_SIGNATURE),
    "powershell": rb"\b(?:powershell|pwsh)(?:\.exe)?\b",
    "encoded_command": rb"(?:^|[\s\"'])[-/](?:enc|encodedcommand)\s+[a-z0-9+/=]{16,256}",
    "download": rb"\b(?:downloadstring|downloadfile|invoke-webrequest)\b",
    "expression": rb"\b(?:invoke-expression|iex)\b",
    "download_execute": rb"\b(?:curl|wget)\b[^\r\n]{0,256}\|\s*(?:bash|sh|zsh|dash)\b",
    "decode_execute": rb"\b(?:eval|exec)\s*\([^\r\n]{0,100}(?:b64decode|base64_decode|atob)\s*\(",
    "php_input_execute": rb"\b(?:eval|assert)\s*\(\s*\$_(?:POST|GET|REQUEST)\s*\[",
    "tcp_shell": rb"/dev/tcp/[a-z0-9_.-]{1,253}/[0-9]{1,5}",
    "allocate_remote": rb"\b(?:VirtualAllocEx|NtAllocateVirtualMemory)\b",
    "write_remote": rb"\b(?:WriteProcessMemory|NtWriteVirtualMemory)\b",
    "thread_remote": rb"\b(?:CreateRemoteThread|NtCreateThreadEx)\b",
    "run_key": rb"software\\microsoft\\windows\\currentversion\\run(?:once)?\b",
    "shadow_delete": rb"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b",
    "backup_delete": rb"\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)\b",
    "log_clear": rb"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\s+\S{1,80}",
    "macro_auto": rb"\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open)\b",
    "macro_shell": rb"(?:WScript\.Shell|Shell\s*\(|ShellExecute)",
    "pdf_javascript": rb"/(?:JavaScript|JS)\b",
    "pdf_automatic": rb"/(?:OpenAction|AA)\b",
    "pdf_launch": rb"/Launch\b",
    "pdf_embedded": rb"/EmbeddedFile\b",
    "xml_entity": rb"<!ENTITY\s+[^>]{1,160}\b(?:SYSTEM|PUBLIC)\b",
    "office_template": rb"relationships/attachedTemplate\b",
    "external_target": rb"TargetMode\s*=\s*[\"']External[\"']",
}

TOKEN_EXPRESSIONS.update(
    {
        "amsi_patch": rb"\b(?:AmsiScanBuffer|AmsiScanString|amsiInitFailed)\b",
        "memory_protect": rb"\b(?:VirtualProtect|NtProtectVirtualMemory)\b",
        "defender_disable": rb"\bSet-MpPreference\b[^\r\n]{0,160}-DisableRealtimeMonitoring\s+\$?true\b",
        "defender_exclusion": rb"\bAdd-MpPreference\b[^\r\n]{0,160}-Exclusion(?:Path|Process|Extension)\b",
        "scheduled_task": rb"\bschtasks(?:\.exe)?\s+/create\b",
        "task_command": rb"/tr\s+[^\r\n]{0,80}(?:powershell|cmd|wscript|mshta)\b",
        "debug_check": rb"\b(?:IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess)\b",
        "lsass_target": rb"\blsass(?:\.exe)?\b",
        "memory_dump": rb"\b(?:MiniDumpWriteDump|comsvcs\.dll|sekurlsa|logonpasswords)\b",
        "browser_secrets": rb"(?:\\Login Data\b|\\Local State\b|\\Cookies\b|logins\.json\b|key4\.db\b)",
        "credential_decrypt": rb"\b(?:CryptUnprotectData|DPAPI|win32crypt)\b",
        "persistence_service": rb"\b(?:CreateService[AW]?|sc(?:\.exe)?\s+create)\b",
        "lolbin_remote": rb"\b(?:mshta|regsvr32)(?:\.exe)?\s+[^\r\n]{0,120}https?://",
        "certutil_decode": rb"\bcertutil(?:\.exe)?\s+[^\r\n]{0,80}-(?:decode|urlcache)\b",
        "security_log_clear": rb"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\s+Security\b",
        "ransom_note": rb"(?:your files (?:have been|are) encrypted|decrypt (?:your|all) files)",
        "wallet_payment": rb"\b(?:bitcoin|monero|ransom|\.onion)\b",
        "mei_runtime": rb"(?:_MEI[0-9a-z]{3,16}|_MEIPASS|pyi_rth_|pyimod0[123]_|PYINSTALLER_)",
        "macro_dde": rb"\bDDEAUTO\b[^\r\n]{0,120}\b(?:cmd|powershell)\b",
        "macro_dangerous": rb"\b(?:VBA\.Shell|CreateObject\s*\(\s*[\"']WScript\.Shell|ExecuteExcel4Macro)\b",
        "script_remote_process": rb"\b(?:subprocess\.(?:Popen|run|call)|os\.system)\s*\([^\r\n]{0,120}(?:powershell|curl|wget)\b",
    }
)

TOKEN_PATTERNS = {
    name: re.compile(expression, 0 if name == "eicar" else re.IGNORECASE)
    for name, expression in TOKEN_EXPRESSIONS.items()
}

RULES = (
    SignatureRule(
        "signature.eicar",
        "EICAR antivirus test signature",
        Severity.CRITICAL,
        frozenset({"eicar"}),
        "The harmless EICAR test marker was detected. It tests antivirus detection and is not real malware.",
        1.0,
    ),
    SignatureRule(
        "script.encoded_powershell",
        "Encoded PowerShell command",
        Severity.MEDIUM,
        frozenset({"powershell", "encoded_command"}),
        "A PowerShell reference and an encoded command argument occur in the file; inspect the decoded payload manually.",
    ),
    SignatureRule(
        "script.download_expression",
        "Download and dynamic execution indicators",
        Severity.HIGH,
        frozenset({"download", "expression"}),
        "Download APIs and expression execution occur together. Their presence does not prove that they are connected.",
        0.7,
    ),
    SignatureRule(
        "script.download_execute",
        "Download piped into a shell",
        Severity.HIGH,
        frozenset({"download_execute"}),
        "A command downloads content and pipes it to a shell. Legitimate installers can use the same pattern.",
    ),
    SignatureRule(
        "script.decode_execute",
        "Decoded content passed to dynamic execution",
        Severity.HIGH,
        frozenset({"decode_execute"}),
        "A decoding call appears inside an eval or exec expression, a common obfuscation technique.",
    ),
    SignatureRule(
        "script.webshell_input",
        "Request input passed to PHP execution",
        Severity.HIGH,
        frozenset({"php_input_execute"}),
        "A PHP eval or assert expression references request-controlled input, a common web shell pattern.",
        0.95,
    ),
    SignatureRule(
        "script.tcp_shell",
        "Shell TCP redirection endpoint",
        Severity.MEDIUM,
        frozenset({"tcp_shell"}),
        "A shell TCP endpoint occurs in the content. Review it for unauthorized remote shell behavior.",
    ),
    SignatureRule(
        "binary.process_injection",
        "Process injection API combination",
        Severity.HIGH,
        frozenset({"allocate_remote", "write_remote", "thread_remote"}),
        "Remote allocation, memory writing, and thread creation API names occur together. Debuggers can also contain them.",
    ),
    SignatureRule(
        "system.run_key",
        "Windows startup registry reference",
        Severity.LOW,
        frozenset({"run_key"}),
        "A Windows startup registry key is referenced. This is a persistence indicator, not proof of malicious intent.",
        0.55,
    ),
    SignatureRule(
        "system.shadow_delete",
        "Shadow copy deletion command",
        Severity.HIGH,
        frozenset({"shadow_delete"}),
        "A command deletes Windows recovery snapshots, a behavior associated with both administration and ransomware.",
    ),
    SignatureRule(
        "system.backup_delete",
        "Backup deletion command",
        Severity.HIGH,
        frozenset({"backup_delete"}),
        "A command deletes backup metadata or system-state backups and may impair recovery.",
    ),
    SignatureRule(
        "system.log_clear",
        "Windows event log clearing command",
        Severity.MEDIUM,
        frozenset({"log_clear"}),
        "An event log clearing command occurs in the content and merits contextual review.",
    ),
    SignatureRule(
        "office.auto_execution",
        "Automatic macro and shell execution indicators",
        Severity.HIGH,
        frozenset({"macro_auto", "macro_shell"}),
        "Automatic macro entry points and shell execution references occur together; compressed VBA may not be visible.",
    ),
    SignatureRule(
        "pdf.javascript",
        "PDF JavaScript reference",
        Severity.MEDIUM,
        frozenset({"pdf_javascript"}),
        "The PDF references JavaScript. Interactive forms may legitimately contain it.",
        0.65,
        frozenset({"pdf"}),
    ),
    SignatureRule(
        "pdf.automatic_action",
        "PDF automatic action",
        Severity.LOW,
        frozenset({"pdf_automatic"}),
        "The PDF declares an automatic action; inspect its target and associated scripts.",
        0.6,
        frozenset({"pdf"}),
    ),
    SignatureRule(
        "pdf.launch",
        "PDF external launch action",
        Severity.HIGH,
        frozenset({"pdf_launch"}),
        "The PDF references an external application launch action.",
        0.85,
        frozenset({"pdf"}),
    ),
    SignatureRule(
        "pdf.embedded_file",
        "PDF embedded file reference",
        Severity.LOW,
        frozenset({"pdf_embedded"}),
        "Embedded PDF attachments require separate extraction and inspection; this engine does not decode PDF object streams.",
        0.65,
        frozenset({"pdf"}),
    ),
    SignatureRule(
        "xml.external_entity",
        "External XML entity declaration",
        Severity.MEDIUM,
        frozenset({"xml_entity"}),
        "An external entity declaration may be unsafe if opened by an XML parser with external entity resolution enabled.",
    ),
    SignatureRule(
        "office.external_template",
        "External Office template relationship",
        Severity.MEDIUM,
        frozenset({"office_template", "external_target"}),
        "An Office relationship references an external template, which can fetch remote active content when opened.",
    ),
)

RULES += (
    SignatureRule(
        "defense.amsi_tamper",
        "Possível alteração de AMSI",
        Severity.HIGH,
        frozenset({"amsi_patch", "memory_protect"}),
        "Referências a AMSI e alteração de proteção de memória coexistem; confirme o contexto antes de concluir que há bypass.",
    ),
    SignatureRule(
        "defense.disable_realtime",
        "Comando para desativar proteção em tempo real",
        Severity.HIGH,
        frozenset({"defender_disable"}),
        "Foi encontrada uma instrução para desativar a proteção do Microsoft Defender.",
    ),
    SignatureRule(
        "defense.exclusion",
        "Adição de exclusão no antivírus",
        Severity.MEDIUM,
        frozenset({"defender_exclusion"}),
        "Uma exclusão do Defender pode ocultar arquivos da inspeção; administradores também usam essa operação.",
    ),
    SignatureRule(
        "persistence.scheduled_script",
        "Tarefa agendada executando interpretador",
        Severity.MEDIUM,
        frozenset({"scheduled_task", "task_command"}),
        "Criação de tarefa agendada e execução de interpretador aparecem no mesmo conteúdo.",
    ),
    SignatureRule(
        "binary.debug_checks",
        "Verificação de depurador",
        Severity.LOW,
        frozenset({"debug_check"}),
        "APIs de detecção de depuração estão presentes; podem pertencer a proteção legítima de software.",
        0.5,
    ),
    SignatureRule(
        "credentials.lsass_dump",
        "Indicadores de dump de credenciais",
        Severity.HIGH,
        frozenset({"lsass_target", "memory_dump"}),
        "Referências a LSASS e operações de dump ou extração de credenciais aparecem juntas.",
    ),
    SignatureRule(
        "credentials.browser_decrypt",
        "Acesso a credenciais de navegador",
        Severity.MEDIUM,
        frozenset({"browser_secrets", "credential_decrypt"}),
        "Arquivos de credenciais de navegador e APIs de descriptografia coexistem; ferramentas de migração também podem utilizá-los.",
    ),
    SignatureRule(
        "persistence.service",
        "Criação de serviço Windows",
        Severity.LOW,
        frozenset({"persistence_service"}),
        "Criação de serviço é um possível mecanismo de persistência, mas também é comum em instaladores.",
        0.55,
    ),
    SignatureRule(
        "execution.lolbin_remote",
        "Utilitário Windows com conteúdo remoto",
        Severity.HIGH,
        frozenset({"lolbin_remote"}),
        "MSHTA ou Regsvr32 recebe uma URL remota; revise a origem e a finalidade.",
    ),
    SignatureRule(
        "execution.certutil",
        "Certutil usado para download ou decodificação",
        Severity.MEDIUM,
        frozenset({"certutil_decode"}),
        "Certutil pode ser usado para preparar payloads; o comando isolado não prova malícia.",
    ),
    SignatureRule(
        "defense.security_log_clear",
        "Limpeza do log de segurança",
        Severity.HIGH,
        frozenset({"security_log_clear"}),
        "Comando explícito para apagar eventos do log Security.",
    ),
    SignatureRule(
        "ransom.note",
        "Texto compatível com pedido de resgate",
        Severity.MEDIUM,
        frozenset({"ransom_note", "wallet_payment"}),
        "Texto sobre arquivos criptografados aparece junto a referências a pagamento ou resgate.",
        0.65,
    ),
    SignatureRule(
        "pyinstaller.runtime",
        "Referências ao runtime PyInstaller/MEI",
        Severity.INFO,
        frozenset({"mei_runtime"}),
        "PyInstaller é um empacotador legítimo. Referências MEI não significam malware; pacotes reconhecidos recebem inspeção separada.",
        0.9,
    ),
    SignatureRule(
        "office.dde_execution",
        "DDE com interpretador de comandos",
        Severity.HIGH,
        frozenset({"macro_dde"}),
        "Um campo DDEAUTO referencia cmd ou PowerShell.",
    ),
    SignatureRule(
        "office.active_macro",
        "Macro com execução de comandos",
        Severity.MEDIUM,
        frozenset({"macro_dangerous"}),
        "Referências VBA indicam capacidade de iniciar comandos externos.",
    ),
    SignatureRule(
        "script.external_command",
        "Script inicia utilitário de rede ou PowerShell",
        Severity.MEDIUM,
        frozenset({"script_remote_process"}),
        "Uma API de criação de processos recebe um comando sensível; revise seu contexto.",
    ),
)

WIDE_TEXT = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){6,}|(?:\x00[\x09\x0a\x0d\x20-\x7e]){6,}")
PDF_ESCAPED_NAME = re.compile(rb"#[0-9a-fA-F]{2}")

class SignatureAnalyzer:
    def __init__(self) -> None:
        self._tail = b""
        self._hits: dict[str, tuple[int, str]] = {}
        self._kind = "unknown"

    def _scan_view(self, view: bytes, base: int, stride: int, encoding: str) -> None:
        for name, pattern in TOKEN_PATTERNS.items():
            if name in self._hits:
                continue
            match = pattern.search(view)
            if match is not None:
                self._hits[name] = (base + match.start() * stride, encoding)

    def feed(self, data: bytes, offset: int) -> None:
        if offset == 0 and data.startswith(b"%PDF-"):
            self._kind = "pdf"
        window = self._tail + data
        base = offset - len(self._tail)
        self._scan_view(window, base, 1, "raw bytes")
        if b"\x00" in window:
            for match in WIDE_TEXT.finditer(window):
                value = match.group()
                shift = 1 if value[0] == 0 else 0
                self._scan_view(
                    value[shift::2],
                    base + match.start() + shift,
                    2,
                    "UTF-16 BE" if shift else "UTF-16 LE",
                )
        if self._kind == "pdf" and b"#" in window:
            for match in re.finditer(rb"/[^\s<>/\[\]()]{1,256}", window):
                name = PDF_ESCAPED_NAME.sub(
                    lambda escaped: bytes([int(escaped.group()[1:], 16)]), match.group()
                )
                self._scan_view(name, base + match.start(), 1, "decoded PDF name")
        self._tail = window[-2048:]

    def finish(self, context: FileContext) -> Iterable[Finding]:
        available = self._hits.keys()
        for rule in RULES:
            if rule.kinds and context.kind not in rule.kinds:
                continue
            if rule.required <= available:
                evidence = tuple(
                    f"{name}: byte {self._hits[name][0]} ({self._hits[name][1]})"
                    for name in sorted(rule.required)
                )
                yield Finding(
                    rule.rule_id,
                    rule.severity,
                    rule.title,
                    rule.description,
                    context.name,
                    evidence,
                    rule.confidence,
                    min(self._hits[name][0] for name in rule.required),
                )
