import re
from xml.parsers import expat

from .models import FileReport, Finding, Severity
from .policy import LimitExceeded, ScanBudget, ScanError

DDE = re.compile(r"\bDDE(?:AUTO)?\b", re.IGNORECASE)
XLM_COMMAND = re.compile(r"(?:^|[=+\s(,;])(?:EXEC|CALL|REGISTER(?:\.ID)?|RUN)\s*\(", re.IGNORECASE)
OFFICE_NAMESPACE_PREFIXES = (
    "http://schemas.openxmlformats.org/",
    "http://purl.oclc.org/ooxml/",
    "http://schemas.microsoft.com/office/",
)

def inspect_xml(data: bytes, report: FileReport, budget: ScanBudget) -> None:
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    metadata = {
        "external_entities_resolved": False,
        "dtd_allowed": False,
        "network_access": False,
        "elements": 0,
        "maximum_depth": 0,
        "relationships": [],
        "field_instructions": [],
        "office_namespace": False,
    }
    report.metadata["xml"] = metadata
    stack: list[tuple[str, bool]] = []
    captures: list[tuple[str, list[str]]] = []
    captured_size = 0
    field_tail = ""
    detected = {finding.rule_id for finding in report.findings}
    filename = report.name.rsplit("!", 1)[-1].replace("\\", "/").lower()
    macro_sheet = "/macrosheets/" in "/" + filename

    def finding(rule: str, severity: Severity, title: str, description: str, evidence: str = ""):
        if rule in detected:
            return
        detected.add(rule)
        if len(report.findings) >= budget.policy.max_findings_per_file:
            report.mark_incomplete("O limite de achados documentais foi atingido.")
            return
        report.findings.append(
            Finding(
                rule,
                severity,
                title,
                description,
                report.name,
                (evidence[:2048],) if evidence else (),
                0.9,
                parser.CurrentByteIndex,
            )
        )

    def reject_dtd(*_):
        finding(
            "xml.dtd_blocked",
            Severity.MEDIUM,
            "DTD ou entidades XML recusadas",
            "Declarações de entidades não são expandidas. Nenhuma URL ou arquivo externo foi consultado.",
        )
        raise ScanError(
            "DTD e entidades XML foram bloqueadas; conteúdo dependente delas não foi interpretado."
        )

    def inspect_instruction(value: str):
        nonlocal field_tail
        combined = field_tail + value
        if DDE.search(combined):
            finding(
                "office.dde_field",
                Severity.HIGH,
                "Campo Office com DDE",
                "Uma instrução DDE pode solicitar comunicação com outro aplicativo; confirme a origem do documento.",
                combined,
            )
        field_tail = combined[-2048:]
        if len(metadata["field_instructions"]) < budget.policy.max_indicators:
            metadata["field_instructions"].append(value[:2048])
        else:
            report.mark_incomplete("O limite de instruções Office registradas foi atingido.")

    def start(name: str, attributes: dict[str, str]):
        budget.consume_document_tokens(1 + len(attributes))
        namespace, _, local = name.rpartition("}")
        office = namespace.startswith(OFFICE_NAMESPACE_PREFIXES)
        stack.append((local, office))
        if len(stack) > 64:
            raise LimitExceeded("XML excede a profundidade estrutural permitida.")
        metadata["elements"] += 1
        metadata["maximum_depth"] = max(metadata["maximum_depth"], len(stack))
        metadata["office_namespace"] |= office
        attributes = {key.rsplit("}", 1)[-1]: value for key, value in attributes.items()}
        if any(len(value) > 65536 for value in attributes.values()):
            raise LimitExceeded("Atributo XML excede o limite de tamanho.")
        if (
            office
            and local == "Relationship"
            and attributes.get("TargetMode", "").casefold() == "external"
        ):
            target = attributes.get("Target", "")
            relation = attributes.get("Type", "").rsplit("/", 1)[-1]
            if len(metadata["relationships"]) < budget.policy.max_indicators:
                metadata["relationships"].append(
                    {
                        "id": attributes.get("Id", ""),
                        "type": relation,
                        "target": target,
                        "fetched": False,
                    }
                )
            else:
                report.mark_incomplete(
                    "O limite de relacionamentos externos registrados foi atingido."
                )
            if relation == "attachedTemplate":
                finding(
                    "office.external_template",
                    Severity.MEDIUM,
                    "Modelo Office externo",
                    "O documento referencia um modelo externo que pode carregar conteúdo ativo ao ser aberto.",
                    target,
                )
            elif relation in {
                "oleObject",
                "package",
                "aFChunk",
                "externalLink",
                "externalLinkPath",
            }:
                finding(
                    "office.external_active_content",
                    Severity.MEDIUM,
                    "Relacionamento externo de conteúdo ativo",
                    "O documento depende de conteúdo externo não analisado. Referências não são seguidas.",
                    f"{relation}: {target}",
                )
            else:
                finding(
                    "office.external_relationship",
                    Severity.INFO,
                    "Referência externa Office",
                    "Links externos podem ser legítimos. O destino não foi acessado nem teve reputação consultada.",
                    target,
                )
            if target.lower().startswith(("javascript:", "ms-msdt:", "mshta:", "data:")):
                finding(
                    "office.active_uri",
                    Severity.HIGH,
                    "URI externa com esquema ativo",
                    "O destino referencia um esquema que pode invocar código ou outro aplicativo.",
                    target,
                )
            if target.startswith("\\\\") or target.lower().startswith(("file://", "smb://")):
                finding(
                    "office.network_share",
                    Severity.MEDIUM,
                    "Referência a arquivo ou compartilhamento de rede",
                    "Abrir o documento pode solicitar um recurso remoto ou autenticação de rede.",
                    target,
                )
        if office and local == "Override":
            content_type = attributes.get("ContentType", "").lower()
            if "macroenabled" in content_type or "vbaproject" in content_type:
                finding(
                    "office.macro_enabled",
                    Severity.MEDIUM,
                    "Pacote Office habilitado para macros",
                    "O tipo de conteúdo declara suporte a macros; isso não comprova malícia.",
                    content_type,
                )
            if "macrosheet" in content_type:
                finding(
                    "office.xlm_macro_sheet",
                    Severity.MEDIUM,
                    "Planilha de macros XLM",
                    "Macros Excel 4.0 requerem inspeção; não são executadas pelo analisador.",
                    content_type,
                )
        if office and local == "fldSimple" and "instr" in attributes:
            inspect_instruction(attributes["instr"])
        if (
            office
            and local == "definedName"
            and attributes.get("name", "").casefold()
            in {"_xlnm.auto_open", "_xlnm.auto_close", "auto_open", "auto_close"}
        ):
            finding(
                "office.auto_named_range",
                Severity.MEDIUM,
                "Nome definido com execução automática",
                "Um nome reservado pode iniciar macros de planilha ao abrir ou fechar o documento.",
                attributes.get("name", ""),
            )
        if office and local in {"instrText", "f", "definedName"}:
            if captures:
                raise ScanError("Elementos de instrução Office aninhados são ambíguos.")
            captures.append((local, []))

    def text(value: str):
        nonlocal captured_size
        if captures:
            captured_size += len(value)
            if captured_size > budget.policy.max_metadata_bytes:
                raise LimitExceeded("Texto de instruções Office excede o limite de metadados.")
            captures[-1][1].append(value)

    def end(name: str):
        local, office = stack.pop()
        if captures and captures[-1][0] == local:
            kind, parts = captures.pop()
            value = "".join(parts)
            if kind == "instrText":
                inspect_instruction(value)
            if macro_sheet and office and kind == "f" and XLM_COMMAND.search(value):
                finding(
                    "office.xlm_execution",
                    Severity.HIGH,
                    "Fórmula XLM com chamada de comandos",
                    "A planilha de macros contém EXEC, CALL, REGISTER ou RUN. Nenhuma fórmula foi executada.",
                    value,
                )

    parser.StartDoctypeDeclHandler = reject_dtd
    parser.EntityDeclHandler = reject_dtd
    parser.ExternalEntityRefHandler = reject_dtd
    parser.StartElementHandler = start
    parser.CharacterDataHandler = text
    parser.EndElementHandler = end
    if macro_sheet:
        finding(
            "office.xlm_macro_sheet",
            Severity.MEDIUM,
            "Parte de planilha XLM",
            "O caminho da parte indica uma planilha de macros Excel 4.0.",
            filename,
        )
    try:
        for offset in range(0, len(data), 65536):
            budget.check_time()
            parser.Parse(data[offset : offset + 65536], False)
        parser.Parse(b"", True)
    except expat.ExpatError as error:
        raise ScanError(f"XML inválido na linha {error.lineno}, coluna {error.offset}.") from error
    report.metadata["semantic_analysis"] = (
        "bounded_office_xml" if metadata["office_namespace"] else "bounded_xml"
    )
