import json
from typing import Any

from .gui_theme import COLORS
from .models import SEVERITY_WEIGHTS, AnalysisReport, Finding
from .reporting import RISK_LABELS, render_text, safe_text

SEVERITY_LABELS = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Moderado",
    "low": "Baixo",
    "info": "Informação",
}
MAX_VISIBLE_ROWS = 1500

def format_bytes(amount: int) -> str:
    value = float(amount)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{amount} B"
        value /= 1024
    return str(amount)

def filter_findings(report: AnalysisReport, severity: str, query: str) -> list[Finding]:
    query = query.strip().casefold()
    return sorted(
        (
            item
            for item in report.findings
            if (severity == "Todos" or SEVERITY_LABELS[item.severity] == severity)
            and (
                not query
                or query
                in f"{item.title} {item.rule_id} {item.description} {item.location}".casefold()
            )
        ),
        key=lambda item: (-SEVERITY_WEIGHTS[item.severity], item.rule_id, item.offset or 0),
    )

def overview_text(report: AnalysisReport) -> str:
    nodes = list(report.root.walk())
    alerts = sum(item.severity != "info" for item in report.findings)
    warnings = [(node.name, error) for node in nodes for error in node.errors]
    lines = [
        "LEITURA DO RESULTADO",
        "",
        f"Risco observado: {RISK_LABELS[report.risk]}",
        f"{alerts} alertas · {len(nodes)} arquivos ou payloads · {report.duration_seconds:.2f} s",
        "",
        "Uma pontuação baixa não é um atestado de segurança. Avalie os achados junto da origem do arquivo.",
        "",
        "COBERTURA",
        "",
        "Os testes suportados foram concluídos."
        if report.complete
        else "Há conteúdo ou verificações que não puderam ser analisados por completo.",
        f"Leitura do arquivo principal: {report.root.bytes_scanned:,} de {report.root.size:,} bytes.",
        f"Formato identificado pelos bytes: {report.root.kind.upper()}.",
    ]
    if warnings:
        lines.extend(("", "PONTOS QUE EXIGEM ATENÇÃO", ""))
        for name, error in warnings[:100]:
            lines.append(f"{safe_text(name)}\n{safe_text(error)}\n")
        if len(warnings) > 100:
            lines.append("A lista completa de avisos está no relatório exportado.")
    lines.extend(
        (
            "",
            "PRÓXIMA LEITURA",
            "",
            "Evidências: detalhes dos alertas e suas posições no arquivo.",
            "Arquivos internos: conteúdo expandido e cobertura de cada membro.",
            "Integridade: hashes, comparação de referência e assinatura digital.",
        )
    )
    return "\n".join(lines)

def integrity_text(report: AnalysisReport) -> str:
    lines = ["IDENTIDADE DO ARQUIVO", "", safe_text(report.root.name), ""]
    for algorithm, digest in report.root.hashes.items():
        lines.extend((algorithm.upper(), digest, ""))
    if not report.root.hashes:
        lines.append("Hashes indisponíveis: leitura incompleta ou arquivo alterado.")
    comparison = report.root.metadata.get("hash_comparison")
    if comparison:
        lines.extend(
            (
                "REFERÊNCIA SHA-256",
                comparison["status"],
                comparison["expected_sha256"],
                "",
            )
        )
    else:
        lines.extend(("Nenhuma referência SHA-256 foi informada.", ""))
    for node in report.root.walk():
        signature = node.metadata.get("authenticode")
        if signature:
            lines.extend(
                (
                    f"ASSINATURA · {safe_text(node.name)}",
                    safe_text(signature.get("status", "unavailable")),
                    safe_text(signature.get("reason", "")),
                    "",
                )
            )
    lines.append(
        "Hashes iguais confirmam igualdade de bytes. Uma assinatura não garante segurança."
    )
    return "\n".join(lines)

class ReportViews:
    def __init__(self, parent: Any, tk: Any, ttk: Any, sans: str, mono: str) -> None:
        self.tk = tk
        self.ttk = ttk
        self.sans = sans
        self.mono = mono
        self.report: AnalysisReport | None = None
        self.findings: dict[str, Finding] = {}
        self.nodes: dict[str, Any] = {}
        self.notebook = ttk.Notebook(parent)
        self.notebook.pack(fill="both", expand=True)
        self.overview = self._text_tab("Visão geral")
        self._build_evidence()
        self._build_structure()
        self.integrity = self._text_tab("Integridade", fixed=True)
        self.output = self._text_tab("Relatório completo", fixed=True)
        self.reset()

    def _text(self, parent: Any, fixed: bool = False) -> Any:
        frame = self.ttk.Frame(parent, style="Paper.TFrame")
        frame.pack(fill="both", expand=True)
        text = self.tk.Text(
            frame,
            wrap="word",
            state="disabled",
            background=COLORS["paper"],
            foreground=COLORS["ink"],
            selectbackground=COLORS["brand"],
            selectforeground=COLORS["paper"],
            font=(self.mono if fixed else self.sans, 11),
            borderwidth=0,
            highlightthickness=0,
            padx=22,
            pady=20,
            spacing3=6,
            height=7,
        )
        scroll = self.ttk.Scrollbar(frame, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        return text

    def _text_tab(self, title: str, fixed: bool = False) -> Any:
        frame = self.ttk.Frame(self.notebook, style="Paper.TFrame")
        self.notebook.add(frame, text=title)
        return self._text(frame, fixed)

    def _tree(self, parent: Any, columns: tuple) -> Any:
        frame = self.ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        tree = self.ttk.Treeview(frame, columns=tuple(item[0] for item in columns), show="headings")
        for key, label, width in columns:
            tree.heading(key, text=label)
            tree.column(key, width=width, minwidth=70, stretch=key in ("title", "name"))
        scroll = self.ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        tree.tag_configure("attention", foreground=COLORS["alert"])
        return tree

    def _build_evidence(self) -> None:
        frame = self.ttk.Frame(self.notebook, style="Paper.TFrame")
        self.notebook.add(frame, text="Evidências")
        filters = self.ttk.Frame(frame, padding=12, style="Paper.TFrame")
        filters.pack(fill="x")
        self.severity = self.tk.StringVar(value="Todos")
        self.query = self.tk.StringVar()
        self.ttk.Label(filters, text="Nível", style="Paper.TLabel").pack(side="left")
        self.ttk.Combobox(
            filters,
            textvariable=self.severity,
            values=("Todos", *SEVERITY_LABELS.values()),
            state="readonly",
            width=13,
        ).pack(side="left", padx=(8, 20))
        self.ttk.Label(filters, text="Buscar", style="Paper.TLabel").pack(side="left")
        self.ttk.Entry(filters, textvariable=self.query).pack(
            side="left", fill="x", expand=True, padx=8
        )
        self.evidence_count = self.tk.StringVar(value="Nenhuma análise")
        self.ttk.Label(
            frame, textvariable=self.evidence_count, padding=12, style="Paper.TLabel"
        ).pack(anchor="w")
        table, detail = self._split(frame)
        self.evidence_tree = self._tree(
            table,
            (("severity", "Nível", 110), ("title", "Evidência", 400), ("offset", "Byte", 100)),
        )
        self.evidence_detail = self._text(detail)
        self.evidence_tree.bind("<<TreeviewSelect>>", self._select_finding)
        self.severity.trace_add("write", self._filter)
        self.query.trace_add("write", self._filter)

    def _build_structure(self) -> None:
        frame = self.ttk.Frame(self.notebook, style="Paper.TFrame")
        self.notebook.add(frame, text="Arquivos internos")
        self.structure_count = self.tk.StringVar(value="Nenhum arquivo")
        self.ttk.Label(
            frame, textvariable=self.structure_count, padding=14, style="Paper.TLabel"
        ).pack(anchor="w")
        table, detail = self._split(frame)
        self.structure_tree = self._tree(
            table,
            (
                ("name", "Arquivo / payload", 390),
                ("kind", "Formato", 90),
                ("size", "Tamanho", 110),
                ("coverage", "Cobertura", 120),
            ),
        )
        self.structure_detail = self._text(detail, fixed=True)
        self.structure_tree.bind("<<TreeviewSelect>>", self._select_node)

    def _split(self, parent: Any) -> tuple[Any, Any]:
        panes = self.ttk.Panedwindow(parent, orient="vertical")
        panes.pack(fill="both", expand=True)
        table = self.ttk.Frame(panes, height=140)
        detail = self.ttk.Frame(panes, height=140)
        table.pack_propagate(False)
        detail.pack_propagate(False)
        panes.add(table, weight=1)
        panes.add(detail, weight=1)
        return table, detail

    @staticmethod
    def put(text: Any, content: str) -> None:
        if len(content) > 400000:
            content = content[:400000] + "\n\nVisualização limitada. Exporte o relatório completo."
        text.configure(state="normal")
        text.delete("1.0", "end")
        text.insert("1.0", content)
        text.configure(state="disabled")

    def reset(self) -> None:
        self.report = None
        self.findings.clear()
        self.nodes.clear()
        for tree in (self.evidence_tree, self.structure_tree):
            tree.delete(*tree.get_children())
        self.evidence_count.set("Nenhuma análise carregada")
        self.structure_count.set("Nenhum arquivo analisado")
        for text in (self.evidence_detail, self.structure_detail, self.integrity, self.output):
            self.put(text, "Os resultados aparecerão aqui depois da análise.")
        self.put(
            self.overview,
            "ANTES DE CONFIAR, INSPECIONE.\n\nEscolha um arquivo na bancada à esquerda. O ByteGuard lê os bytes, calcula hashes e inspeciona estruturas e conteúdos suportados em um processo separado.\n\nSEU ARQUIVO FICA COM VOCÊ\n\nSem upload. Sem execução do arquivo. Sem consultas de reputação.\n\nTEM UMA REFERÊNCIA CONFIÁVEL?\n\nPreencha o SHA-256 esperado para comparar a integridade. Uma coincidência de hash não substitui a avaliação da origem.\n\nSAIBA O QUE NÃO FOI LIDO\n\nLimites, conteúdo protegido e formatos não interpretados são apresentados como lacunas de cobertura, nunca como garantia de segurança.",
        )
        self.notebook.select(0)

    def show(self, report: AnalysisReport) -> None:
        self.report = report
        self.put(self.overview, overview_text(report))
        self.put(self.integrity, integrity_text(report))
        self.put(self.output, render_text(report))
        self._filter()
        self.structure_tree.delete(*self.structure_tree.get_children())
        self.nodes.clear()
        nodes = list(report.root.walk())
        self.structure_count.set(
            f"{len(nodes)} arquivos e payloads · exibindo até {MAX_VISIBLE_ROWS}; dados completos na exportação"
        )
        for index, node in enumerate(nodes[:MAX_VISIBLE_ROWS]):
            key = str(index)
            self.nodes[key] = node
            self.structure_tree.insert(
                "",
                "end",
                iid=key,
                values=(
                    safe_text(node.name),
                    node.kind.upper(),
                    format_bytes(node.size),
                    "Concluída" if node.complete else "Parcial",
                ),
                tags=() if node.complete else ("attention",),
            )
        if nodes:
            self.structure_tree.selection_set("0")
        self.notebook.select(0)

    def _filter(self, *_: Any) -> None:
        self.evidence_tree.delete(*self.evidence_tree.get_children())
        self.findings.clear()
        if self.report is None:
            return
        findings = filter_findings(self.report, self.severity.get(), self.query.get())
        self.evidence_count.set(
            f"{len(findings)} resultados · exibindo {min(len(findings), MAX_VISIBLE_ROWS)}"
        )
        for index, finding in enumerate(findings[:MAX_VISIBLE_ROWS]):
            key = str(index)
            self.findings[key] = finding
            self.evidence_tree.insert(
                "",
                "end",
                iid=key,
                values=(
                    SEVERITY_LABELS[finding.severity],
                    safe_text(finding.title),
                    finding.offset if finding.offset is not None else "—",
                ),
                tags=("attention",) if finding.severity in {"high", "critical"} else (),
            )
        self.put(
            self.evidence_detail,
            "Nenhuma evidência corresponde ao filtro."
            if not findings
            else "Selecione uma evidência para examinar o contexto.",
        )
        if findings:
            self.evidence_tree.selection_set("0")

    def _select_finding(self, *_: Any) -> None:
        selection = self.evidence_tree.selection()
        finding = self.findings.get(selection[0]) if selection else None
        if finding:
            self.put(
                self.evidence_detail,
                f"{safe_text(finding.title)}\n{safe_text(finding.rule_id)} · confiança heurística: {finding.confidence:.0%}\n\n{safe_text(finding.description)}\n\nLocal: {safe_text(finding.location)}\n"
                + "\n".join(safe_text(item) for item in finding.evidence),
            )

    def _select_node(self, *_: Any) -> None:
        selection = self.structure_tree.selection()
        node = self.nodes.get(selection[0]) if selection else None
        if node:
            detail = json.dumps(
                {"hashes": node.hashes, "avisos": node.errors, "metadados": node.metadata},
                ensure_ascii=True,
                indent=2,
            )
            self.put(self.structure_detail, safe_text(node.name) + "\n\n" + detail)
