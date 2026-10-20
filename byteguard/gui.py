import sys
from collections.abc import Iterable
from dataclasses import replace
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from typing import Any

from .engine import ScanEngine
from .gui_theme import COLORS, configure_theme
from .gui_views import ReportViews, format_bytes
from .models import ENGINE_VERSION, AnalysisReport
from .policy import ScanError, ScanPolicy
from .reporting import RISK_LABELS, load_hash_list, render_json, render_text, safe_text, save_report
from .worker import ScanCancelled, scan_isolated

class DesktopApp:
    def __init__(
        self,
        root: Any,
        tk: Any,
        ttk: Any,
        dialogs: Any,
        messages: Any,
        policy: ScanPolicy | None = None,
        known_hashes: Iterable[str] = (),
        expected_sha256: str | None = None,
    ) -> None:
        self.root = root
        self.dialogs = dialogs
        self.messages = messages
        self.policy = policy or ScanPolicy()
        self.hashes = frozenset(known_hashes)
        self.results: Queue[AnalysisReport | Exception] = Queue()
        self.report: AnalysisReport | None = None
        self.cancel_event = Event()
        self.closed = False
        self.running = False
        self.root.title(f"ByteGuard {ENGINE_VERSION} — Bancada de análise")
        self.root.geometry("1260x850")
        self.root.minsize(1040, 700)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        sans, mono = configure_theme(root, ttk)
        rail = tk.Frame(root, background=COLORS["ink"], width=216, padx=22, pady=28)
        rail.grid(row=0, column=0, sticky="nsew")
        rail.grid_propagate(False)
        rail.columnconfigure(0, weight=1)
        rail.rowconfigure(5, weight=1)
        for row, value, font in (
            (0, "B/G", (mono, 28, "bold")),
            (1, "ByteGuard", (sans, 18, "bold")),
            (2, f"LOCAL / {ENGINE_VERSION}", (mono, 11)),
        ):
            tk.Label(
                rail,
                text=value,
                font=font,
                background=COLORS["ink"],
                foreground=COLORS["paper"],
                anchor="w",
            ).grid(row=row, column=0, sticky="ew", pady=(0, 12))
        self.select_button = ttk.Button(
            rail, text="Escolher arquivo", style="Primary.TButton", command=self.choose_file
        )
        self.select_button.grid(row=3, column=0, sticky="ew", pady=(28, 10))
        self.cancel_button = ttk.Button(
            rail, text="Cancelar análise", command=self.cancel, state="disabled"
        )
        self.cancel_button.grid(row=4, column=0, sticky="ew")
        tk.Label(
            rail,
            text="Seu arquivo\nfica com você.",
            font=(sans, 15),
            justify="left",
            background=COLORS["ink"],
            foreground=COLORS["paper"],
        ).grid(row=6, column=0, sticky="w", pady=(0, 14))
        tk.Label(
            rail,
            text="Sem upload.\nSem execução.\nEvidência, não suposição.",
            font=(sans, 11),
            justify="left",
            background=COLORS["ink"],
            foreground=COLORS["background"],
        ).grid(row=7, column=0, sticky="w")
        workspace = ttk.Frame(root, padding=(28, 24, 28, 12))
        workspace.grid(row=0, column=1, sticky="nsew")
        workspace.columnconfigure(0, weight=1)
        workspace.rowconfigure(4, weight=1)
        header = ttk.Frame(workspace)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 22))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="ANÁLISE ESTÁTICA  /  OFFLINE", style="Caption.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(header, text="Bancada de análise", style="Heading.TLabel").grid(
            row=1, column=0, sticky="w", pady=(8, 0)
        )
        self.save_button = ttk.Button(
            header, text="Exportar relatório", command=self.save, state="disabled"
        )
        self.save_button.grid(row=1, column=1, sticky="e")
        self.settings_button = ttk.Button(
            header, text="Mostrar parâmetros", command=self.toggle_settings
        )
        self.settings_button.grid(row=0, column=1, sticky="e", pady=(0, 8))
        settings = ttk.LabelFrame(workspace, text="Parâmetros da análise", padding=16)
        self.settings = settings
        settings.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        settings.columnconfigure(1, weight=1)
        self.expected = tk.StringVar(value=expected_sha256 or "")
        ttk.Label(settings, text="SHA-256 de referência").grid(
            row=0, column=0, sticky="w", padx=(0, 12)
        )
        self.hash_entry = ttk.Entry(settings, textvariable=self.expected, font=(mono, 10))
        self.hash_entry.grid(row=0, column=1, sticky="ew")
        ttk.Label(
            settings, text="Opcional. Utilize uma referência publicada por uma fonte confiável."
        ).grid(row=1, column=1, sticky="w", pady=(6, 12))
        limits = ttk.Frame(settings)
        limits.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.timeout = tk.StringVar(value=str(self.policy.timeout_seconds))
        self.max_file_mb = tk.StringVar(value=str(self.policy.max_file_bytes // (1024 * 1024)))
        ttk.Label(limits, text="Prazo (s)").pack(side="left")
        self.timeout_entry = ttk.Entry(limits, textvariable=self.timeout, width=6)
        self.timeout_entry.pack(side="left", padx=(8, 18))
        ttk.Label(limits, text="Limite (MiB)").pack(side="left")
        self.size_entry = ttk.Entry(limits, textvariable=self.max_file_mb, width=6)
        self.size_entry.pack(side="left", padx=(8, 18))
        self.list_button = ttk.Button(
            limits, text="Lista de bloqueio SHA-256", command=self.choose_hash_list
        )
        self.list_button.pack(side="left")
        self.hash_count = tk.StringVar(value=f"{len(self.hashes)} hashes na lista de bloqueio")
        ttk.Label(settings, textvariable=self.hash_count, wraplength=690).grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(10, 0)
        )
        if expected_sha256:
            self.settings_button.configure(text="Ocultar parâmetros")
        else:
            settings.grid_remove()
        self.file_name = tk.StringVar(value="Nenhum arquivo selecionado")
        ttk.Label(
            workspace, textvariable=self.file_name, style="Caption.TLabel", wraplength=770
        ).grid(row=2, column=0, sticky="w", pady=(0, 14))
        metrics = ttk.Frame(workspace)
        metrics.grid(row=3, column=0, sticky="ew", pady=(0, 22))
        self.metrics = {}
        for column, (key, title, value) in enumerate(
            (
                ("risk", "RISCO OBSERVADO", "Aguardando arquivo"),
                ("coverage", "COBERTURA", "—"),
                ("files", "ARQUIVOS / PAYLOADS", "—"),
                ("bytes", "BYTES LIDOS", "—"),
            )
        ):
            metrics.columnconfigure(column, weight=1)
            frame = ttk.Frame(metrics)
            frame.grid(row=0, column=column, sticky="nw", padx=(0, 18))
            ttk.Label(frame, text=title, style="Caption.TLabel").pack(anchor="w")
            variable = tk.StringVar(value=value)
            self.metrics[key] = variable
            ttk.Label(frame, textvariable=variable, style="Metric.TLabel", wraplength=210).pack(
                anchor="w", pady=(7, 0)
            )
        body = ttk.Frame(workspace)
        body.grid(row=4, column=0, sticky="nsew")
        self.views = ReportViews(body, tk, ttk, sans, mono)
        self.output = self.views.output
        self.progress = ttk.Progressbar(workspace, mode="determinate", value=0)
        self.progress.grid(row=5, column=0, sticky="ew", pady=(12, 8))
        self.status = tk.StringVar(
            value="Pronto. Nenhuma análise estática garante que um arquivo seja seguro."
        )
        ttk.Label(workspace, textvariable=self.status, wraplength=810).grid(
            row=6, column=0, sticky="w"
        )
        self.root.bind("<Control-o>", lambda _: self.choose_file())
        self.root.bind("<Control-s>", lambda _: self.save())
        self.poll_id = self.root.after(100, self.poll)

    def toggle_settings(self) -> None:
        if self.settings.winfo_manager():
            self.settings.grid_remove()
            self.settings_button.configure(text="Mostrar parâmetros")
        else:
            self.settings.grid()
            self.settings_button.configure(text="Ocultar parâmetros")

    def choose_hash_list(self) -> None:
        filename = self.dialogs.askopenfilename(
            title="Lista de bloqueio: um SHA-256 por linha",
            filetypes=(("Texto ou lista SHA-256", "*.txt *.sha256"), ("Todos os arquivos", "*")),
        )
        if not filename:
            return
        try:
            self.hashes = load_hash_list(Path(filename))
        except (OSError, ValueError, ScanError) as error:
            self.messages.showerror("Lista não carregada", safe_text(str(error)))
        else:
            self.hash_count.set(
                f"{len(self.hashes)} hashes na lista — {safe_text(Path(filename).name)}"
            )

    def choose_file(self) -> None:
        if self.running:
            return
        try:
            policy = replace(
                self.policy,
                timeout_seconds=float(self.timeout.get()),
                max_file_bytes=int(self.max_file_mb.get()) * 1024 * 1024,
            )
            expected = self.expected.get().strip() or None
            ScanEngine(policy, self.hashes, expected_sha256=expected)
        except (ValueError, TypeError) as error:
            self.messages.showerror("Configuração inválida", safe_text(str(error)))
            return
        filename = self.dialogs.askopenfilename(title="Escolha um arquivo para análise estática")
        if not filename:
            return
        self.report = None
        self.settings.grid_remove()
        self.settings_button.configure(text="Mostrar parâmetros")
        self.views.reset()
        self.file_name.set(safe_text(str(Path(filename))))
        for key, variable in self.metrics.items():
            variable.set("Analisando…" if key == "risk" else "—")
        self.running = True
        self.cancel_event.clear()
        self._set_controls("disabled")
        self.cancel_button.configure(state="normal")
        self.save_button.configure(state="disabled")
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.status.set(f"Analisando em processo isolado: {safe_text(Path(filename).name)}")
        self.display(
            "Lendo todos os bytes dentro dos limites e inspecionando os conteúdos suportados…\n\nO arquivo não será executado."
        )
        Thread(target=self.analyze, args=(filename, policy, expected), daemon=True).start()

    def _set_controls(self, state: str) -> None:
        for widget in (
            self.select_button,
            self.list_button,
            self.hash_entry,
            self.timeout_entry,
            self.size_entry,
        ):
            widget.configure(state=state)

    def analyze(self, filename: str, policy: ScanPolicy, expected: str | None) -> None:
        try:
            self.results.put(
                scan_isolated(filename, policy, self.hashes, expected, self.cancel_event)
            )
        except Exception as error:
            self.results.put(error)

    def cancel(self) -> None:
        if self.running:
            self.cancel_event.set()
            self.cancel_button.configure(state="disabled")
            self.status.set("Encerrando o processo de análise…")

    def poll(self) -> None:
        if self.closed:
            return
        if getattr(self, "poll_id", None) is not None:
            self.root.after_cancel(self.poll_id)
            self.poll_id = None
        try:
            result = self.results.get_nowait()
        except Empty:
            self.poll_id = self.root.after(100, self.poll)
            return
        self.running = False
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self._set_controls("normal")
        self.cancel_button.configure(state="disabled")
        if isinstance(result, Exception):
            self.status.set(
                "Análise cancelada."
                if isinstance(result, ScanCancelled)
                else "Análise interrompida. Nenhum veredito de segurança está disponível."
            )
            self.metrics["risk"].set("Sem conclusão")
            self.metrics["coverage"].set("Interrompida")
            self.views.put(self.views.overview, safe_text(str(result)))
            self.display(safe_text(str(result)))
        else:
            self.report = result
            self.file_name.set(safe_text(result.root.name))
            self.save_button.configure(state="normal")
            self.metrics["risk"].set(RISK_LABELS[result.risk])
            self.metrics["coverage"].set("Testes concluídos" if result.complete else "Parcial")
            self.metrics["files"].set(str(sum(1 for _ in result.root.walk())))
            self.metrics["bytes"].set(format_bytes(result.bytes_scanned))
            self.status.set(
                f"Risco: {RISK_LABELS[result.risk]} | Cobertura: {'concluída nos testes suportados' if result.complete else 'incompleta'}"
            )
            self.views.show(result)
        self.poll_id = self.root.after(100, self.poll)

    def display(self, content: str) -> None:
        if len(content) > 400000:
            content = (
                content[:400000]
                + "\n\nVisualização limitada. Exporte o relatório para consultar todos os resultados."
            )
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", content)
        self.output.configure(state="disabled")

    def save(self) -> None:
        if self.report is None:
            return
        filename = self.dialogs.asksaveasfilename(
            title="Salvar novo relatório",
            defaultextension=".json",
            filetypes=(("Relatório JSON completo", "*.json"), ("Relatório de texto", "*.txt")),
        )
        if not filename:
            return
        try:
            content = (
                render_text(self.report)
                if filename.lower().endswith(".txt")
                else render_json(self.report)
            )
            save_report(Path(filename), content)
        except (OSError, UnicodeError) as error:
            self.messages.showerror("Relatório não salvo", safe_text(str(error)))
        else:
            self.status.set("Relatório salvo. Arquivos existentes nunca são sobrescritos.")

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.cancel_event.set()
        if getattr(self, "poll_id", None) is not None:
            self.root.after_cancel(self.poll_id)
            self.poll_id = None
        self.root.destroy()

def main(
    policy: ScanPolicy | None = None,
    known_hashes: Iterable[str] = (),
    expected_sha256: str | None = None,
) -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        root = tk.Tk()
    except (ImportError, RuntimeError) as error:
        print(f"O desktop requer Python com Tkinter e uma tela gráfica: {error}", file=sys.stderr)
        return 2
    except Exception as error:
        print(
            f"Não foi possível abrir o desktop: {error}. O modo de linha de comando continua disponível.",
            file=sys.stderr,
        )
        return 2
    DesktopApp(root, tk, ttk, filedialog, messagebox, policy, known_hashes, expected_sha256)
    root.mainloop()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
