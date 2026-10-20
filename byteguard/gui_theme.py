from typing import Any

COLORS = {
    "background": "#f2f4f4",
    "paper": "#ffffff",
    "ink": "#263a3d",
    "brand": "#356e66",
    "alert": "#a24631",
}

def configure_theme(root: Any, ttk: Any) -> tuple[str, str]:
    from tkinter import font

    available = set(font.families(root))
    sans = next(
        (
            name
            for name in ("Segoe UI", "Helvetica Neue", "DejaVu Sans", "Noto Sans", "helvetica")
            if name in available
        ),
        font.nametofont("TkDefaultFont", root=root).actual("family"),
    )
    mono = next(
        (
            name
            for name in ("Cascadia Mono", "Consolas", "DejaVu Sans Mono", "courier")
            if name in available
        ),
        font.nametofont("TkFixedFont", root=root).actual("family"),
    )
    root.configure(background=COLORS["background"])
    style = ttk.Style(root)
    if "clam" in style.theme_names():
        style.theme_use("clam")
    style.configure(".", background=COLORS["background"], foreground=COLORS["ink"], font=(sans, 11))
    style.configure("Paper.TFrame", background=COLORS["paper"])
    style.configure("Paper.TLabel", background=COLORS["paper"])
    style.configure("Heading.TLabel", font=(sans, 24, "bold"))
    style.configure("Caption.TLabel", font=(mono, 11))
    style.configure("Metric.TLabel", font=(sans, 15, "bold"))
    style.configure("Brand.TLabel", foreground=COLORS["brand"])
    style.configure("Alert.TLabel", foreground=COLORS["alert"])
    style.configure("TLabelframe", borderwidth=1, relief="solid")
    style.configure("TLabelframe.Label", font=(sans, 11, "bold"))
    style.configure(
        "TButton",
        padding=(14, 9),
        borderwidth=1,
        relief="flat",
        background=COLORS["paper"],
        bordercolor=COLORS["ink"],
        lightcolor=COLORS["paper"],
        darkcolor=COLORS["paper"],
    )
    style.map(
        "TButton",
        background=[("active", COLORS["paper"])],
        foreground=[("disabled", COLORS["brand"])],
    )
    style.configure("Primary.TButton", background=COLORS["brand"], foreground=COLORS["paper"])
    style.map(
        "Primary.TButton",
        background=[("disabled", COLORS["ink"]), ("active", COLORS["ink"])],
        foreground=[("disabled", COLORS["background"]), ("active", COLORS["paper"])],
    )
    style.configure("TEntry", fieldbackground=COLORS["paper"], padding=7, borderwidth=1)
    style.configure("TCombobox", fieldbackground=COLORS["paper"], padding=6)
    style.configure("TNotebook", borderwidth=0, tabmargins=0)
    style.configure("TNotebook.Tab", padding=(16, 11), borderwidth=0)
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLORS["paper"])],
        foreground=[("selected", COLORS["brand"])],
    )
    style.configure(
        "Treeview",
        background=COLORS["paper"],
        fieldbackground=COLORS["paper"],
        foreground=COLORS["ink"],
        rowheight=34,
        borderwidth=0,
        font=(sans, 11),
    )
    style.configure(
        "Treeview.Heading", background=COLORS["background"], font=(sans, 11, "bold"), padding=8
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["brand"])],
        foreground=[("selected", COLORS["paper"])],
    )
    style.configure(
        "Horizontal.TProgressbar",
        background=COLORS["brand"],
        troughcolor=COLORS["background"],
        borderwidth=0,
    )
    return sans, mono
