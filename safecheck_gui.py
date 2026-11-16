#!/usr/bin/env python3
"""Interface gráfica (Tkinter) do safecheck. Use: python safecheck_gui.py"""
import os
import queue
import subprocess
import sys
import threading
import time
import prereqs

prereqs.ensure_tkinter()  # se o Tkinter faltar, oferece instalar antes de importá-lo
import tkinter as tk  # noqa: E402
import webbrowser
from tkinter import filedialog, messagebox, ttk  # noqa: E402
from tkinter import font as tkfont  # noqa: E402

import downloader
import safecheck as sc
import settings

# ---- paleta: papel frio, tinta, azul-petróleo para ação; verde/âmbar/vermelho só para status
PAPER, WHITE, SOFT = "#F2F4F5", "#FFFFFF", "#EAF0F2"
INK, MUTED, RULE = "#1B2730", "#5C6B75", "#D5DBDF"
ACCENT, ACCENT_D = "#14606B", "#0E4850"
OK, WARN, BAD, INFO = "#2E7D4F", "#9A6A12", "#B83232", "#2A6F97"
OK_BG, WARN_BG, BAD_BG = "#E7F3EB", "#FBF2DD", "#FBE9E9"

COLORS = {"PASS": OK, "FAIL": BAD, "WARN": WARN, "SKIP": MUTED, "INFO": INFO}
ICONS = {"PASS": "✓", "FAIL": "✗", "WARN": "!", "SKIP": "–", "INFO": "i"}
WORDS = {"PASS": "Aprovado", "FAIL": "Reprovado", "WARN": "Atenção", "SKIP": "Não executado", "INFO": "Informação"}
PLURAL = {"PASS": ("aprovado", "aprovados"), "FAIL": ("reprovado", "reprovados"), "WARN": ("aviso", "avisos"),
          "SKIP": ("não executado", "não executados"), "INFO": ("informação", "informações")}
SPIN = "◐◓◑◒"
DL_OK, DL_OK_D = "#2E7D4F", "#236039"
BTN, BTN_D = "#E3EAED", "#D3DCE1"  # botão secundário: cinza-azulado claro (a borda não aparece no Windows)
WARN_D = "#7B5409"

# links do autor (aparecem no rodapé da janela)
AUTOR = "Esdras Furmanovicz"
GITHUB_URL = "https://github.com/esdrasfurmanovicz"
PORTFOLIO_URL = "https://furmanovicz.com.br"

GROUPS = ["Conferência inicial", "Dentro do sandbox", "Reputação do arquivo"]
EARLY = {"scheme", "host", "dns", "resolve", "probe", "clen", "ext", "size_cap", "shortener", "ctype", "defender"}


def group_of(cid):
    if cid in EARLY:
        return GROUPS[0]
    return GROUPS[2] if cid == "vt" else GROUPS[1]


class Row:
    """Linha da checklist: ícone, nome, resumo e status. Clique ou Enter abre o detalhe."""

    def __init__(self, app, parent, cid, name):
        self.app, self.cid, self.open, self.status, self.running = app, cid, False, None, False
        self.frame = tk.Frame(parent, bg=WHITE)
        self.frame.pack(fill="x")
        self.head = tk.Frame(self.frame, bg=WHITE, cursor="hand2", takefocus=1,
                             highlightthickness=2, highlightbackground=WHITE, highlightcolor=ACCENT)
        self.head.pack(fill="x")
        self.head.columnconfigure(3, weight=1)
        px = app.px
        self.arrow = tk.Label(self.head, text="▸", bg=WHITE, fg=MUTED, width=2)
        self.icon = tk.Label(self.head, text="○", bg=WHITE, fg=MUTED, width=2, font=app.f_icon)
        self.name = tk.Label(self.head, text=name, bg=WHITE, fg=INK, anchor="w", font=app.f_row)
        self.summary = tk.Label(self.head, text="", bg=WHITE, fg=MUTED, anchor="w", font=app.f_small)
        self.word = tk.Label(self.head, text="", bg=WHITE, anchor="e", font=app.f_chip)
        self.arrow.grid(row=0, column=0, padx=(px(8), 0), pady=px(7))
        self.icon.grid(row=0, column=1)
        self.name.grid(row=0, column=2, sticky="w", padx=(px(6), px(12)))
        self.summary.grid(row=0, column=3, sticky="ew")
        self.word.grid(row=0, column=4, padx=(px(8), px(12)))
        self.body = tk.Label(self.frame, text="", bg=SOFT, fg=INK, justify="left", anchor="w",
                             padx=px(46), pady=px(10), font=app.f_small, wraplength=px(640))
        self.rule = tk.Frame(self.frame, height=1, bg=RULE)
        self.rule.pack(fill="x")
        for w in (self.head, self.arrow, self.icon, self.name, self.summary, self.word):
            w.bind("<Button-1>", self.toggle)
            w.bind("<Enter>", lambda e: self.shade(SOFT))
            w.bind("<Leave>", lambda e: self.shade(WHITE))
        self.head.bind("<Return>", self.toggle)
        self.head.bind("<space>", self.toggle)

    def shade(self, color):
        for w in (self.head, self.arrow, self.icon, self.name, self.summary, self.word):
            w.configure(bg=color)

    def toggle(self, _e=None):
        self.open = not self.open
        self.arrow.configure(text="▾" if self.open else "▸")
        if self.open:
            self.body.pack(fill="x", before=self.rule)
        else:
            self.body.pack_forget()

    def set(self, status, summary, body, running=False):
        self.status, self.running = status, running
        if running:
            self.icon.configure(text=SPIN[0], fg=INFO)
            self.summary.configure(text="em andamento", fg=INFO)
            self.word.configure(text="")
        elif status is None:
            self.icon.configure(text="○", fg=MUTED)
            self.summary.configure(text="aguardando", fg=MUTED)
            self.word.configure(text="")
        else:
            c = COLORS[status]
            short = summary if len(summary) <= 84 else summary[:83] + "…"
            self.icon.configure(text=ICONS[status], fg=c)
            self.summary.configure(text=short, fg=MUTED)
            self.word.configure(text=WORDS[status], fg=c)
        self.body.configure(text=body)


APP_ID = "esdrasfurmanovicz.safecheck"  # identidade do programa no Windows (a barra de tarefas agrupa por ela)


class App(tk.Tk):
    def __init__(self):
        if sys.platform == "win32":
            try:  # sem isto, a barra de tarefas mostra o ícone do Python em vez do ícone do programa
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
            except Exception:  # noqa: BLE001
                pass
        super().__init__()
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)  # texto nítido em telas de alta densidade
            except Exception:  # noqa: BLE001
                pass
        self.scale = max(1.0, self.winfo_fpixels("1i") / 96)
        self.px = lambda n: int(n * self.scale)
        self.title("safecheck: confira um arquivo antes de abrir")
        self.configure(bg=PAPER)
        self.apply_icon()
        self.geometry(f"{self.px(960)}x{self.px(800)}")
        self.minsize(self.px(780), self.px(620))

        fams = set(tkfont.families())
        body = "Segoe UI" if "Segoe UI" in fams else tkfont.nametofont("TkDefaultFont").actual("family")
        head = "Bahnschrift" if "Bahnschrift" in fams else body
        self.f_title = (head, 17, "bold")
        self.f_verdict = (head, 21, "bold")
        self.f_group = (head, 11, "bold")
        self.f_row = (body, 10, "bold")
        self.f_body = (body, 10)
        self.f_small = (body, 9)
        self.f_chip = (body, 9, "bold")
        self.f_icon = (body, 12, "bold")
        self.f_input = (body, 11)

        self.q = queue.Queue()
        self.report_path, self.rows, self.groups, self.plan = None, {}, {}, []
        self.spin_i, self.t0, self.running, self.placeholder_on = 0, 0.0, False, False
        self.last = None
        self.style_ttk()
        self.build()
        self.bind("<Control-o>", lambda e: self.choose_file())
        self.after(100, self.poll)
        self.after(180, self.tick)
        self.after(300, self.check_prereqs)

    def check_prereqs(self):
        """Confere em segundo plano o que falta no computador (Docker) e, se faltar, pergunta se deve instalar."""
        result = []
        threading.Thread(target=lambda: result.append(prereqs.find_pending()), daemon=True).start()

        def wait():
            if not result:
                self.after(150, wait)
            elif result[0]:
                self.offer_install(result[0])
        self.after(150, wait)

    def offer_install(self, pending):
        auto = [p for p in pending if not p["manual"] and p["cmds"]]
        texto = "Antes de começar, faltam algumas coisas neste computador:\n\n" + prereqs.describe(pending)
        if not auto:
            messagebox.showinfo("safecheck", texto + "\n\nNão consigo instalar isso sozinho neste sistema. "
                                "Instale manualmente e abra o programa de novo.", parent=self)
            self.destroy()
            return
        texto += "\n\nPosso instalar agora?"
        if any(p["admin"] for p in auto) and sys.platform.startswith("linux"):
            texto += " O sistema vai pedir sua senha de administrador."
        if not messagebox.askyesno("safecheck: instalação necessária", texto, icon="question", parent=self):
            self.destroy()  # sem as dependências o programa não funciona: sai
            return
        self.run_install(pending, auto)

    def run_install(self, pending, auto):
        win = tk.Toplevel(self)
        win.title("Instalando o que falta")
        win.transient(self)
        win.protocol("WM_DELETE_WINDOW", lambda: None)  # não fecha no meio da instalação
        box = tk.Text(win, width=90, height=18, bg=WHITE, fg=INK, font=("Consolas" if sys.platform == "win32" else "monospace", 9))
        box.pack(fill="both", expand=True, padx=8, pady=8)
        lines, outcome = queue.Queue(), []

        def log(t):
            lines.put(t)

        def work():
            outcome.append(prereqs.install(auto, log=log, graphical=True))

        threading.Thread(target=work, daemon=True).start()

        def pump():
            while not lines.empty():
                box.insert("end", lines.get() + "\n")
                box.see("end")
            if not outcome:
                win.after(120, pump)
                return
            win.destroy()
            self.after_install(pending, outcome[0][1])
        pump()

    def after_install(self, pending, failed):
        if failed:
            messagebox.showerror("safecheck", "Não consegui instalar: " + ", ".join(p["label"] for p in failed) +
                                 ".\nInstale manualmente e abra o programa de novo.", parent=self)
            self.destroy()
            return
        left = prereqs.find_pending()
        if left:
            relogin = any(p["relogin"] for p in pending)
            messagebox.showinfo("safecheck", ("Instalado. Falta só aplicar a mudança de grupo: saia da sessão e entre de novo "
                                              "(ou reinicie) e abra o programa outra vez.") if relogin else
                                "O que foi instalado ainda não está pronto:\n\n" + prereqs.describe(left), parent=self)
            self.destroy()
            return
        messagebox.showinfo("safecheck", "Tudo pronto. Pode usar o programa.", parent=self)

    def apply_icon(self):
        """Ícone da barra de título e da barra de tarefas (e dos diálogos). Se os arquivos faltarem, segue sem ícone."""
        assets = os.path.join(sc.HERE, "assets")
        self.ico, png = os.path.join(assets, "icon.ico"), os.path.join(assets, "icon.png")
        try:
            if sys.platform == "win32" and os.path.exists(self.ico):
                self.iconbitmap(default=self.ico)
            if os.path.exists(png):
                self._icon = tk.PhotoImage(file=png)  # guarda a referência, senão o Tk descarta a imagem
                self.iconphoto(True, self._icon)  # Linux e macOS
        except tk.TclError:
            pass
        self.set_win_icon(self)

    def set_win_icon(self, window):
        """Windows: define o ícone direto pela API (WM_SETICON). No Tk 9 o iconbitmap e o iconphoto não trocam o ícone
        da barra de título nem o da barra de tarefas, e a janela ficava com a pena padrão do Tk."""
        ico = getattr(self, "ico", "")
        if sys.platform != "win32" or not os.path.exists(ico):
            return
        try:
            import ctypes
            user32 = ctypes.windll.user32
            user32.LoadImageW.restype = ctypes.c_void_p
            user32.GetParent.restype = ctypes.c_void_p
            user32.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p]
            window.update_idletasks()
            hwnd = user32.GetParent(window.winfo_id())
            for which, metric in ((0, 49), (1, 11)):  # ICON_SMALL (barra de título) e ICON_BIG (barra de tarefas, Alt+Tab)
                px = user32.GetSystemMetrics(metric)
                handle = user32.LoadImageW(None, ico, 1, px, px, 0x10)  # IMAGE_ICON, LR_LOADFROMFILE
                if handle:
                    user32.SendMessageW(hwnd, 0x80, which, handle)  # WM_SETICON
        except Exception:  # noqa: BLE001 - o ícone é só enfeite: nunca deve impedir o programa de abrir
            pass

    # ------------------------------------------------------------------ estilo
    def style_ttk(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("TNotebook", background=PAPER, borderwidth=0, tabmargins=(0, 0, 0, 0))
        st.configure("TNotebook.Tab", background=PAPER, foreground=MUTED, padding=(self.px(16), self.px(8)),
                     borderwidth=0, font=self.f_row)
        st.map("TNotebook.Tab", background=[("selected", WHITE)], foreground=[("selected", INK)])
        st.configure("Bar.Horizontal.TProgressbar", troughcolor=RULE, background=ACCENT, bordercolor=PAPER,
                     lightcolor=ACCENT, darkcolor=ACCENT, thickness=self.px(4))
        st.configure("TNotebook", bordercolor=RULE, lightcolor=PAPER, darkcolor=PAPER)
        st.configure("Vertical.TScrollbar", troughcolor=PAPER, background=RULE, bordercolor=PAPER,
                     arrowcolor=MUTED, relief="flat")

    def button(self, parent, text, command, primary=False):
        # cores por variante: True = ação principal (azul-petróleo), "success" = verde, "warn" = âmbar, False = secundário
        base, hover = {True: (ACCENT, ACCENT_D), "success": (DL_OK, DL_OK_D), "warn": (WARN, WARN_D)}.get(primary, (BTN, BTN_D))
        b = tk.Button(parent, text=text, command=command, font=self.f_row, cursor="hand2", relief="flat", bd=0,
                      padx=self.px(16), pady=self.px(8), takefocus=1,
                      bg=base, fg=WHITE if primary else INK, activebackground=hover,
                      activeforeground=WHITE if primary else INK,
                      disabledforeground="#9AA7AF", highlightthickness=2,
                      highlightbackground=base, highlightcolor=INK)
        return b

    # ------------------------------------------------------------------ layout
    def build(self):
        px = self.px
        pad = px(20)
        hdr = tk.Frame(self, bg=PAPER)
        hdr.pack(fill="x", padx=pad, pady=(px(16), px(10)))
        tk.Label(hdr, text="safecheck", font=self.f_title, bg=PAPER, fg=INK).pack(side="left")
        tk.Label(hdr, text="Confira um arquivo antes de abrir", font=self.f_body, bg=PAPER, fg=MUTED).pack(side="left", padx=(px(12), 0), pady=(px(5), 0))
        self.vtbtn = self.button(hdr, "", self.open_vt_dialog)
        self.vtbtn.pack(side="right")
        self.refresh_vt_button()

        card = tk.Frame(self, bg=WHITE, highlightthickness=1, highlightbackground=RULE)
        card.pack(fill="x", padx=pad)
        inner = tk.Frame(card, bg=WHITE)
        inner.pack(fill="x", padx=px(16), pady=px(14))
        tk.Label(inner, text="Link ou arquivo que você já baixou (MP4/MOV, áudio ou PDF)", font=self.f_row, bg=WHITE, fg=INK).pack(anchor="w")
        row = tk.Frame(inner, bg=WHITE)
        row.pack(fill="x", pady=(px(8), px(6)))
        self.url = tk.StringVar()
        self.entry = tk.Entry(row, textvariable=self.url, font=self.f_input, relief="flat", bg=WHITE, fg=INK,
                              insertbackground=INK, highlightthickness=1, highlightbackground=RULE, highlightcolor=ACCENT)
        self.entry.pack(side="left", fill="x", expand=True, ipady=px(7))
        self.entry.bind("<Return>", lambda e: self.start())
        self.entry.bind("<FocusIn>", self.on_focus_in)
        self.entry.bind("<FocusOut>", self.on_focus_out)
        self.pick = self.button(row, "Escolher arquivo", self.choose_file)
        self.pick.pack(side="left", padx=(px(8), 0))
        self.btn = self.button(row, "Verificar", self.start, primary=True)
        self.btn.pack(side="left", padx=(px(8), 0))
        tk.Label(inner, text="A análise acontece num ambiente isolado. O arquivo nunca é aberto nem executado no seu PC.",
                 font=self.f_small, bg=WHITE, fg=MUTED, anchor="w").pack(fill="x")
        self.set_placeholder()

        strip = tk.Frame(self, bg=PAPER)
        strip.pack(fill="x", padx=pad, pady=(px(12), 0))
        top = tk.Frame(strip, bg=PAPER)
        top.pack(fill="x")
        self.status = tk.StringVar(value="Pronto para verificar.")
        tk.Label(top, textvariable=self.status, font=self.f_body, bg=PAPER, fg=INK, anchor="w").pack(side="left", fill="x", expand=True)
        self.pct = tk.StringVar(value="")
        tk.Label(top, textvariable=self.pct, font=self.f_row, bg=PAPER, fg=MUTED, anchor="e").pack(side="right")
        self.bar = ttk.Progressbar(strip, mode="determinate", maximum=100, style="Bar.Horizontal.TProgressbar")
        self.bar.pack(fill="x", pady=(px(6), 0))

        self.vwrap = tk.Frame(self, bg=PAPER)  # cartão de veredito, preenchido ao terminar

        # rodapé com os links do autor: empacotado antes das abas, para nunca sumir quando a janela fica pequena
        foot = tk.Frame(self, bg=PAPER)
        foot.pack(side="bottom", fill="x", padx=pad, pady=(0, px(12)))
        tk.Label(foot, text=f"Criado por {AUTOR}", font=self.f_small, bg=PAPER, fg=MUTED).pack(side="left")
        for texto, url in (("Portfólio", PORTFOLIO_URL), ("GitHub", GITHUB_URL)):
            b = self.button(foot, texto, lambda u=url: webbrowser.open(u))
            b.configure(padx=px(12), pady=px(4), font=self.f_small)
            b.pack(side="right", padx=(px(8), 0))

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=pad, pady=(px(12), px(8)))
        self.tab_tests = tk.Frame(self.tabs, bg=WHITE)
        self.tab_steps = tk.Frame(self.tabs, bg=WHITE)
        self.tab_cov = tk.Frame(self.tabs, bg=WHITE)
        self.tab_lim = tk.Frame(self.tabs, bg=WHITE)
        for t, label in ((self.tab_tests, "Testes"), (self.tab_steps, "Próximos passos"),
                         (self.tab_cov, "Cobertura"), (self.tab_lim, "Limitações")):
            self.tabs.add(t, text=label)

        # aba Testes: lista rolável
        self.canvas = tk.Canvas(self.tab_tests, highlightthickness=0, bg=WHITE)
        sb = ttk.Scrollbar(self.tab_tests, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.list = tk.Frame(self.canvas, bg=WHITE)
        self.win = self.canvas.create_window((0, 0), window=self.list, anchor="nw")
        self.list.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self.on_canvas)
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self.on_wheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))
        self.empty = self.build_empty()

        self.steps_text = self.make_text(self.tab_steps)
        self.cov_text = self.make_text(self.tab_cov)
        self.lim_text = self.make_text(self.tab_lim)
        self.fill_static()
        self.write_to(self.steps_text, [("p", "Depois da verificação, esta aba mostra o que fazer a mais no seu caso: "
                                              "por exemplo, o que fazer quando o arquivo é grande demais para o VirusTotal.\n")])

    def build_empty(self):
        px = self.px
        f = tk.Frame(self.list, bg=WHITE)
        f.pack(fill="x", padx=px(24), pady=px(24))
        tk.Label(f, text="Como funciona", font=self.f_group, bg=WHITE, fg=INK, anchor="w").pack(fill="x")
        steps = ["Confere o link ou o arquivo, sem abrir nada.",
                 "Analisa tudo dentro de um ambiente isolado (Windows Sandbox ou Docker).",
                 "Mostra o resultado e o que mais você pode fazer."]
        for i, s in enumerate(steps, 1):  # é uma sequência de verdade, então numerar faz sentido
            r = tk.Frame(f, bg=WHITE)
            r.pack(fill="x", pady=(px(8), 0))
            tk.Label(r, text=str(i), font=self.f_chip, bg=INK, fg=WHITE, width=2).pack(side="left")
            tk.Label(r, text=s, font=self.f_body, bg=WHITE, fg=INK, anchor="w").pack(side="left", padx=(px(10), 0))
        tk.Label(f, text="A primeira análise com Docker pode levar alguns minutos, porque baixa o antivírus e o ffmpeg.",
                 font=self.f_small, bg=WHITE, fg=MUTED, anchor="w").pack(fill="x", pady=(px(16), 0))
        return f

    def make_text(self, parent):
        px = self.px
        t = tk.Text(parent, wrap="word", font=self.f_body, bg=WHITE, fg=INK, relief="flat", highlightthickness=0,
                    padx=px(22), pady=px(16), cursor="arrow", spacing1=px(2), spacing3=px(2))
        sb = ttk.Scrollbar(parent, command=t.yview)
        t.configure(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        t.pack(side="left", fill="both", expand=True)
        t.tag_configure("h", font=self.f_row, foreground=INK, spacing1=px(12))
        t.tag_configure("p", foreground=MUTED, font=self.f_body)
        t.tag_configure("li", foreground=MUTED, lmargin1=px(14), lmargin2=px(28), spacing1=px(4))
        t.tag_configure("good", foreground=OK, font=self.f_chip)
        t.tag_configure("part", foreground=WARN, font=self.f_chip)
        t.tag_configure("gap", foreground=BAD, font=self.f_chip)
        return t

    def write_to(self, t, parts, clear=True):
        t.configure(state="normal")
        if clear:
            t.delete("1.0", "end")
        for tag, s in parts:
            t.insert("end", s, tag)
        t.configure(state="disabled")

    def fill_static(self):
        parts = []
        for cat, level, how in sc.COVERAGE:
            tag = {"coberto": "good", "parcial": "part"}.get(level, "gap")
            parts += [(tag, level.capitalize() + "  "), ("h", cat + "\n"), ("p", how + "\n")]
        self.write_to(self.cov_text, parts)
        self.write_to(self.lim_text, [("li", "–  " + l + "\n") for l in sc.LIMITATIONS])

    # ------------------------------------------------------------------ entrada
    def set_placeholder(self):
        if not self.url.get():
            self.placeholder_on = True
            self.url.set("Cole um link ou o caminho de um arquivo (MP4, MP3, PDF...)")
            self.entry.configure(fg="#8A98A1")

    def on_focus_in(self, _e=None):
        if self.placeholder_on:
            self.placeholder_on = False
            self.url.set("")
            self.entry.configure(fg=INK)

    def on_focus_out(self, _e=None):
        if not self.url.get().strip():
            self.set_placeholder()

    def get_input(self):
        return "" if self.placeholder_on else sc.clean_input(self.url.get())

    def choose_file(self):
        if self.running:
            return
        path = filedialog.askopenfilename(
            title="Escolha o arquivo a verificar",
            filetypes=[("Mídia e PDF", "*.mp4 *.m4v *.mov *.m4a *.mp3 *.aac *.wav *.flac *.ogg *.oga *.pdf"),
                       ("Todos os arquivos", "*.*")])
        if path:
            self.placeholder_on = False
            self.entry.configure(fg=INK)
            self.url.set(os.path.normpath(path))

    # ------------------------------------------------------------------ layout dinâmico
    def on_canvas(self, e):
        self.canvas.itemconfigure(self.win, width=e.width)
        for r in self.rows.values():
            r.body.configure(wraplength=max(self.px(300), e.width - self.px(110)))

    def on_wheel(self, e):
        self.canvas.yview_scroll(int(-e.delta / 120), "units")

    def tick(self):
        self.spin_i = (self.spin_i + 1) % len(SPIN)
        for r in self.rows.values():
            if r.running:
                r.icon.configure(text=SPIN[self.spin_i])
        self.apply_download_text()
        if self.running:
            s = int(time.time() - self.t0)
            base = self.pct.get().split("   ")[0] if self.pct.get() else "0%"
            self.pct.set(f"{base}   {s // 60:02d}:{s % 60:02d}")
        self.after(180, self.tick)

    def apply_download_text(self):
        """Mostra o progresso do download (%, velocidade, tempo restante) na linha do teste e no status.
        Usado pelo relógio e por update_view, para os dois escreverem sempre o mesmo texto (sem piscar)."""
        row = self.rows.get("download")
        if self.running and row is not None and row.running and sc.DOWNLOAD:
            text = sc.download_text(sc.DOWNLOAD)
            row.summary.configure(text=text, fg=WARN if sc.DOWNLOAD.get("note") else INFO)
            self.status.set("Baixando no sandbox: " + text)
            return True
        return False

    # ------------------------------------------------------------------ checklist
    def reset_rows(self):
        for g in self.groups.values():
            g["frame"].destroy()
        self.rows, self.groups = {}, {}

    def ensure_group(self, name):
        if name in self.groups:
            return self.groups[name]
        frame = tk.Frame(self.list, bg=WHITE)
        head = tk.Frame(frame, bg=WHITE)
        head.pack(fill="x", padx=self.px(16), pady=(self.px(14), self.px(6)))
        title = tk.Label(head, text=name, font=self.f_group, bg=WHITE, fg=INK, anchor="w")
        title.pack(side="left")
        count = tk.Label(head, text="", font=self.f_small, bg=WHITE, fg=MUTED)
        count.pack(side="left", padx=(self.px(10), 0), pady=(self.px(2), 0))
        tk.Frame(frame, height=1, bg=RULE).pack(fill="x")
        body = tk.Frame(frame, bg=WHITE)
        body.pack(fill="x")
        self.groups[name] = {"frame": frame, "body": body, "count": count}
        for n in GROUPS:  # mantém a ordem fixa dos grupos
            if n in self.groups:
                self.groups[n]["frame"].pack_forget()
                self.groups[n]["frame"].pack(fill="x")
        return self.groups[name]

    def add_row(self, cid, name):
        g = self.ensure_group(group_of(cid))
        r = Row(self, g["body"], cid, name)
        r.body.configure(wraplength=max(self.px(300), self.canvas.winfo_width() - self.px(110)))
        self.rows[cid] = r

    def update_view(self, plan, checks, final=False):
        if self.empty is not None:
            self.empty.destroy()
            self.empty = None
        by = {}
        for c in checks:
            by.setdefault(c["id"], c)
        if self.plan != plan:
            self.reset_rows()
            self.plan = plan
        for cid, name in plan:
            if cid not in self.rows:
                self.add_row(cid, name)
        for c in checks:  # testes fora do plano: aviso extra, falha do sandbox...
            if c["id"] not in self.rows:
                self.add_row(c["id"], c["name"])
        ids = [i for i, _ in plan]
        running_set, done = False, 0
        for cid, row in self.rows.items():
            c = by.get(cid)
            descr = sc.DESCR.get(cid, "")
            if c:
                done += cid in ids
                row.name.configure(text=c["name"])
                short = "não executado" if c["detail"].startswith("não executado") else c["detail"].replace("\n", " ")
                row.set(c["status"], short, (descr + "\n\n" if descr else "") + f"Resultado: {c['detail']}")
            elif cid in ids:
                is_next = not running_set and not final
                running_set = running_set or is_next
                row.set(None, "", descr, running=is_next)
        for name, g in self.groups.items():
            members = [i for i in self.rows if group_of(i) == name and i in ids]
            g["count"].configure(text=f"{sum(i in by for i in members)} de {len(members)}" if members else "")
        total = max(1, len(plan))
        pct = 100 if final else int(done * 100 / total)
        self.bar["value"] = pct
        self.pct.set(f"{pct}%")
        cur = next((r for r in self.rows.values() if r.running), None)
        if not self.apply_download_text() and cur is not None:  # no download, o texto de progresso tem prioridade
            self.status.set(f"Em andamento: {cur.name.cget('text')}")

    # ------------------------------------------------------------------ veredito
    def clear_verdict(self):
        self.vwrap.pack_forget()
        for w in self.vwrap.winfo_children():
            w.destroy()

    def show_verdict(self, level, title, text, chips=(), actions=()):
        bg, bar = {"bad": (BAD_BG, BAD), "warn": (WARN_BG, WARN), "ok": (OK_BG, OK)}[level]
        self.clear_verdict()
        px = self.px
        card = tk.Frame(self.vwrap, bg=bg)
        card.pack(fill="x")
        tk.Frame(card, width=px(8), bg=bar).pack(side="left", fill="y")
        inner = tk.Frame(card, bg=bg)
        inner.pack(side="left", fill="x", expand=True, padx=px(18), pady=px(14))
        self._vinner, self._vbg, self.vnote = inner, bg, None
        tk.Label(inner, text=title, font=self.f_verdict, bg=bg, fg=bar, anchor="w").pack(fill="x")
        tk.Label(inner, text=text, font=self.f_body, bg=bg, fg=INK, anchor="w", justify="left",
                 wraplength=px(780)).pack(fill="x", pady=(px(4), 0))
        if chips:
            cr = tk.Frame(inner, bg=bg)
            cr.pack(fill="x", pady=(px(10), 0))
            for label, color in chips:
                tk.Label(cr, text=label, font=self.f_chip, bg=WHITE, fg=color, padx=px(9), pady=px(3)).pack(side="left", padx=(0, px(6)))
        if actions:
            ar = tk.Frame(inner, bg=bg)
            ar.pack(fill="x", pady=(px(12), 0))
            for label, cmd, primary in actions:
                b = self.button(ar, label, None, primary=primary)
                b.configure(command=lambda b=b, c=cmd: c(b))  # o botão recebe a si mesmo, para mostrar "Copiado"
                b.pack(side="right" if primary else "left", padx=(px(8) if primary else 0, 0 if primary else px(8)))
        self.vwrap.pack(fill="x", padx=px(20), pady=(px(12), 0), before=self.tabs)

    def copy(self, text, widget=None, done="Copiado"):
        self.clipboard_clear()
        self.clipboard_append(text)
        if widget is not None:
            old = widget.cget("text")
            widget.configure(text=done)
            self.after(1600, lambda: widget.winfo_exists() and widget.configure(text=old))

    # ------------------------------------------------------------------ execução
    def start(self):
        url = self.get_input()
        if not url:
            self.status.set("Cole um link ou escolha um arquivo primeiro.")
            self.entry.focus_set()
            return
        self.running, self.t0 = True, time.time()
        for b in (self.btn, self.pick):
            b.configure(state="disabled")
        self.entry.configure(state="disabled")
        self.clear_verdict()
        self.reset_rows()
        self.plan = []
        if self.empty is not None:
            self.empty.destroy()
            self.empty = None
        self.tabs.select(self.tab_tests)
        self.tabs.tab(self.tab_steps, text="Próximos passos")
        self.write_to(self.steps_text, [("p", "Aparece quando a verificação terminar.\n")])
        self.bar["value"] = 0
        self.pct.set("0%")
        self.status.set("Iniciando...")
        sc.LOG = lambda m: self.q.put(("log", m))
        sc.PROGRESS = lambda plan, checks: self.q.put(("progress", (list(plan), list(checks))))
        threading.Thread(target=self.work, args=(url,), daemon=True).start()

    def work(self, url):
        try:
            checks, facts, method = sc.analyze_input(url)
            path = sc.save_report(url, method, checks, facts, settings.reports_dir())
            self.q.put(("done", (url, checks, facts, method, path)))
        except Exception as e:  # noqa: BLE001
            self.q.put(("error", f"{type(e).__name__}: {e}"))

    def poll(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "log":
                    if not any(r.running for r in self.rows.values()):
                        self.status.set(data.strip())
                elif kind == "progress":
                    self.update_view(*data)
                elif kind == "done":
                    self.finish(*data)
                elif kind.startswith("dl"):
                    self.on_download_event(kind, data)
                elif kind == "error":
                    self.end_run()
                    self.status.set("Não foi possível concluir.")
                    self.show_verdict("bad", "Não foi possível concluir a verificação",
                                      f"{data}\nConfira se o Docker está aberto (ou o Windows Sandbox ativado) e tente de novo.")
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def end_run(self):
        self.running = False
        for b in (self.btn, self.pick):
            b.configure(state="normal")
        self.entry.configure(state="normal")

    def summary_text(self, url, checks, facts, steps):
        lines = [f"safecheck: {url}", f"Veredito: {self.verdict_title}"]
        if facts.get("sha256"):
            lines.append(f"SHA-256: {facts['sha256']}")
        lines.append("\nTestes:")
        lines += [f"[{WORDS[c['status']]}] {c['name']}: {c['detail']}" for c in checks]
        lines.append("\nPróximos passos:")
        lines += [f"- {t}: {x}" for t, x in steps]
        return "\n".join(lines)

    def finish(self, url, checks, facts, method, path):
        self.end_run()
        self.report_path = path
        self.update_view(self.plan, checks, final=True)
        elapsed = int(time.time() - self.t0)
        self.status.set(f"Concluído em {elapsed // 60:02d}:{elapsed % 60:02d}. Sandbox: {method}.")
        level, self.verdict_title, text = sc.summarize(checks)
        n = {s: sum(c["status"] == s for c in checks) for s in WORDS}
        chips = [(f"{n[s]} {PLURAL[s][n[s] != 1]}", COLORS[s]) for s in ("PASS", "FAIL", "WARN", "SKIP") if n[s]]
        steps = sc.guidance(checks, facts, not os.path.isfile(sc.clean_input(url)))
        actions = []
        if facts.get("sha256"):
            sha, link = facts["sha256"], sc.vt_link(facts["sha256"])
            actions.append(("Copiar SHA-256", lambda b: self.copy(sha, b), False))
            actions.append(("Abrir no VirusTotal", lambda b: webbrowser.open(link), False))
        actions.append(("Copiar resumo", lambda b: self.copy(self.summary_text(url, checks, facts, steps), b), False))
        self.last, self.dl_active = {"url": url, "checks": checks, "facts": facts, "level": level}, False
        if sc.can_download(checks, facts):  # análise por link, hash conhecido e nenhuma falha
            self.dl_label = "Baixar arquivo verificado" if level == "ok" else "Baixar mesmo com avisos"
            actions.append((self.dl_label, self.start_download, "success" if level == "ok" else "warn"))
        actions.append(("Pasta dos relatórios", lambda b: self.open_reports_folder(), False))
        actions.append(("Abrir relatório completo no navegador", lambda b: self.open_report(), True))
        self.show_verdict(level, self.verdict_title, text, chips, actions)
        for r in self.rows.values():  # abre sozinhos os testes que merecem atenção
            if r.status in ("FAIL", "WARN") and not r.open:
                r.toggle()
        parts = []
        for t, x in steps:
            parts += [("h", t + "\n"), ("p", x + "\n")]
        self.write_to(self.steps_text, parts)
        self.tabs.tab(self.tab_steps, text=f"Próximos passos ({len(steps)})")
        self.canvas.yview_moveto(0)

    # ------------------------------------------------------------------ chave do VirusTotal
    def refresh_vt_button(self):
        src = settings.vt_key_source()
        self.vtbtn.configure(text="Chave do VirusTotal: " + ("configurada ✓" if src else "não configurada"))

    def open_vt_dialog(self):
        px = self.px
        win = tk.Toplevel(self)
        win.title("Chave do VirusTotal")
        win.configure(bg=PAPER)
        self.set_win_icon(win)
        win.transient(self)
        win.resizable(False, False)
        body = tk.Frame(win, bg=WHITE, highlightthickness=1, highlightbackground=RULE)
        body.pack(fill="both", expand=True, padx=px(16), pady=px(16))
        pad = tk.Frame(body, bg=WHITE)
        pad.pack(fill="both", expand=True, padx=px(20), pady=px(18))
        tk.Label(pad, text="Chave do VirusTotal", font=self.f_group, bg=WHITE, fg=INK, anchor="w").pack(fill="x")
        tk.Label(pad, bg=WHITE, fg=MUTED, font=self.f_body, justify="left", anchor="w", wraplength=px(460),
                 text="Com a chave, o safecheck consulta sozinho o hash do arquivo no VirusTotal e mostra o resultado nos testes. "
                      "A chave é gratuita e fica só no seu PC: ela nunca vai para o sandbox.").pack(fill="x", pady=(px(6), px(10)))
        self.link_button(pad, "Obter uma chave gratuita no VirusTotal",
                         "https://www.virustotal.com/gui/my-apikey").pack(anchor="w", pady=(0, px(12)))
        tk.Label(pad, text="Cole a chave aqui", font=self.f_row, bg=WHITE, fg=INK, anchor="w").pack(fill="x")
        row = tk.Frame(pad, bg=WHITE)
        row.pack(fill="x", pady=(px(4), px(6)))
        var = tk.StringVar(value=settings.saved_vt_key())
        ent = tk.Entry(row, textvariable=var, show="•", font=self.f_input, relief="flat", bg=WHITE, fg=INK, width=46,
                       insertbackground=INK, highlightthickness=1, highlightbackground=RULE, highlightcolor=ACCENT)
        ent.pack(side="left", fill="x", expand=True, ipady=px(6))
        show = tk.BooleanVar(value=False)
        tk.Checkbutton(row, text="Mostrar", variable=show, bg=WHITE, fg=INK, activebackground=WHITE, font=self.f_small,
                       command=lambda: ent.configure(show="" if show.get() else "•")).pack(side="left", padx=(px(8), 0))
        msg = tk.Label(pad, text="", font=self.f_small, bg=WHITE, fg=MUTED, anchor="w", justify="left", wraplength=px(460))
        msg.pack(fill="x", pady=(px(2), px(8)))
        info = "Guardada criptografada com a sua conta do Windows." if sys.platform == "win32" else \
            "Guardada em um arquivo só seu, sem criptografia, com permissão restrita."
        if os.environ.get("VT_API_KEY", "").strip():
            info += " Há uma variável VT_API_KEY definida e ela tem prioridade sobre a chave salva."
        tk.Label(pad, text=info, font=self.f_small, bg=WHITE, fg=MUTED, anchor="w", justify="left", wraplength=px(460)).pack(fill="x")
        btns = tk.Frame(pad, bg=WHITE)
        btns.pack(fill="x", pady=(px(14), 0))
        state = {"busy": False}

        def say(text, color=MUTED):
            msg.configure(text=text, fg=color)

        def current():
            return var.get().strip()

        def save():
            k = current()
            if not settings.valid_key_format(k):
                say("A chave do VirusTotal tem 64 letras e números. Confira se copiou inteira.", BAD)
                return
            settings.set_vt_key(k)
            self.refresh_vt_button()
            say("Chave salva.", OK)

        def remove():
            settings.clear_vt_key()
            var.set("")
            self.refresh_vt_button()
            say("Chave removida.", OK)

        def test():
            k = current()
            if not settings.valid_key_format(k):
                say("A chave do VirusTotal tem 64 letras e números. Confira se copiou inteira.", BAD)
                return
            if state["busy"]:
                return
            state["busy"] = True
            say("Testando com o VirusTotal...", INFO)
            out = []
            threading.Thread(target=lambda: out.append(settings.test_vt_key(k)), daemon=True).start()

            def check():
                if not win.winfo_exists():
                    return
                if out:
                    state["busy"] = False
                    ok, text = out[0]
                    say(text, OK if ok else BAD)
                else:
                    win.after(150, check)
            win.after(150, check)

        self.button(btns, "Salvar", save, primary=True).pack(side="left")
        self.button(btns, "Testar", test).pack(side="left", padx=(px(8), 0))
        self.button(btns, "Remover", remove).pack(side="left", padx=(px(8), 0))
        self.button(btns, "Fechar", win.destroy).pack(side="right")
        win.bind("<Escape>", lambda e: win.destroy())
        win.bind("<Return>", lambda e: save())
        win.update_idletasks()
        win.geometry(f"+{self.winfo_rootx() + px(80)}+{self.winfo_rooty() + px(60)}")
        win.grab_set()
        ent.focus_set()

    def link_button(self, parent, text, url):
        b = tk.Label(parent, text=text, font=self.f_small, bg=WHITE, fg="#0969da", cursor="hand2", anchor="w")
        b.configure(font=(self.f_small[0], self.f_small[1], "underline"))
        b.bind("<Button-1>", lambda e: webbrowser.open(url))
        return b

    # ------------------------------------------------------------------ baixar o arquivo verificado
    def verdict_note(self, text, color=INK):
        """Linha de aviso dentro do cartão de veredito (resultado do download)."""
        if getattr(self, "vnote", None) is not None:
            self.vnote.destroy()
        self.vnote = tk.Label(self._vinner, text=text, font=self.f_body, bg=self._vbg, fg=color, anchor="w",
                              justify="left", wraplength=self.px(780))
        self.vnote.pack(fill="x", pady=(self.px(10), 0))

    def confirm_download(self):
        """Pergunta se o usuário tem certeza. Com avisos, lista cada um e a resposta padrão é Não."""
        warns = [c for c in self.last["checks"] if c["status"] == "WARN"]
        if self.last["level"] == "warn" and warns:
            lines = "\n".join(f"• {c['name']}: {c['detail'][:110]}" for c in warns[:5])
            if len(warns) > 5:
                lines += f"\n• e mais {len(warns) - 5} aviso(s)"
            return messagebox.askyesno(
                "Baixar mesmo com avisos?",
                f"A verificação teve avisos:\n\n{lines}\n\nBaixar um arquivo com avisos tem risco. Você tem certeza de que quer baixar?",
                icon="warning", default="no", parent=self)
        return messagebox.askyesno(
            "Baixar o arquivo?",
            "O arquivo passou em todos os testes, mas isso não garante que é seguro.\n\n"
            "O programa vai baixá-lo de novo, conferir se é idêntico ao que foi analisado e só então salvar.\n\nQuer baixar?",
            icon="question", default="yes", parent=self)

    def start_download(self, btn):
        if getattr(self, "dl_active", False):  # o mesmo botão cancela
            self.dl_cancel.set()
            btn.configure(text="Cancelando...", state="disabled")
            return
        facts = self.last["facts"]
        if not self.confirm_download():
            return
        folder = os.path.join(os.path.expanduser("~"), "Downloads")
        dest = filedialog.asksaveasfilename(
            title="Onde salvar o arquivo verificado", initialdir=folder if os.path.isdir(folder) else None,
            initialfile=sc.suggest_filename(), defaultextension=os.path.splitext(sc.suggest_filename())[1] or ".bin",
            filetypes=[("Arquivo verificado", "*" + (os.path.splitext(sc.suggest_filename())[1] or ".bin")), ("Todos os arquivos", "*.*")])
        if not dest:
            return
        self.dl_active, self.dl_cancel, self.dl_btn, self.dl_dest = True, threading.Event(), btn, dest
        btn.configure(text="Cancelar download")
        for b in (self.btn, self.pick):
            b.configure(state="disabled")
        self.entry.configure(state="disabled")
        self.verdict_note("Preparando o download...", MUTED)
        self.bar["value"] = 0
        self.pct.set("0%")
        threading.Thread(target=self.download_worker, args=(dest, facts), daemon=True).start()

    def download_worker(self, dest, facts):
        try:
            url = sc.fresh_download_url()
            if not url:
                raise RuntimeError("não encontrei o link direto do arquivo")
            progress = lambda d: self.q.put(("dlprog", d))  # noqa: E731
            try:
                downloader.download_file(url, dest, facts["sha256"], facts.get("size"), on_progress=progress, cancel=self.dl_cancel)
            except downloader.Stalled as direct_err:
                # o caminho de rede do PC (ou o servidor) corta a conexão: tenta pelo contêiner Docker, que usa outra rota
                self.q.put(("dlprog", {"done": 0, "total": None,
                                       "note": "A conexão direta do seu PC foi cortada. Tentando baixar pelo contêiner Docker, que usa outra rota de rede..."}))
                try:
                    sc.download_via_container(url, dest, facts["sha256"], facts.get("size"), on_progress=progress, cancel=self.dl_cancel)
                except (downloader.Cancelled, downloader.HashMismatch):
                    raise
                except Exception as via_err:  # noqa: BLE001
                    raise RuntimeError(f"{direct_err}.\n\nTentei também pelo contêiner Docker e falhou: {via_err}.\n"
                                       "Se as duas rotas falham, quem corta é o servidor (o MediaFire limita downloads grandes por IP). "
                                       "Tente de novo mais tarde ou em outra rede.")
            scan = None
            if sc.find_mpcmdrun():  # Windows: o Defender confere o arquivo já salvo (lê, não abre)
                self.q.put(("dlprog", {"done": 0, "total": None, "note": "Baixado e conferido. Agora o Microsoft Defender está escaneando o arquivo..."}))
                scan = sc.defender_scan(dest)
            self.q.put(("dldone", (dest, scan)))
        except downloader.Cancelled:
            downloader.cleanup_part(dest)
            self.q.put(("dlcancel", None))
        except downloader.HashMismatch as e:
            self.q.put(("dlmismatch", str(e)))
        except Exception as e:  # noqa: BLE001
            downloader.cleanup_part(dest)
            self.q.put(("dlerror", f"{e}" if isinstance(e, (RuntimeError, OSError)) else f"{type(e).__name__}: {e}"))

    def download_finished(self, button_text, button_state="normal"):
        self.dl_active = False
        for b in (self.btn, self.pick):
            b.configure(state="normal")
        self.entry.configure(state="normal")
        if self.dl_btn.winfo_exists():
            self.dl_btn.configure(text=button_text, state=button_state)

    def reveal(self, path):
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", os.path.dirname(path)])
        except OSError:
            pass

    def on_download_event(self, kind, data):
        if kind == "dlprog":
            text = sc.download_text(data)
            self.status.set("Baixando para o seu PC: " + text)
            if data.get("total"):
                pct = int(data["done"] * 100 / data["total"])
                self.bar["value"] = pct
                self.pct.set(f"{pct}%")
            self.verdict_note(text, WARN if data.get("note") else MUTED)
        elif kind == "dldone":
            self.status.set("Arquivo baixado e conferido.")
            self.bar["value"] = 100
            self.pct.set("100%")
            dest, scan = data
            extra = " A verificação teve avisos: abra com cuidado." if self.last["level"] == "warn" else ""
            if scan and scan["status"] == "FAIL":  # o Defender achou algo no arquivo já salvo
                self.status.set("O Defender encontrou uma ameaça no arquivo baixado.")
                self.verdict_note(f"Baixado em {dest}, mas o Microsoft Defender encontrou: {scan['detail']}. NÃO abra o arquivo e apague-o.", BAD)
            else:
                dfd = ""
                if scan and scan["status"] == "PASS":
                    dfd = " O Microsoft Defender também não encontrou ameaças."
                elif scan and scan["status"] != "SKIP":
                    dfd = f" Defender: {scan['detail']}"
                self.verdict_note(f"Baixado em {dest}. O SHA-256 é idêntico ao do arquivo analisado no sandbox.{dfd}{extra}", OK)
            self.download_finished("Mostrar na pasta")
            self.dl_btn.configure(command=lambda p=dest: self.reveal(p))
        elif kind == "dlmismatch":
            self.status.set("O arquivo baixado é diferente do analisado.")
            self.verdict_note(f"O arquivo baixado é diferente do que foi analisado (SHA-256 {data[:16]}… em vez de "
                              f"{self.last['facts']['sha256'][:16]}…). Ele foi apagado. O servidor pode estar entregando um "
                              "arquivo diferente para você: não use este link.", BAD)
            self.download_finished("Download bloqueado", "disabled")
        elif kind == "dlcancel":
            self.status.set("Download cancelado.")
            self.verdict_note("Download cancelado. Nada foi salvo.", MUTED)
            self.download_finished(self.dl_label)
        elif kind == "dlerror":
            self.status.set("Não foi possível baixar o arquivo.")
            self.verdict_note(f"Não foi possível baixar: {data}", BAD)
            self.download_finished("Tentar baixar de novo")

    def open_path(self, caminho):
        """Abre um arquivo ou pasta com o programa padrão do sistema."""
        try:
            if sys.platform == "win32":
                os.startfile(caminho)
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", caminho])
        except OSError:
            pass

    def open_reports_folder(self):
        """Abre a pasta onde os relatórios são salvos (e a cria se ainda não existir)."""
        pasta = settings.reports_dir()
        os.makedirs(pasta, exist_ok=True)
        self.open_path(pasta)

    def open_report(self):
        """Abre o relatório HTML completo no navegador padrão."""
        if self.report_path:
            html_file = sc.html_path_for(self.report_path)
            if os.path.exists(html_file):
                sc.open_in_browser(html_file)


if __name__ == "__main__":
    App().mainloop()
