"""Gera o relatório HTML completo do safecheck: um único arquivo, sem recursos externos.

Recebe um dicionário com tudo que precisa (ver safecheck.build_report_data), para não importar safecheck.
"""
import html
import json
from datetime import datetime

E = html.escape
STATUS = {
    "PASS": ("Aprovado", "ok", "✓"),
    "FAIL": ("Reprovado", "bad", "✗"),
    "WARN": ("Atenção", "warn", "!"),
    "SKIP": ("Não executado", "skip", "–"),
    "INFO": ("Informação", "info", "i"),
}
GROUPS = ["Conferência inicial", "Dentro do sandbox", "Reputação do arquivo"]
EARLY = {"scheme", "host", "dns", "resolve", "probe", "clen", "ext", "size_cap", "shortener", "ctype", "defender"}


def group_of(cid):
    if cid in EARLY:
        return GROUPS[0]
    return GROUPS[2] if cid == "vt" else GROUPS[1]


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.2f} {unit}".replace(".", ",")
        n /= 1000


def dur(s):
    s = int(s)
    if s >= 3600:
        return f"{s // 3600}h{s % 3600 // 60:02d}m{s % 60:02d}s"
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


CSS = """
:root{--paper:#F2F4F5;--card:#fff;--ink:#1B2730;--muted:#5C6B75;--rule:#D5DBDF;--accent:#14606B;--soft:#EAF0F2;
--ok:#2E7D4F;--warn:#9A6A12;--bad:#B83232;--info:#2A6F97;--ok-bg:#E7F3EB;--warn-bg:#FBF2DD;--bad-bg:#FBE9E9;--code:#EEF2F4}
@media (prefers-color-scheme:dark){:root{--paper:#11181D;--card:#192229;--ink:#E6ECEF;--muted:#9AAAB4;--rule:#2C3942;--accent:#5FB3BF;--soft:#1F2A32;
--ok:#6CC38C;--warn:#E0B04F;--bad:#EE7F7F;--info:#7DB7DD;--ok-bg:#16291F;--warn-bg:#2C2515;--bad-bg:#2E1B1B;--code:#202B33}}
*{box-sizing:border-box}html{scroll-behavior:smooth}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
h1,h2,h3,.big{font-family:Bahnschrift,"Segoe UI Semibold","Segoe UI",system-ui,sans-serif;letter-spacing:.2px;margin:0}
.wrap{max-width:1040px;margin:0 auto;padding:0 20px 80px}
header.top{padding:28px 0 18px;display:flex;flex-wrap:wrap;gap:6px 16px;align-items:baseline;justify-content:space-between}
header.top h1{font-size:1.55rem}.muted{color:var(--muted)}.small{font-size:.86rem}
nav.toc{position:sticky;top:0;z-index:5;background:var(--paper);border-bottom:1px solid var(--rule);display:flex;gap:4px;flex-wrap:wrap;padding:8px 0;margin-bottom:22px}
nav.toc a{color:var(--muted);text-decoration:none;padding:6px 12px;border-radius:6px;font-size:.92rem}
nav.toc a:hover,nav.toc a:focus-visible{background:var(--soft);color:var(--ink);outline:none}
section{margin:0 0 34px;scroll-margin-top:60px}section>h2{font-size:1.3rem;margin-bottom:12px}
.verdict{display:flex;border-radius:8px;overflow:hidden;margin-bottom:26px}
.verdict .edge{width:10px;flex:none}.verdict .body{padding:20px 24px;flex:1}
.verdict h2{font-size:2rem;line-height:1.15}.verdict p{margin:8px 0 0;max-width:70ch}
.verdict.bad{background:var(--bad-bg)}.verdict.bad .edge{background:var(--bad)}.verdict.bad h2{color:var(--bad)}
.verdict.warn{background:var(--warn-bg)}.verdict.warn .edge{background:var(--warn)}.verdict.warn h2{color:var(--warn)}
.verdict.ok{background:var(--ok-bg)}.verdict.ok .edge{background:var(--ok)}.verdict.ok h2{color:var(--ok)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.chip{background:var(--card);border-radius:999px;padding:3px 12px;font-weight:600;font-size:.88rem}
.chip.ok{color:var(--ok)}.chip.bad{color:var(--bad)}.chip.warn{color:var(--warn)}.chip.skip{color:var(--muted)}.chip.info{color:var(--info)}
.card{background:var(--card);border:1px solid var(--rule);border-radius:8px}
dl.kv{display:grid;grid-template-columns:minmax(150px,230px) 1fr;margin:0}
dl.kv dt,dl.kv dd{margin:0;padding:10px 16px;border-top:1px solid var(--rule)}
dl.kv dt:first-of-type,dl.kv dd:first-of-type{border-top:0}dl.kv dt{color:var(--muted);font-size:.92rem}
dl.kv dd{overflow-wrap:anywhere}
code,.mono{font-family:Consolas,"Cascadia Mono",ui-monospace,monospace;font-size:.88rem;background:var(--code);padding:1px 6px;border-radius:4px}
.hash{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
button,.btn{font:inherit;font-size:.86rem;font-weight:600;background:var(--card);color:var(--ink);border:1px solid var(--rule);border-radius:6px;padding:4px 10px;cursor:pointer;text-decoration:none}
button:hover,.btn:hover{background:var(--soft)}button:focus-visible,.btn:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.tools{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}.tools button[aria-pressed=true]{background:var(--accent);color:var(--card);border-color:var(--accent)}
.group{margin-bottom:18px}.group h3{font-size:1.02rem;margin:0 0 6px;display:flex;gap:10px;align-items:baseline}
details.test{border-top:1px solid var(--rule)}details.test:first-of-type{border-top:0}
details.test>summary{list-style:none;display:grid;grid-template-columns:28px minmax(180px,300px) 1fr auto;gap:8px;align-items:baseline;padding:10px 14px;cursor:pointer}
details.test>summary::-webkit-details-marker{display:none}details.test>summary:hover{background:var(--soft)}
.ico{font-weight:700;text-align:center}.ico.ok,.w.ok{color:var(--ok)}.ico.bad,.w.bad{color:var(--bad)}.ico.warn,.w.warn{color:var(--warn)}.ico.skip,.w.skip{color:var(--muted)}.ico.info,.w.info{color:var(--info)}
.tname{font-weight:600}.tsum{color:var(--muted);font-size:.9rem;overflow-wrap:anywhere}.w{font-weight:600;font-size:.86rem;white-space:nowrap}
details.test .more{padding:4px 18px 16px 50px;background:var(--soft)}details.test .more h4{margin:12px 0 2px;font-size:.84rem;color:var(--muted);font-weight:600}
details.test .more p{margin:0;max-width:75ch}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px 14px;border-top:1px solid var(--rule);vertical-align:top}th{font-size:.84rem;color:var(--muted);font-weight:600;border-top:0}
.lvl{font-weight:700;white-space:nowrap}.lvl.good{color:var(--ok)}.lvl.part{color:var(--warn)}.lvl.gap{color:var(--bad)}
.steps{counter-reset:s;margin:0;padding:0;list-style:none}.steps li{padding:14px 18px;border-top:1px solid var(--rule)}.steps li:first-child{border-top:0}
.steps b{display:block}.steps p{margin:4px 0 0;color:var(--muted);max-width:80ch}
ul.plain{margin:0;padding:0;list-style:none}ul.plain li{padding:10px 18px;border-top:1px solid var(--rule)}ul.plain li:first-child{border-top:0}
.timeline{margin:0;padding:6px 18px 6px 34px;border-left:2px solid var(--rule);margin-left:14px;list-style:none}
.timeline li{position:relative;padding:5px 0}.timeline li::before{content:"";position:absolute;left:-41px;top:12px;width:10px;height:10px;border-radius:50%;background:var(--rule)}
.timeline li.ok::before{background:var(--ok)}.timeline li.bad::before{background:var(--bad)}.timeline li.warn::before{background:var(--warn)}
pre{margin:0;padding:14px 16px;overflow:auto;font-size:.8rem;background:var(--code);border-radius:0 0 8px 8px;max-height:420px}
.hex{font-family:Consolas,ui-monospace,monospace;font-size:.82rem;overflow-wrap:anywhere;padding:12px 16px}
.boxbar{display:flex;height:22px;margin:12px 16px 4px;border-radius:4px;overflow:hidden;background:var(--rule)}.boxbar span{min-width:3px}
.legend{display:flex;gap:14px;flex-wrap:wrap;padding:6px 16px 14px;font-size:.84rem;color:var(--muted)}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}
.disclaimer{border-left:4px solid var(--warn);background:var(--warn-bg);padding:14px 18px;border-radius:0 8px 8px 0}
footer{color:var(--muted);font-size:.86rem;margin-top:40px;border-top:1px solid var(--rule);padding-top:14px}
@media (max-width:700px){dl.kv{grid-template-columns:1fr}dl.kv dt{padding-bottom:0}details.test>summary{grid-template-columns:24px 1fr;}details.test>summary .tsum,details.test>summary .w{grid-column:2}}
@media print{nav.toc,.tools,button{display:none!important}details.test{break-inside:avoid}body{background:#fff}details>*{display:block!important}.wrap{max-width:none}}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
"""

JS = """
function cp(t,b){navigator.clipboard.writeText(t).then(function(){var o=b.textContent;b.textContent='Copiado';setTimeout(function(){b.textContent=o},1500)})}
document.querySelectorAll('[data-copy]').forEach(function(b){b.addEventListener('click',function(){cp(b.dataset.copy,b)})});
var fb=document.querySelectorAll('[data-filter]');
fb.forEach(function(b){b.addEventListener('click',function(){
  fb.forEach(function(x){x.setAttribute('aria-pressed',x===b?'true':'false')});
  var f=b.dataset.filter;
  document.querySelectorAll('details.test').forEach(function(d){d.hidden=(f==='problems'&&!(d.dataset.s==='bad'||d.dataset.s==='warn'))});
  document.querySelectorAll('.group').forEach(function(g){g.hidden=!g.querySelector('details.test:not([hidden])')});
})});
document.querySelectorAll('[data-expand]').forEach(function(b){b.addEventListener('click',function(){
  var open=b.dataset.expand==='all';document.querySelectorAll('details.test').forEach(function(d){d.open=open})})});
"""


def row(label, value, raw=False):
    if value in (None, ""):
        return ""
    return f"<dt>{E(label)}</dt><dd>{value if raw else E(str(value))}</dd>"


def copyable(value, label="Copiar"):
    return f'<span class="hash"><code>{E(value)}</code><button type="button" data-copy="{E(value)}">{E(label)}</button></span>'


def build_html(d):
    """d: dict com url, method, checks, facts, verdict_level, verdict_title, verdict_text, steps, coverage,
    limitations, descr, meaning, glossary, plan, times, started, duration, vt_link, tool, os_info, sandbox_info."""
    checks, facts = d["checks"], d["facts"]
    ctx = facts.get("context", {})
    counts = {s: sum(c["status"] == s for c in checks) for s in STATUS}
    lvl = d["verdict_level"]
    sha = facts.get("sha256", "")

    # ---------- veredito
    plural = {"PASS": ("aprovado", "aprovados"), "FAIL": ("reprovado", "reprovados"), "WARN": ("aviso", "avisos"),
              "SKIP": ("não executado", "não executados")}
    chips = "".join(f'<span class="chip {STATUS[s][1]}">{counts[s]} {plural[s][counts[s] != 1]}</span>'
                    for s in ("PASS", "FAIL", "WARN", "SKIP") if counts[s])
    verdict = (f'<div class="verdict {lvl}" role="status"><div class="edge"></div><div class="body">'
               f'<h2>{E(d["verdict_title"])}</h2><p>{E(d["verdict_text"])}</p><div class="chips">{chips}</div></div></div>')

    # ---------- identificação
    parts = []
    if ctx.get("kind") == "link":
        parts += [row("Origem", "Link"), row("Endereço (sem parâmetros)", ctx.get("url")),
                  row("Servidor do download", ctx.get("direct_host") or facts.get("final_url_host")),
                  row("Caminho de redirecionamentos", " → ".join(ctx.get("hops", [])) if ctx.get("hops") else ""),
                  row("Tipo anunciado pelo servidor", ctx.get("announced_type")),
                  row("Tamanho anunciado", human(ctx["announced_length"]) if str(ctx.get("announced_length", "")).isdigit() else ""),
                  row("Tipo recebido pelo sandbox", facts.get("content_type")),
                  row("Última modificação (servidor)", facts.get("last_modified"))]
    elif ctx.get("kind") == "arquivo":
        parts += [row("Origem", "Arquivo local"), row("Caminho", ctx.get("path")), row("Nome", ctx.get("name")),
                  row("Modificado em", ctx.get("modified")), row("Criado em", ctx.get("created"))]
    if facts.get("size"):
        parts.append(row("Tamanho", f"{human(facts['size'])} ({format(facts['size'], ',').replace(',', '.')} bytes)"))
    if sha:
        parts.append(row("SHA-256", copyable(sha), True))
    if facts.get("sha1"):
        parts.append(row("SHA-1", copyable(facts["sha1"]), True))
    if facts.get("md5"):
        parts.append(row("MD5", copyable(facts["md5"]), True))
    if sha:
        parts.append(row("VirusTotal (por hash)", f'<a class="btn" href="{E(d["vt_link"])}" target="_blank" rel="noopener noreferrer">Abrir no VirusTotal</a>', True))
    ident = f'<section id="arquivo"><h2>Identificação</h2><div class="card"><dl class="kv">{"".join(parts)}</dl></div></section>'

    # ---------- conteúdo técnico do vídeo
    media = []
    if facts.get("format_name"):
        media.append(row("Formato (ffprobe)", facts["format_name"]))
    for i, s in enumerate(facts.get("streams", []), 1):
        bits = [s.get("codec_type", "?"), s.get("codec_name", "?")]
        if s.get("width"):
            bits.append(f"{s.get('width')}x{s.get('height')}")
        media.append(row(f"Stream {i}", " / ".join(bits)))
    if facts.get("duration_s"):
        media.append(row("Duração", dur(facts["duration_s"])))
    if facts.get("width"):
        media.append(row("Resolução", f"{facts['width']}x{facts['height']}"))
    if facts.get("mbps") is not None and facts.get("duration_s"):
        media.append(row("Bitrate médio", f"{facts['mbps']:.2f} Mbps".replace(".", ",")))
    boxes = facts.get("boxes", [])
    boxviz = ""
    if boxes:
        total = sum(b[1] for b in boxes) or 1
        pal = {"ftyp": "#2A6F97", "moov": "#14606B", "mdat": "#8CA3AE", "free": "#B83232", "skip": "#B83232", "uuid": "#9A6A12"}
        segs = "".join(f'<span title="{E(b[0])}: {human(b[1])}" style="flex:{max(b[1], total * 0.004)};background:{pal.get(b[0], "#9A6A12")}"></span>' for b in boxes)
        names = ", ".join(f"{E(b[0])} ({human(b[1])})" for b in boxes[:40])
        boxviz = (f'<div class="boxbar" aria-hidden="true">{segs}</div>'
                  '<div class="legend"><span><i style="background:#2A6F97"></i>ftyp</span><span><i style="background:#14606B"></i>moov (índice)</span>'
                  '<span><i style="background:#8CA3AE"></i>mdat (vídeo e áudio)</span><span><i style="background:#B83232"></i>free/skip (espaço livre)</span>'
                  '<span><i style="background:#9A6A12"></i>outras</span></div>'
                  f'<p class="small muted" style="padding:0 16px 14px;margin:0">Caixas de topo, em ordem: {names}.</p>')
    hexdump = ""
    if facts.get("header_hex"):
        hx = facts["header_hex"]
        hexdump = ('<h3 style="margin:18px 0 8px;font-size:1.02rem">Primeiros 64 bytes</h3><div class="card"><div class="hex">'
                   + " ".join(hx[i:i + 2] for i in range(0, len(hx), 2)) + "</div></div>")
    tech = ""
    if media or boxviz:
        tech = (f'<section id="video"><h2>Conteúdo da mídia</h2><div class="card"><dl class="kv">{"".join(media)}</dl>{boxviz}</div>{hexdump}</section>')

    # ---------- detalhes por tipo (tags de áudio, palavras-chave e links de PDF...)
    det_rows = facts.get("details") or []
    detail_sec = ""
    if det_rows:
        kv = "".join(row(k, v) for k, v in det_rows)
        detail_sec = f'<section id="detalhes"><h2>Detalhes do conteúdo</h2><div class="card"><dl class="kv">{kv}</dl></div></section>'

    # ---------- testes
    by = {}
    for c in checks:
        by.setdefault(c["id"], c)
    groups = {g: [] for g in GROUPS}
    for c in checks:
        groups[group_of(c["id"])].append(c)
    gh = []
    for g in GROUPS:
        items = groups[g]
        if not items:
            continue
        ds = []
        for c in items:
            w, cls, ic = STATUS[c["status"]]
            descr = d["descr"].get(c["id"], "")
            mean = d["meaning"].get(c["id"], "")
            t = d["times"].get(c["id"])
            when = f'<h4>Quando</h4><p>{E(t)} após o início (aproximado)</p>' if t else ""
            meaning = f'<h4>Se reprovar ou avisar</h4><p>{E(mean)}</p>' if mean else ""
            op = " open" if c["status"] in ("FAIL", "WARN") else ""
            ds.append(
                f'<details class="test" data-s="{cls}"{op}><summary><span class="ico {cls}">{ic}</span><span class="tname">{E(c["name"])}</span>'
                f'<span class="tsum">{E(c["detail"][:110])}</span><span class="w {cls}">{E(w)}</span></summary>'
                f'<div class="more"><h4>O que este teste faz</h4><p>{E(descr)}</p><h4>Resultado</h4><p>{E(c["detail"])}</p>{meaning}{when}</div></details>')
        done = sum(1 for c in items if c["status"] != "SKIP")
        gh.append(f'<div class="group"><h3>{E(g)}<span class="muted small">{done} de {len(items)} executados</span></h3><div class="card">{"".join(ds)}</div></div>')
    tests = ('<section id="testes"><h2>Resultado de cada teste</h2><div class="tools">'
             '<button type="button" data-filter="all" aria-pressed="true">Todos</button>'
             '<button type="button" data-filter="problems" aria-pressed="false">Só problemas e avisos</button>'
             '<button type="button" data-expand="all">Abrir tudo</button><button type="button" data-expand="none">Fechar tudo</button></div>'
             + "".join(gh) + "</section>")

    # ---------- linha do tempo
    tl = ""
    ordered = sorted((c for c in checks if d["times"].get(c["id"])), key=lambda c: d["times_raw"].get(c["id"], 0))
    if ordered:
        li = "".join(f'<li class="{STATUS[c["status"]][1]}"><b>{E(d["times"][c["id"]])}</b> &nbsp;{E(c["name"])}: <span class="muted">{E(STATUS[c["status"]][0])}</span></li>'
                     for c in ordered)
        tl = (f'<section id="tempo"><h2>Linha do tempo</h2><p class="muted small">Tempos aproximados: o programa consulta o sandbox a cada poucos segundos. '
              f'Duração total: {E(d["duration"])}.</p><ul class="timeline">{li}</ul></section>')

    # ---------- próximos passos
    steps = "".join(f'<li><b>{E(t)}</b><p>{E(x)}</p></li>' for t, x in d["steps"])
    nxt = f'<section id="proximos"><h2>Próximos passos</h2><div class="card"><ol class="steps">{steps}</ol></div></section>'

    # ---------- cobertura
    cov_rows = "".join(
        f'<tr><td>{E(c)}</td><td class="lvl {"good" if l == "coberto" else "part" if l == "parcial" else "gap"}">{E(l.capitalize())}</td><td class="muted">{E(h)}</td></tr>'
        for c, l, h in d["coverage"])
    cov = ('<section id="cobertura"><h2>O que foi coberto e o que não foi</h2><div class="card"><table><thead><tr><th>Ameaça ou problema</th><th>Cobertura</th><th>Como</th></tr></thead>'
           f'<tbody>{cov_rows}</tbody></table></div></section>')

    # ---------- ambiente / metodologia
    env = [row("Ferramenta", d["tool"]), row("Sandbox usado", d["method"]), row("Sistema do seu PC", d["os_info"]),
           row("Antivírus no sandbox", facts.get("clamav") or ("Microsoft Defender" if "Windows" in d["method"] else "")),
           row("Python no sandbox", facts.get("python")), row("Início", d["started"]), row("Duração", d["duration"])]
    for k, v in d["sandbox_info"]:
        env.append(row(k, v))
    method = (f'<section id="metodo"><h2>Ambiente e método</h2><div class="card"><dl class="kv">{"".join(env)}</dl></div></section>')

    # ---------- limitações, glossário, dados
    lim = "".join(f"<li>{E(l)}</li>" for l in d["limitations"])
    glos = "".join(f"<li><b>{E(t)}</b><br><span class=\"muted\">{E(x)}</span></li>" for t, x in d["glossary"])
    raw = json.dumps({"target": d["url"], "sandbox": d["method"], "checks": checks, "facts": facts}, ensure_ascii=False, indent=2).replace("</", "<\\/")
    tail = (f'<section id="limites"><h2>Limitações</h2><div class="disclaimer"><b>Este relatório não garante que o arquivo é seguro.</b> '
            'Ele registra o que foi verificado e o que não foi. Ausência de alertas não é prova de que o arquivo está limpo.</div>'
            f'<div class="card" style="margin-top:14px"><ul class="plain">{lim}</ul></div></section>'
            f'<section id="glossario"><h2>Glossário</h2><div class="card"><ul class="plain">{glos}</ul></div></section>'
            f'<section id="dados"><h2>Dados brutos</h2><details class="card"><summary style="padding:12px 16px;cursor:pointer">Mostrar JSON</summary><pre>{E(raw)}</pre></details></section>')

    toc = "".join(f'<a href="#{i}">{t}</a>' for i, t in (("arquivo", "Identificação"), ("video", "Mídia"), ("detalhes", "Detalhes"), ("testes", "Testes"),
                  ("tempo", "Linha do tempo"), ("proximos", "Próximos passos"), ("cobertura", "Cobertura"),
                  ("metodo", "Método"), ("limites", "Limitações"), ("glossario", "Glossário"), ("dados", "Dados")))
    title = ctx.get("name") or ctx.get("url") or "arquivo"
    return (f'<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex"><title>Relatório de segurança: {E(str(title))[:60]}</title><style>{CSS}</style></head><body><div class="wrap">'
            f'<header class="top"><h1>Relatório de segurança do arquivo</h1><span class="muted small">Gerado em {E(d["started"])} por {E(d["tool"])}</span></header>'
            f'<nav class="toc" aria-label="Seções">{toc}</nav>{verdict}{ident}{tech}{detail_sec}{tests}{tl}{nxt}{cov}{method}{tail}'
            f'<footer>Relatório local e autocontido: não carrega nada da internet. Guarde ou apague junto com o arquivo analisado.</footer></div>'
            f'<script>{JS}</script></body></html>')
