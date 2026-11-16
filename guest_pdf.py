"""Análise estática de PDF, estilo pdfid + checagem de estrutura. Roda dentro do sandbox.

Não renderiza nem executa nada. Descompacta fluxos FlateDecode com limites rígidos (proteção contra bombas de descompressão)
para enxergar o que fica escondido dentro de object streams.
"""
import os
import re
import shutil
import subprocess
import urllib.parse
import zlib

MB = 1024 * 1024
MAX_FILE = 300 * MB          # acima disso, só os testes de estrutura
MAX_STREAM_OUT = 20 * MB     # por fluxo
MAX_TOTAL_OUT = 200 * MB     # no total
MAX_STREAMS = 20000

DELIM = rb"(?=[\s/<>\[\]()%]|$)"
KEYWORDS = ["JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "EmbeddedFiles", "RichMedia", "XFA",
            "AcroForm", "URI", "SubmitForm", "GoToR", "GoToE", "ImportData", "ObjStm", "JBIG2Decode", "Encrypt", "Sound", "Movie"]
PATTERNS = {k: re.compile(rb"/" + k.encode() + DELIM) for k in KEYWORDS}
# Palavras que, sozinhas, já merecem atenção (as demais são comuns em PDFs normais)
ATTENTION = {"JavaScript", "JS", "OpenAction", "AA", "Launch", "EmbeddedFile", "RichMedia", "XFA", "SubmitForm", "GoToR",
             "GoToE", "ImportData", "JBIG2Decode", "Encrypt", "Sound", "Movie"}
# (nome legível, expressão): técnicas comuns em JavaScript de exploit em PDF
SUSPECT_JS = [("eval()", rb"eval\s*\("), ("unescape()", rb"unescape\s*\("), ("String.fromCharCode", rb"String\.fromCharCode"),
              ("shellcode em %uXXXX", rb"%u[0-9a-fA-F]{4}%u[0-9a-fA-F]{4}"), ("app.launchURL", rb"app\.launchURL"),
              ("exportDataObject", rb"exportDataObject"), ("util.printf", rb"util\.printf"),
              ("collab.collectEmailInfo", rb"collab\.collectEmailInfo"), ("media.newPlayer", rb"media\.newPlayer"),
              ("getAnnots", rb"getAnnots"), ("this.submitForm", rb"this\.submitForm"), ("app.execMenuItem", rb"app\.execMenuItem")]
SUSPECT_JS = [(name, re.compile(p)) for name, p in SUSPECT_JS]
BAD_NAMES = re.compile(rb"\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsf|hta|ps1|lnk|jar|msi|dll|docm|xlsm|iso)\b", re.I)
DOS_STUB = b"This program cannot be run in DOS mode"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly", "shorturl.at"}


def unhex_names(data):
    """Desfaz o disfarce '/J#61vaScript' (letras escritas como #xx dentro de nomes)."""
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), data)


def decompress_streams(data):
    """Percorre os 'stream ... endstream' e tenta descompactar. Retorna (lista_de_conteúdos, estatísticas)."""
    out, total, n, skipped, multi_filter = [], 0, 0, 0, 0
    pos = 0
    while n < MAX_STREAMS:
        s = data.find(b"stream", pos)
        if s < 0:
            break
        pos = s + 6
        if data[max(0, s - 3):s] == b"end":
            continue
        start = s + 6
        if data[start:start + 2] == b"\r\n":
            start += 2
        elif data[start:start + 1] in (b"\n", b"\r"):
            start += 1
        e = data.find(b"endstream", start)
        if e < 0:
            break
        pos = e + 9
        n += 1
        dict_text = data[max(0, s - 600):s]
        d_start = dict_text.rfind(b"<<")
        dict_text = dict_text[d_start:] if d_start >= 0 else dict_text
        filt = re.search(rb"/Filter\s*(\[[^\]]*\]|/\w+)", dict_text)
        if filt and filt.group(1).count(b"/") >= 2:
            multi_filter += 1
        if b"FlateDecode" not in dict_text and b"/Fl" not in dict_text:
            out.append(data[start:min(e, start + 4096)])  # fluxo não compactado: confere só o começo
            continue
        if total >= MAX_TOTAL_OUT:
            skipped += 1
            continue
        try:
            d = zlib.decompressobj()
            chunk = d.decompress(data[start:e], MAX_STREAM_OUT)
            if d.unconsumed_tail:
                skipped += 1  # saída maior que o limite: parece bomba de descompressão
            total += len(chunk)
            out.append(chunk)
        except zlib.error:
            skipped += 1
    return out, {"streams": n, "skipped": skipped, "multi_filter": multi_filter, "decompressed": total}


def run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)


def tool_views(path, size, res):
    """Visões extras do mesmo PDF, geradas por ferramentas independentes. Retorna (textos_extras, pdf_normalizado).
    Guarda em res['attachments'] os nomes dos anexos (pdfdetach). Falhas são ignoradas: são só reforços."""
    extra, qdf_bytes = [], b""
    if shutil.which("pdfinfo"):
        try:  # só mostra scripts do nível do documento (árvore de nomes), então muitas vezes sai vazio
            js = run(["pdfinfo", "-js", path], 60).stdout
            if js.strip():
                extra.append(js.encode("utf-8", "replace"))
                res["details"].append(["JavaScript do documento (pdfinfo)", f"{len(js)} caracteres"])
        except Exception:  # noqa: BLE001
            pass
    if shutil.which("pdfdetach"):
        try:
            out = run(["pdfdetach", "-list", path], 60).stdout
            names = [m.group(1).strip() for m in re.finditer(r"^\s*\d+:\s+(.+)$", out, re.M)]
            res["attachments"] = names[:50]
            if names:
                res["details"].append(["Anexos (pdfdetach)", ", ".join(names[:8])])
        except Exception:  # noqa: BLE001
            pass
    if shutil.which("qpdf") and size <= 40 * MB:
        out = "/tmp/safecheck_qdf.pdf"
        try:  # normaliza: descompacta tudo e abre os object streams, para a busca de palavras-chave enxergar o conteúdo escondido
            r = run(["qpdf", "--qdf", "--object-streams=disable", "--stream-data=uncompress", path, out], 120)
            if r.returncode in (0, 3) and os.path.exists(out) and os.path.getsize(out) <= 150 * MB:
                with open(out, "rb") as f:
                    qdf_bytes = f.read()
        except Exception:  # noqa: BLE001
            pass
        finally:
            try:
                os.remove(out)
            except OSError:
                pass
    return extra, qdf_bytes


def analyze_pdf(path, size):
    """Retorna dict com: structure (lista), audit (lista de (nível, texto)), embedded (lista), quality (status, texto), details."""
    res = {"structure": [], "audit": [], "embedded": [], "quality": None, "details": [], "uris": []}
    with open(path, "rb") as f:
        head = f.read(1024)
        f.seek(max(0, size - 4096))
        tail = f.read()
    hdr = head.find(b"%PDF-")
    if hdr > 0:
        res["structure"].append(f"{hdr} bytes de lixo antes do cabeçalho %PDF (técnica de arquivo duplo)")
    ver = re.search(rb"%PDF-(\d\.\d)", head)
    if ver:
        res["details"].append(["Versão do PDF", ver.group(1).decode()])
    sx = tail.rfind(b"startxref")
    eof = tail.rfind(b"%%EOF")
    if sx < 0:
        res["structure"].append("sem 'startxref' no fim (arquivo truncado ou adulterado)")
    if eof < 0:
        res["structure"].append("sem marcador %%EOF no fim")
    else:
        after = tail[eof + 5:].strip(b"\r\n \x00")
        if len(tail) - eof - 5 > 16 and after:
            res["structure"].append(f"{len(tail) - eof - 5} bytes depois do último %%EOF (dados anexados?)")
    if sx >= 0:
        m = re.search(rb"startxref\s+(\d+)", tail[sx:])
        if m and int(m.group(1)) > size:
            res["structure"].append("o ponteiro 'startxref' aponta para fora do arquivo")

    if size > MAX_FILE:
        res["audit"].append(("WARN", f"arquivo de {size / 1e6:.0f} MB grande demais para a auditoria de conteúdo ativo"))
        return res
    with open(path, "rb") as f:
        data = f.read()
    objs, ends = len(re.findall(rb"\d+\s+\d+\s+obj\b", data)), data.count(b"endobj")
    res["details"].append(["Objetos", f"{objs}"])
    if abs(objs - ends) > max(10, objs // 20):
        res["structure"].append(f"{objs} objetos abertos e {ends} fechados (estrutura inconsistente)")
    eofs = data.count(b"%%EOF")
    if eofs > 1:
        res["details"].append(["Atualizações incrementais", f"{eofs - 1}"])

    streams, sinfo = decompress_streams(data)
    res["details"].append(["Fluxos de dados", f"{sinfo['streams']}"])
    extra_js, qdf = tool_views(path, size, res)  # JavaScript do pdfinfo e o PDF normalizado pelo qpdf (--qdf)
    corpus = [data] + streams + extra_js
    qdf_views = [qdf] if qdf else []
    pd_names = res.pop("attachments", [])
    obf = len(re.findall(rb"/[A-Za-z]+#[0-9A-Fa-f]{2}", data))
    if obf:
        corpus = [unhex_names(c) for c in corpus]
        qdf_views = [unhex_names(c) for c in qdf_views]
    counts = {k: sum(len(p.findall(c)) for c in corpus) for k, p in PATTERNS.items()}
    if qdf_views:  # a versão normalizada pode revelar o que estava escondido; vale o maior valor (sem contar duas vezes)
        qc = {k: sum(len(p.findall(c)) for c in qdf_views) for k, p in PATTERNS.items()}
        counts = {k: max(v, qc[k]) for k, v in counts.items()}
    scan_views = corpus + qdf_views
    risky = {k: v for k, v in counts.items() if v}
    if risky:
        res["details"].append(["Palavras-chave", ", ".join(f"/{k} x{v}" for k, v in risky.items())])

    # ---- conteúdo ativo
    flagged = []
    fail = False
    js = counts["JavaScript"] + counts["JS"]
    auto = counts["OpenAction"] + counts["AA"]
    if js:
        hits = sorted({name for name, p in SUSPECT_JS for c in scan_views if p.search(c)})
        if hits:
            flagged.append(f"JavaScript com padrões de ataque ({', '.join(hits[:3])})")
            fail = True
        else:
            flagged.append(f"JavaScript ({js}x)" + (", executado ao abrir" if auto else ""))
    if counts["Launch"]:
        flagged.append(f"ação /Launch (abre programas) {counts['Launch']}x" + (" executada ao abrir" if auto else ""))
        fail = fail or bool(auto)
    elif auto and not js:
        flagged.append("ação automática ao abrir (/OpenAction ou /AA)")
    if counts["EmbeddedFile"] or pd_names:
        # nomes reais dos anexos, lidos pelo pdfdetach (mais confiável que a busca por texto)
        names = [n.encode("latin1", "replace") for n in pd_names] or re.findall(rb"/(?:UF|F)\s*\(([^)]{1,120})\)", data)
        counts["EmbeddedFile"] = max(counts["EmbeddedFile"], len(pd_names))
        bad = [n for n in names if BAD_NAMES.search(n)]
        if bad:
            flagged.append("arquivo executável embutido: " + ", ".join(sorted({b.decode('latin1')[:40] for b in bad})[:3]))
            fail = True
        else:
            flagged.append(f"arquivo(s) embutido(s) ({counts['EmbeddedFile']})")
    for k, label in (("RichMedia", "mídia interativa (RichMedia)"), ("XFA", "formulário XFA (superfície de ataque comum)"),
                     ("SubmitForm", "envio de formulário para a internet"), ("GoToR", "salto para outro arquivo (GoToR)"),
                     ("GoToE", "salto para arquivo embutido (GoToE)"), ("ImportData", "importação de dados"),
                     ("JBIG2Decode", "imagem JBIG2 (já usada em exploits de leitores desatualizados)"),
                     ("Sound", "som embutido"), ("Movie", "vídeo embutido")):
        if counts[k]:
            flagged.append(label)
    if counts["Encrypt"]:
        flagged.append("PDF criptografado: o conteúdo não pôde ser inspecionado")
    if obf:
        flagged.append(f"{obf} nomes disfarçados com #xx (ofuscação)")
        fail = fail or bool(js or counts["Launch"])
    if sinfo["multi_filter"] > 2:
        flagged.append(f"{sinfo['multi_filter']} fluxos com vários filtros em cadeia (ofuscação)")
    if sinfo["skipped"]:
        n = sinfo["skipped"]
        flagged.append(f"{n} fluxo{'s' if n != 1 else ''} de dados não pôde{'ram' if n != 1 else ''} ser aberto{'s' if n != 1 else ''} "
                       "(corrompido ou grande demais: possível bomba de descompressão)")
    if counts["ObjStm"] and (js or counts["Launch"]):
        flagged.append("o conteúdo ativo estava dentro de object streams (escondido)")
    uris = []
    for c in scan_views:
        uris += re.findall(rb"/URI\s*\(([^)]{1,300})\)", c)
    uris = list(dict.fromkeys(uris))  # a versão normalizada repete os mesmos links
    seen, suspicious = [], []
    for u in uris:
        url = u.decode("latin1").strip()
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host and host not in seen:
            seen.append(host)
            if re.fullmatch(r"[\d.]+", host) or "xn--" in host or host in SHORTENERS:
                suspicious.append(host)
    res["uris"] = seen[:15]
    if uris:
        res["details"].append(["Links externos", f"{len(uris)} para {len(seen)} domínios: " + ", ".join(seen[:8])])
    if suspicious:
        flagged.append("links para endereços suspeitos: " + ", ".join(suspicious[:3]))
    for lvl in flagged:
        res["audit"].append(("FAIL" if fail else "WARN", lvl))
    if fail:  # só o primeiro item carrega a gravidade; evita contar o mesmo problema várias vezes
        res["audit"] = [("FAIL", "; ".join(f for _, f in res["audit"]))]
    elif res["audit"]:
        res["audit"] = [("WARN", "; ".join(f for _, f in res["audit"]))]

    # ---- executáveis escondidos dentro de fluxos descompactados
    for c in streams + qdf_views:
        if c[:2] == b"MZ" or DOS_STUB in c:
            res["embedded"].append("executável do Windows dentro de um fluxo do PDF")
            break
    for c in streams:
        if c[:4] == b"PK\x03\x04":
            res["embedded"].append("arquivo ZIP/Office dentro de um fluxo do PDF")
            break
        if c[:4] == b"Rar!" or c[:2] == b"7z":
            res["embedded"].append("arquivo compactado (RAR/7z) dentro de um fluxo do PDF")
            break

    # ---- ferramentas do sistema (se existirem)
    if shutil.which("qpdf"):
        try:
            r = run(["qpdf", "--check", path], 120)
            out = (r.stdout + r.stderr).strip()
            # códigos do qpdf: 0 = ok, 2 = erros, 3 = só avisos (o arquivo abre, mas foge do padrão, comum em PDFs reais)
            if r.returncode == 2 and "password" in out.lower():
                res["details"].append(["qpdf", "o PDF exige senha: não foi possível checar a estrutura"])
            elif r.returncode == 2:
                lines = [l.strip() for l in out.splitlines() if l.strip() and not l.lower().startswith(("checking", "pdf version"))]
                res["structure"].append("qpdf: " + (lines[0] if lines else "erro de estrutura")[:140])
            elif r.returncode == 3:
                res["details"].append(["qpdf", "avisos de estrutura (o arquivo abre, mas foge do padrão)"])
        except Exception:  # noqa: BLE001
            pass
    if shutil.which("pdfinfo"):
        try:
            r = run(["pdfinfo", "-isodates", path], 60)
            info = dict(l.split(":", 1) for l in r.stdout.splitlines() if ":" in l)
            info = {k.strip(): v.strip() for k, v in info.items()}
            pages = info.get("Pages", "")
            bits = [f"{pages} páginas" if pages else "", f"produtor {info['Producer']}" if info.get("Producer") else "",
                    f"criado em {info['CreationDate'][:10]}" if info.get("CreationDate") else ""]
            if r.returncode != 0 or not pages.isdigit() or int(pages) == 0:
                res["quality"] = ("WARN", "o leitor não conseguiu abrir o PDF: " + (r.stderr.strip().splitlines() or ["sem páginas"])[0][:100])
            else:
                res["quality"] = ("INFO", ", ".join(b for b in bits if b) + (f", título '{info['Title'][:60]}'" if info.get("Title") else ""))
                for k, label in (("Title", "Título"), ("Author", "Autor"), ("Creator", "Criado com"), ("Producer", "Produtor"),
                                 ("CreationDate", "Criado em"), ("Pages", "Páginas"), ("Encrypted", "Criptografado"), ("Page size", "Tamanho da página")):
                    if info.get(k):
                        res["details"].append([label, info[k][:120]])
        except Exception as e:  # noqa: BLE001
            res["quality"] = ("WARN", f"pdfinfo falhou: {type(e).__name__}")
    return res
