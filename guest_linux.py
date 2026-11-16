"""Roda DENTRO do container/VM descartável. Baixa a URL e analisa o arquivo.

Não importa nada de fora da biblioteca padrão. Escreve /out/report.json.
"""
import hashlib
import http.client
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # o modo -I não inclui a pasta do script
import guest_audio  # noqa: E402
import guest_pdf  # noqa: E402

IN_DIR = os.environ.get("IN_DIR", "/in")
OUT_DIR = os.environ.get("OUT_DIR", "/out")
WORK_DIR = os.environ.get("WORK_DIR", "/work")
MAX_BYTES = int(os.environ.get("MAX_BYTES", 3 * 1024**3))

IDLE_TIMEOUT = float(os.environ.get("IDLE_TIMEOUT", 60))  # segundos sem receber nada antes de tentar de novo
ATTEMPTS = int(os.environ.get("MAX_ATTEMPTS", 8))

checks = []
facts = {}
dl = {}


def flush():
    """Publica o progresso parcial (a interface mostra cada teste assim que ele termina)."""
    try:
        os.makedirs(OUT_DIR, exist_ok=True)
        tmp = os.path.join(OUT_DIR, "progress.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"checks": checks, "facts": facts, "download": dl}, f)
        os.replace(tmp, os.path.join(OUT_DIR, "progress.json"))
    except OSError:
        pass


def add(cid, name, status, detail):
    checks.append({"id": cid, "name": name, "status": status, "detail": detail})
    flush()


HTTP_HINT = {401: "exige login", 403: "link expirado ou bloqueado", 404: "arquivo removido", 410: "arquivo removido"}
RETRY_HTTP = {408, 425, 429, 500, 502, 503, 504}
_last_flush = [0.0]


def progress(pos, total, attempt, t0, p0, note="", force=False):
    """Estado do download para a interface (no máximo 1 gravação por segundo)."""
    now = time.time()
    if not force and now - _last_flush[0] < 1:
        return
    _last_flush[0] = now
    dl.update(done=pos, total=total, attempt=attempt, max_attempts=ATTEMPTS, note=note,
              speed=int((pos - p0) / max(now - t0, 0.001)))
    flush()


def download(url, dest):
    """Baixa com novas tentativas e retomada (Range). Termina assim que o tamanho anunciado é atingido,
    sem esperar o servidor fechar a conexão (servidores que travam em 100%)."""
    hs = hash_set()
    pos, total_len, attempt, err = 0, None, 0, None
    with open(dest, "wb") as f:
        while True:
            attempt += 1
            headers = {"User-Agent": "Mozilla/5.0"}
            if pos:
                headers["Range"] = f"bytes={pos}-"
            t0, p0 = time.time(), pos
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=IDLE_TIMEOUT) as r:
                    status = getattr(r, "status", 200)
                    if pos and status != 206:  # o servidor ignorou o Range: recomeça do zero
                        pos, p0 = 0, 0
                        f.seek(0)
                        f.truncate()
                        hs = hash_set()
                    if status == 206:
                        tail = r.headers.get("Content-Range", "").rsplit("/", 1)[-1]
                        total_len = int(tail) if tail.isdigit() else total_len
                    else:
                        cl = r.headers.get("Content-Length", "")
                        total_len = int(cl) if cl.isdigit() else None
                    if attempt == 1:
                        facts["final_url_host"] = urllib.parse.urlparse(r.geturl()).hostname
                        facts["content_type"] = r.headers.get("Content-Type", "")
                        facts["server"] = r.headers.get("Server", "")
                        facts["last_modified"] = r.headers.get("Last-Modified", "")
                    if total_len and total_len > MAX_BYTES:
                        raise RuntimeError(f"arquivo de {total_len / 1e9:.1f} GB acima do limite de {MAX_BYTES / 1e9:.0f} GB")
                    progress(pos, total_len, attempt, t0, p0, force=True)
                    while total_len is None or pos < total_len:
                        chunk = r.read(1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        for h in hs.values():
                            h.update(chunk)
                        pos += len(chunk)
                        if pos > MAX_BYTES:
                            raise RuntimeError(f"limite de {MAX_BYTES / 1e9:.0f} GB excedido")
                        progress(pos, total_len, attempt, t0, p0)
                if total_len is None or pos >= total_len:
                    break
                raise ConnectionError(f"o servidor encerrou a conexão em {pos} de {total_len} bytes")
            except urllib.error.HTTPError as e:
                if e.code == 416 and pos:  # já tínhamos o arquivo inteiro
                    break
                if e.code not in RETRY_HTTP:
                    raise RuntimeError(f"o servidor respondeu HTTP {e.code} ({HTTP_HINT.get(e.code, 'erro do servidor')})")
                err = e
            except RuntimeError:
                raise
            except (OSError, http.client.HTTPException) as e:  # TimeoutError, URLError, IncompleteRead...
                err = e
            where = f"{pos} de {total_len if total_len else '?'} bytes" + (f" ({pos * 100 // total_len}%)" if total_len else "")
            if attempt >= ATTEMPTS:
                raise RuntimeError(f"falhou após {attempt} tentativas e parou em {where}: {type(err).__name__}: {err}")
            wait = min(30, 3 * attempt)
            progress(pos, total_len, attempt, t0, p0, force=True,
                     note=f"conexão caiu ({type(err).__name__}); tentativa {attempt + 1} de {ATTEMPTS} em {wait} s, retomando de {where}")
            time.sleep(wait)
    facts["download_attempts"] = attempt
    progress(pos, total_len, attempt, t0, p0, force=True)
    return pos, finish_hashes(hs)


def hash_set():
    return {"sha256": hashlib.sha256(), "sha1": hashlib.sha1(), "md5": hashlib.md5()}


def finish_hashes(hs):
    for k in ("md5", "sha1"):
        facts[k] = hs[k].hexdigest()
    return hs["sha256"].hexdigest()


def parse_boxes(f, size):
    pos, boxes = 0, []
    while pos < size:
        f.seek(pos)
        head = f.read(8)
        if len(head) < 8:
            return boxes, "cabeçalho de caixa truncado"
        sz, typ = struct.unpack(">I4s", head)
        if sz == 1:
            sz = struct.unpack(">Q", f.read(8))[0]
        elif sz == 0:
            sz = size - pos
        name = typ.decode("latin1")
        if sz < 8 or pos + sz > size:
            return boxes, f"caixa '{name}' com tamanho inválido"
        boxes.append((name, pos, sz))
        pos += sz
    return boxes, None


def children(buf, start, end):
    pos = start
    while pos + 8 <= end:
        sz, typ = struct.unpack(">I4s", buf[pos:pos + 8])
        hdr = 8
        if sz == 1:
            sz = struct.unpack(">Q", buf[pos + 8:pos + 16])[0]
            hdr = 16
        if sz < hdr or pos + sz > end:
            return
        yield typ.decode("latin1"), pos + hdr, pos + sz
        pos += sz


def metadata(f, moov):
    _, pos, sz = moov
    if sz > 64 * 1024 * 1024:
        return None
    f.seek(pos)
    buf = f.read(sz)
    dur = w = h = 0
    for t, s, e in children(buf, 8, len(buf)):
        if t == "mvhd":
            ver = buf[s]
            if ver == 1:
                ts, d = struct.unpack(">IQ", buf[s + 20:s + 32])
            else:
                ts, d = struct.unpack(">II", buf[s + 12:s + 20])
            dur = d / ts if ts else 0
        elif t == "trak":
            for t2, s2, e2 in children(buf, s, e):
                if t2 == "tkhd":
                    off = s2 + (88 if buf[s2] == 1 else 76)
                    tw, th = struct.unpack(">II", buf[off:off + 8])
                    w, h = max(w, tw >> 16), max(h, th >> 16)
    return dur, w, h


KNOWN_TOP = {"ftyp", "moov", "mdat", "free", "skip", "wide", "pdin", "moof", "mfra", "sidx", "ssix", "styp", "meta", "uuid", "prft"}
CONTAINERS = {"moov", "trak", "mdia", "minf", "stbl", "edts", "dinf", "mvex", "moof", "traf"}
ENTRY_SIZE = {"stts": 8, "stsc": 12, "stco": 4, "co64": 8, "stss": 4, "ctts": 8}


def audit_moov(buf, start, end, path, file_size, issues, depth=0):
    """Confere se as caixas internas se encaixam e se as tabelas de amostras cabem na caixa e apontam para dentro do arquivo."""
    if depth > 12:
        issues.append(f"{path}: aninhamento excessivo")
        return
    pos = start
    while pos + 8 <= end and len(issues) < 6:
        sz, typ = struct.unpack(">I4s", buf[pos:pos + 8])
        hdr = 8
        if sz == 1:
            sz, hdr = struct.unpack(">Q", buf[pos + 8:pos + 16])[0], 16
        elif sz == 0:
            sz = end - pos
        t = typ.decode("latin1")
        if sz < hdr or pos + sz > end:
            issues.append(f"{path}/{t}: tamanho inválido")
            return
        p, box_end = pos + hdr, pos + sz
        if t in CONTAINERS:
            audit_moov(buf, p, box_end, f"{path}/{t}", file_size, issues, depth + 1)
        elif t in ENTRY_SIZE or t == "stsz":
            if box_end - p < 8:
                issues.append(f"{path}/{t}: caixa curta demais")
            elif t == "stsz":
                sample_size, count = struct.unpack(">II", buf[p + 4:p + 12])
                if sample_size == 0 and 12 + count * 4 > box_end - p:
                    issues.append(f"{path}/{t}: {count} entradas não cabem na caixa")
            else:
                count = struct.unpack(">I", buf[p + 4:p + 8])[0]
                if 8 + count * ENTRY_SIZE[t] > box_end - p:
                    issues.append(f"{path}/{t}: {count} entradas não cabem na caixa (possível exploit de parser)")
                elif t in ("stco", "co64") and 0 < count <= 2_000_000:
                    fmt = ">%d%s" % (count, "I" if t == "stco" else "Q")
                    top = max(struct.unpack(fmt, buf[p + 8:p + 8 + count * ENTRY_SIZE[t]]))
                    if top > file_size:
                        issues.append(f"{path}/{t}: aponta para o byte {top}, além do fim do arquivo")
        pos = box_end


def audit(f, boxes, size):
    issues = []
    for name, pos, sz in boxes:
        if name not in KNOWN_TOP:
            issues.append(f"caixa de topo desconhecida '{name}' ({sz} bytes)")
        elif name in ("free", "skip", "wide") and sz > 1_048_576:
            issues.append(f"'{name}' de {sz / 1e6:.1f} MB (espaço livre grande pode esconder dados)")
        elif name == "uuid" and sz > 65536:
            issues.append(f"'uuid' de {sz / 1e6:.1f} MB")
    moov = next((b for b in boxes if b[0] == "moov"), None)
    if moov and moov[2] <= 64 * 1024 * 1024:
        f.seek(moov[1])
        buf = f.read(moov[2])
        try:
            audit_moov(buf, 8, len(buf), "moov", size, issues)
        except struct.error as e:
            issues.append(f"moov truncado ({e})")
    elif moov:
        issues.append("moov maior que 64 MB não foi auditado")
    if issues:
        add("audit", "Caixas e tabelas MP4 sem anomalias", "WARN", "; ".join(issues[:4]) + (f" (+{len(issues) - 4})" if len(issues) > 4 else ""))
    else:
        add("audit", "Caixas e tabelas MP4 sem anomalias", "PASS", "só caixas conhecidas; tabelas de amostras cabem nas caixas e apontam para dentro do arquivo")


def scan_for(path, patterns):
    keep = max(len(p) for p in patterns) - 1
    tail = b""
    with open(path, "rb") as f:
        while True:
            chunk = f.read(4 * 1024 * 1024)
            if not chunk:
                return None
            data = tail + chunk
            for p in patterns:
                if p in data:
                    return p
            tail = data[-keep:]


EXT_FAMILY = {"mp4": {".mp4", ".m4v", ".mov", ".m4a", ".3gp", ".3g2"}, "mp3": {".mp3"}, "aac": {".aac"}, "wav": {".wav"},
              "flac": {".flac"}, "ogg": {".ogg", ".oga"}, "pdf": {".pdf"}}
DEFAULT_EXT = {"mp4": ".mp4", "mp3": ".mp3", "aac": ".aac", "wav": ".wav", "flac": ".flac", "ogg": ".ogg", "pdf": ".pdf"}
KIND_LABEL = {"mp4": "vídeo ou áudio MP4/MOV", "mp3": "áudio MP3", "aac": "áudio AAC (ADTS)", "wav": "áudio WAV",
              "flac": "áudio FLAC", "ogg": "áudio OGG", "pdf": "documento PDF"}
AUDIO_KINDS = {"mp3", "aac", "wav", "flac", "ogg"}


def detect_kind(f, head):
    """Descobre o tipo pelo CONTEÚDO (não pela extensão). Retorna (tipo, None) ou (None, motivo da recusa)."""
    sigs = {b"MZ": "executável Windows (PE)", b"\x7fELF": "executável Linux (ELF)", b"PK\x03\x04": "ZIP ou documento Office (ainda não suportado)",
            b"Rar!": "RAR (ainda não suportado)", b"7z\xbc\xaf": "7-Zip (ainda não suportado)", b"#!": "script",
            b"\x89PNG": "imagem PNG (ainda não suportado)", b"\xff\xd8\xff": "imagem JPEG (ainda não suportado)", b"GIF8": "imagem GIF (ainda não suportado)"}
    bad = next((v for k, v in sigs.items() if head.startswith(k)), None)
    if head.lstrip().lower().startswith((b"<!doctype", b"<html", b"<?xml", b"{")):
        bad = "página ou texto (provável página de erro ou captcha, não o arquivo)"
    if bad:
        return None, f"o arquivo é {bad}"
    if head[4:8] == b"ftyp":
        return "mp4", None
    if head[:4] == b"fLaC":
        return "flac", None
    if head[:4] == b"OggS":
        return "ogg", None
    if head[:4] == b"RIFF":
        return ("wav", None) if head[8:12] == b"WAVE" else (None, "arquivo RIFF que não é WAV (AVI ainda não é suportado)")
    if b"%PDF-" in head[:1024]:
        return "pdf", None
    if head[:3] == b"ID3":
        f.seek(10 + guest_audio.syncsafe(head[6:10]))
        nxt = f.read(2)
        return ("aac", None) if len(nxt) == 2 and nxt[0] == 0xFF and (nxt[1] & 0xF6) == 0xF0 else ("mp3", None)
    if len(head) > 1 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0:
        return ("aac", None) if (head[1] & 0xF6) == 0xF0 else ("mp3", None)
    return None, "formato não reconhecido ou ainda não suportado"


def read_expected_ext():
    try:
        return open(os.path.join(IN_DIR, "ext.txt"), encoding="utf-8").read().strip().lower()
    except OSError:
        return ""


def size_check(kind, size):
    """Tamanho plausível para o tipo. Arquivos minúsculos são típicos de isca de malware."""
    mb = size / 1e6
    small = {"mp4": 5e6, "mp3": 2e4, "aac": 2e4, "wav": 2e4, "flac": 2e4, "ogg": 2e4, "pdf": 500}[kind]
    if size < small:
        note = {"mp4": "vídeos completos costumam ter centenas de MB", "pdf": "um documento real costuma ter mais que isso"}.get(
            kind, "áudios reais costumam ser maiores")
        add("size", "Tamanho plausível para o tipo", "WARN", f"só {mb:.1f} MB ({note})" if size >= 1e5 else f"só {size} bytes ({note})")
    else:
        add("size", "Tamanho plausível para o tipo", "PASS", f"{mb:.0f} MB" if size >= 1e6 else f"{size / 1e3:.0f} KB")


def analyze_mp4(f, head, size):
    boxes, err = parse_boxes(f, size)
    names = [b[0] for b in boxes]
    facts["boxes"] = [[b[0], b[2]] for b in boxes[:300]]  # inventário para o relatório
    if err:
        add("structure", "Estrutura MP4 consistente", "WARN", err + " (dados extras/corrompidos?)")
    elif any(not n.isprintable() or n.strip() != n or not n for n in names):
        add("structure", "Estrutura MP4 consistente", "WARN", "caixa com tipo inválido no fim (dados extras anexados?)")
    elif "moov" not in names or "mdat" not in names:
        add("structure", "Estrutura MP4 consistente", "WARN", f"faltam caixas moov/mdat: {names}")
    else:
        add("structure", "Estrutura MP4 consistente", "PASS", "caixas do topo cobrem o arquivo inteiro: " + ",".join(names))
    audit(f, boxes, size)  # caixas desconhecidas, espaço livre grande, tabelas impossíveis
    moov = next((b for b in boxes if b[0] == "moov"), None)
    try:
        meta = metadata(f, moov) if moov else None
    except Exception as e:  # noqa: BLE001
        meta = None
        facts["meta_error"] = str(e)
    if not meta or not meta[0]:
        add("quality", "Metadados de qualidade", "WARN", "não foi possível ler duração/resolução")
    else:
        dur, w, h = meta
        mbps = size * 8 / dur / 1e6
        hh, mm, ss = int(dur // 3600), int(dur % 3600 // 60), int(dur % 60)
        facts.update(duration_s=round(dur), width=w, height=h, mbps=round(mbps, 2))
        shown = f"{hh}h{mm:02d}m" if hh else (f"{mm}m{ss:02d}s" if mm else f"{ss}s")
        detail = f"{shown}, {w}x{h}, ~{mbps:.1f} Mbps" if w else f"{shown}, só áudio, ~{mbps * 1000:.0f} kbps"
        weak = bool(h) and (h < 480 or (h >= 720 and mbps < 1.0))
        add("quality", "Metadados de qualidade", "WARN" if weak else "INFO", detail + (" (resolução/bitrate baixos)" if weak else ""))


def analyze_audio_file(f, size, kind):
    st, au, det = guest_audio.ANALYZERS[kind](f, size)
    add("structure", "Estrutura do áudio consistente", "WARN" if st else "PASS",
        "; ".join(st[:3]) + (f" (+{len(st) - 3})" if len(st) > 3 else "") if st else f"quadros e blocos {kind.upper()} coerentes com o tamanho do arquivo")
    add("audit", "Tags e blocos sem anomalias", "WARN" if au else "PASS",
        "; ".join(au[:3]) + (f" (+{len(au) - 3})" if len(au) > 3 else "") if au else "tags e blocos de metadados com tamanhos coerentes")
    facts["details"] = det


def analyze_pdf_file(path, size):
    r = guest_pdf.analyze_pdf(path, size)
    st = r["structure"]
    add("structure", "Estrutura do PDF consistente", "WARN" if st else "PASS",
        "; ".join(st[:3]) if st else "cabeçalho, startxref e %%EOF coerentes; objetos fechados")
    lv = [l for l, _ in r["audit"]]
    status = "FAIL" if "FAIL" in lv else "WARN" if lv else "PASS"
    add("audit", "Conteúdo ativo e suspeito no PDF", status,
        "; ".join(t for _, t in r["audit"]) if r["audit"] else "sem JavaScript, ações automáticas, arquivos embutidos ou outros sinais de conteúdo ativo")
    q = r["quality"]
    if q:
        add("quality", "Metadados do PDF", q[0], q[1])
    else:
        add("quality", "Metadados do PDF", "SKIP", "pdfinfo não existe neste ambiente")
    facts["details"] = r["details"]
    facts["pdf_uris"] = r["uris"]
    return r["embedded"]


def analyze(path, size):
    """Detecta o tipo pelo conteúdo e roda o analisador certo. Retorna {"kind", "expect", "pdf"}."""
    info = {"kind": None, "expect": None}
    extra = []
    with open(path, "rb") as f:
        head = f.read(1024)
        facts["header_hex"] = head[:64].hex()
        kind, why = detect_kind(f, head)
        if kind is None:
            add("header", "Tipo de arquivo confere com o conteúdo", "FAIL", why)
            return info
        info["kind"] = kind
        facts["kind"], facts["ext"] = kind, DEFAULT_EXT[kind]
        if kind == "mp4" and head[8:12] == b"M4A ":
            facts["ext"] = ".m4a"
        elif kind == "mp4" and head[8:12] == b"qt  ":
            facts["ext"] = ".mov"
        expected = read_expected_ext()
        if expected and expected not in EXT_FAMILY[kind]:
            add("header", "Tipo de arquivo confere com o conteúdo", "FAIL",
                f"a extensão '{expected}' diz uma coisa, mas o conteúdo é {KIND_LABEL[kind]} (arquivo disfarçado?)")
            return info
        add("header", "Tipo de arquivo confere com o conteúdo", "PASS", f"conteúdo identificado: {KIND_LABEL[kind]}")
        size_check(kind, size)
        if kind == "mp4":
            info["expect"] = "audio" if head[8:12] == b"M4A " else "video"
            analyze_mp4(f, head, size)
        elif kind in AUDIO_KINDS:
            info["expect"] = "audio"
            analyze_audio_file(f, size, kind)
    if kind == "pdf":
        extra = analyze_pdf_file(path, size)
    # executável escondido dentro do arquivo
    hit = scan_for(path, [b"This program cannot be run in DOS mode", b"Rar!\x1a\x07", b"7z\xbc\xaf\x27\x1c"])
    if hit or extra:
        why = ([f"padrão encontrado: {hit[:24]!r}"] if hit else []) + extra
        add("embedded", "Sem executável ou arquivo embutido", "FAIL", "; ".join(why))
    else:
        add("embedded", "Sem executável ou arquivo embutido", "PASS", "nenhum stub de executável ou arquivo compactado")
    return info


def run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)


def media_checks(path, info):
    """ffprobe lê a estrutura; ffmpeg decodifica uma amostra de 30 s. Tudo dentro do sandbox."""
    kind, expect = info["kind"], info["expect"]
    label = "vídeo" if expect == "video" else "áudio"
    if not shutil.which("ffprobe"):
        add("ffprobe", f"ffprobe: estrutura do {label}", "SKIP", "ffprobe não existe neste ambiente")
        return
    try:
        r = run(["ffprobe", "-v", "error", "-show_entries",
                 "format=format_name,duration,bit_rate:format_tags:stream=codec_type,codec_name,width,height,sample_rate,channels",
                 "-of", "json", path], 180)
        data = json.loads(r.stdout or "{}")
    except Exception as e:  # noqa: BLE001
        add("ffprobe", f"ffprobe: estrutura do {label}", "WARN", f"falhou: {type(e).__name__}: {e}")
        return
    fmt = data.get("format", {}).get("format_name", "")
    streams = data.get("streams", [])
    facts["format_name"] = fmt
    facts["streams"] = streams[:16]
    video = [s for s in streams if s.get("codec_type") == "video"]
    audio = [s for s in streams if s.get("codec_type") == "audio"]
    err = (r.stderr or "").strip().splitlines()
    desc = (f"formato {fmt or '?'}; vídeo " + (", ".join(f"{s.get('codec_name')} {s.get('width')}x{s.get('height')}" for s in video) or "nenhum")
            + "; áudio " + (", ".join(str(s.get("codec_name")) for s in audio) or "nenhum"))
    need = video if expect == "video" else audio
    if not fmt or not need:
        add("ffprobe", f"ffprobe: estrutura do {label}", "FAIL", f"não é um arquivo de {label} válido: " + desc)
    elif err:
        add("ffprobe", f"ffprobe: estrutura do {label}", "WARN", f"{desc}; erro: {err[0][:120]}")
    else:
        add("ffprobe", f"ffprobe: estrutura do {label}", "PASS", desc)
    if kind in AUDIO_KINDS and audio:  # qualidade do áudio a partir do ffprobe (o MP4 já tem a sua)
        fm, a = data.get("format", {}), audio[0]
        tags = {k.lower(): v for k, v in (fm.get("tags") or {}).items()}
        try:
            dur = float(fm.get("duration", 0))
        except ValueError:
            dur = 0
        br, sr, ch, codec = int(fm.get("bit_rate") or 0), int(a.get("sample_rate") or 0), a.get("channels"), a.get("codec_name", "?")
        facts.update(duration_s=round(dur), audio_codec=codec, bitrate_bps=br, sample_rate=sr)
        mm, ss = int(dur // 60), int(dur % 60)
        bits = [f"{mm}m{ss:02d}s", codec, f"{br // 1000} kbps" if br else "", f"{sr} Hz" if sr else "",
                {1: "mono", 2: "estéreo"}.get(ch, f"{ch} canais" if ch else "")]
        lossy = codec in ("mp3", "aac", "vorbis", "opus")
        weak = (lossy and 0 < br < 96000) or (0 < sr < 32000)
        title = tags.get("title") or tags.get("artist")
        det = ", ".join(b for b in bits if b) + (f" ({tags.get('artist', '')} {tags.get('title', '')})".replace("  ", " ") if title else "")
        add("quality", "Metadados de qualidade", "WARN" if weak else "INFO", det + (" (bitrate ou taxa de amostragem baixos)" if weak else ""))
    full = expect == "audio"  # áudio decodifica muito mais rápido que o tempo real: dá para decodificar tudo
    name = "Decodificação completa" if full else "Decodificação de amostra (30 s)"
    try:
        cmd = ["ffmpeg", "-v", "error", "-nostdin"] + ([] if full else ["-t", "30"]) + ["-i", path, "-f", "null", "-"]
        r = run(cmd, 1200 if full else 240)
        err = (r.stderr or "").strip().splitlines()
        if r.returncode != 0 or err:
            add("decode", name, "WARN", (err[0] if err else f"código {r.returncode}")[:140])
        else:
            add("decode", name, "PASS", "o arquivo inteiro decodifica sem erros" if full else "os primeiros 30 s decodificam sem erros")
    except Exception as e:  # noqa: BLE001
        add("decode", name, "WARN", f"{type(e).__name__}: {e}")


def tool_lines(r, prefixes):
    """Linhas da saída (stdout+stderr) de uma ferramenta que começam com algum dos prefixos (sem diferenciar maiúsculas)."""
    out = []
    for l in ((r.stdout or "") + "\n" + (r.stderr or "")).splitlines():
        s = l.strip()
        if s.lower().startswith(prefixes):
            out.append(re.sub(r"^\S+:\s*", "", s, count=1) if s.lower().startswith(("warning", "error", "info")) else s)
    return out


def validators(path, kind):
    """Validadores independentes do tipo (flac -t, mp3val, ogginfo, mutool) mais o exiftool. Qualquer problema vira aviso."""
    ran, problems, notes = [], [], []

    def go(name, cmd, timeout, prefixes_bad):
        if not shutil.which(cmd[0]):
            return
        try:
            r = run(cmd, timeout)
        except Exception as e:  # noqa: BLE001
            problems.append(f"{name} não concluiu ({type(e).__name__})")
            return
        ran.append(name)
        bad = tool_lines(r, prefixes_bad)
        if bad:
            problems.append(f"{name}: {bad[0][:130]}" + (f" (+{len(bad) - 1})" if len(bad) > 1 else ""))
        elif r.returncode != 0 and name in ("flac -t", "mutool"):
            first = next((l.strip() for l in ((r.stderr or "") + "\n" + (r.stdout or "")).splitlines() if l.strip()), "")
            problems.append(f"{name}: " + (first[:130] or f"terminou com erro (código {r.returncode})"))

    if kind == "flac":
        go("flac -t", ["flac", "-t", "-s", path], 900, ("error", "warning"))
        # (o flac -t também confere o MD5 gravado no arquivo contra o áudio decodificado)
    elif kind == "mp3":
        go("mp3val", ["mp3val", path], 300, ("warning", "error"))
    elif kind == "ogg":
        go("ogginfo", ["ogginfo", path], 300, ("warning", "error"))
    elif kind == "pdf":
        go("mutool", ["mutool", "info", path], 120, ("error",))
    if shutil.which("exiftool"):  # leitor independente de metadados: avisos de estrutura de qualquer tipo
        try:
            r = run(["exiftool", "-a", "-s3", "-Warning", "-Error", path], 120)
            ran.append("exiftool")
            for l in r.stdout.splitlines():
                if l.strip():
                    (notes if l.strip().startswith("[minor]") else problems).append("exiftool: " + l.strip()[:130])
        except Exception:  # noqa: BLE001
            pass
    if notes:
        facts.setdefault("details", []).append(["exiftool (avisos menores)", "; ".join(n[10:] for n in notes[:3])[:200]])
    if not ran:
        add("validators", "Validadores independentes", "SKIP", "nenhum validador existe neste ambiente")
    elif problems:
        add("validators", "Validadores independentes", "WARN", "; ".join(problems[:3]) + f" (rodaram: {', '.join(ran)})")
    else:
        add("validators", "Validadores independentes", "PASS", f"sem avisos ({', '.join(ran)})")


TOOLS_DIR = "/opt/tools"  # pdfid.py e pdf-parser.py (Didier Stevens), baixados na construção da imagem
MIME_OK = {"mp4": ("mp4", "quicktime", "m4a", "m4v", "3gpp", "iso"), "mp3": ("mpeg", "mp3"), "aac": ("aac",),
           "wav": ("wav", "wave"), "flac": ("flac",), "ogg": ("ogg", "vorbis"), "pdf": ("pdf",)}
PDF_RISKY = {"/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA", "/JBIG2Decode", "/Encrypt"}
# assinaturas do binwalk que importam num PDF, áudio ou vídeo: executáveis, arquivos compactados, atalhos e documentos Office embutidos
BINWALK_RISK = re.compile(r"ELF,|PE32|Mach-O|executable|Zip archive|RAR archive|7-zip archive|Java class|shell script|"
                          r"MS Windows shortcut|Microsoft Office|OLE|Windows Installer|\bMSI\b", re.I)


def second_opinions(path, kind, size):
    """Ferramentas conhecidas olham o mesmo arquivo como segunda opinião. Divergência ou achado vira aviso; o resto vai para os detalhes."""
    probs, ran = [], []
    det = facts.setdefault("details", [])
    have = shutil.which

    def parse_counts(text, pattern):
        out = {}
        for l in text.splitlines():
            m = re.match(pattern, l)
            if m:
                out[m.group(1)] = int(m.group(2))
        return out

    if have("file"):  # tipo segundo o libmagic
        try:
            mime = run(["file", "-b", "--mime-type", path], 60).stdout.strip()
            desc = run(["file", "-b", path], 60).stdout.strip()
            ran.append("file")
            det.append(["Tipo segundo o libmagic (file)", f"{mime}: {desc[:110]}"])
            if not any(k in mime for k in MIME_OK.get(kind, ())):
                probs.append(f"file (libmagic) classifica como '{mime}', diferente do tipo identificado ({kind})")
        except Exception:  # noqa: BLE001
            pass
    if have("binwalk"):  # arquivos embutidos por assinatura
        if size > 300 * 1024 * 1024:
            det.append(["binwalk", "pulado: arquivo acima de 300 MB"])
        else:
            try:
                r = run(["binwalk", path], 600)
                ran.append("binwalk")
                hits, other = [], 0
                for l in r.stdout.splitlines():
                    m = re.match(r"^(\d+)\s+0x[0-9A-Fa-f]+\s+(.*)$", l)
                    if not m or int(m.group(1)) == 0:  # o deslocamento 0 é o próprio tipo do arquivo
                        continue
                    desc = m.group(2)[:70]
                    if BINWALK_RISK.search(desc):
                        hits.append(desc)
                    else:
                        other += 1
                if hits:
                    probs.append("binwalk achou dentro do arquivo: " + "; ".join(dict.fromkeys(hits))[:140])
                if other:
                    det.append(["binwalk (outras assinaturas)", f"{other} de baixo risco ignoradas (textos, caminhos, direitos autorais)"])
            except Exception:  # noqa: BLE001
                pass
    if kind == "pdf":
        third = {}
        for name, cmd, pat in (("pdfid", ["python3", "-I", f"{TOOLS_DIR}/pdfid.py", path], r"^\s+(/[A-Za-z0-9]+)\s+(\d+)"),
                               ("pdf-parser", ["python3", "-I", f"{TOOLS_DIR}/pdf-parser.py", "-O", "--stats", path], r"^\s+(/[A-Za-z0-9]+)\s+(\d+):")):
            if not os.path.exists(cmd[2]):
                continue
            try:
                r = run(cmd, 180)
                ran.append(name)
                for k, v in parse_counts(r.stdout, pat).items():
                    if k in PDF_RISKY and v:
                        third[k] = max(third.get(k, 0), v)
            except Exception:  # noqa: BLE001
                pass
        if third:
            det.append(["pdfid / pdf-parser (palavras-chave)", ", ".join(f"{k} x{v}" for k, v in third.items())])
            audit_c = next((c for c in reversed(checks) if c["id"] == "audit"), None)
            if audit_c and audit_c["status"] == "PASS":  # a análise própria disse "limpo", e eles discordam
                probs.append("pdfid/pdf-parser veem " + ", ".join(sorted(third)) + ", que a análise própria não apontou")
        if have("pdfresurrect"):
            try:
                r = run(["pdfresurrect", path, "-q"], 60)
                out = (r.stdout + r.stderr).strip()
                m = re.search(r":\s*(\d+)\s*$", out)
                if m:
                    ran.append("pdfresurrect")
                    n = int(m.group(1))
                    det.append(["Revisões do documento (pdfresurrect)", f"{n}" + (f": {n - 1} versão(ões) anterior(es) ainda dentro do arquivo" if n > 1 else "")])
                else:  # o programa não lê PDFs com menos de ~1 KB
                    det.append(["pdfresurrect", "não conseguiu ler o PDF (arquivo pequeno demais)"])
            except Exception:  # noqa: BLE001
                pass
    if kind == "wav" and have("steghide"):  # só encontra dados escondidos com senha vazia
        try:
            r = subprocess.run(["steghide", "info", path, "-p", ""], input="y\n", capture_output=True, text=True, errors="replace", timeout=90)
            ran.append("steghide")
            m = re.search(r'embedded file "([^"]+)"', r.stdout + r.stderr)
            if m:
                probs.append(f"steghide encontrou dados escondidos no WAV (arquivo '{m.group(1)}') com senha vazia")
            else:
                det.append(["steghide (WAV)", "nenhum dado escondido com senha vazia (não prova que não há: só testa essa senha)"])
        except Exception:  # noqa: BLE001
            pass
    if have("ssdeep") and size <= 1024 * 1024 * 1024:  # hash por similaridade, só informativo
        try:
            lines = run(["ssdeep", "-b", path], 300).stdout.splitlines()
            m = re.match(r"^(\d+:[^,]+),", lines[1]) if len(lines) > 1 else None
            if m:
                ran.append("ssdeep")
                det.append(["ssdeep (hash por similaridade)", m.group(1)])
        except Exception:  # noqa: BLE001
            pass
    if not ran:
        add("second", "Ferramentas de segunda opinião", "SKIP", "nenhuma das ferramentas existe neste ambiente")
    elif probs:
        add("second", "Ferramentas de segunda opinião", "WARN", "; ".join(probs[:3]) + f" (rodaram: {', '.join(ran)})")
    else:
        add("second", "Ferramentas de segunda opinião", "PASS", f"sem divergências nem achados ({', '.join(ran)})")


YARA_RULES, YARA_MANIFEST = "/opt/yara/rules.yarc", "/opt/yara/manifest.txt"


def yara_scan(path, ext):
    """Regras YARA da comunidade (embutidas na imagem), focadas em PDF, documentos e executáveis escondidos."""
    if not shutil.which("yara") or not os.path.exists(YARA_RULES):
        add("yara", "Regras YARA da comunidade", "SKIP", "sem regras YARA nesta imagem (o download das regras falhou na construção)")
        return
    base = os.path.basename(path)
    cmd = ["yara", "-C", "-f", "-m", "-d", f"filename={base}", "-d", f"filepath={path}", "-d", f"extension={ext}",
           "-d", "filetype=", "-d", "owner=", YARA_RULES, path]
    try:
        r = run(cmd, 1500)
    except Exception as e:  # noqa: BLE001
        add("yara", "Regras YARA da comunidade", "WARN", f"o scan não concluiu: {type(e).__name__}")
        return
    try:
        n_files = sum(1 for l in open(YARA_MANIFEST, encoding="utf-8") if l.rstrip().endswith(" OK"))
        built = open(YARA_MANIFEST, encoding="utf-8").readline().strip().replace("gerado em ", "")
    except OSError:
        n_files, built = 0, "?"
    facts["yara_rules"] = f"{n_files} arquivos de regra, {built}"
    if r.returncode != 0:
        add("yara", "Regras YARA da comunidade", "WARN", "erro no scan: " + ((r.stderr or r.stdout).strip().splitlines() or ["?"])[0][:140])
        return
    hits, ignored = [], 0
    for l in r.stdout.splitlines():
        l = l.rstrip()
        if not l.endswith(path):
            continue
        head = l[: -len(path)].rstrip()
        name = head.split(" ", 1)[0]
        meta = head[len(name):].strip().lstrip("[").rstrip("]")
        kv = {k.lower(): v.strip('"') for k, v in re.findall(r'(\w+)\s*=\s*("[^"]*"|[^,\]]+)', meta)}
        score = int(kv.get("score") or kv.get("impact") or 0)
        # convenção do signature-base: hide=true é regra auxiliar de baixo sinal; pontuação < 50 é só informativa
        if kv.get("hide", "").lower() == "true" or (("score" in kv or "impact" in kv) and score < 50):
            ignored += 1
            continue
        hits.append((name, score, kv.get("description") or kv.get("desc") or ""))
    facts["yara_ignored"] = ignored
    if not hits:
        add("yara", "Regras YARA da comunidade", "PASS",
            f"nenhuma regra relevante casou ({n_files} arquivos de regra, de {built})" + (f"; {ignored} regra(s) de baixo sinal ignorada(s)" if ignored else ""))
        return
    status = "FAIL" if any(s >= 80 for _, s, _ in hits) else "WARN"
    txt = "; ".join(f"{n}" + (f" ({d[:70]})" if d else "") for n, _, d in hits[:4]) + (f" (+{len(hits) - 4})" if len(hits) > 4 else "")
    add("yara", "Regras YARA da comunidade", status, "regras que casaram: " + txt)


def av_scan(path):
    """ClamAV com limites de tamanho elevados (o padrão do clamscan ignora arquivos > 100 MB)."""
    if not shutil.which("clamscan"):
        add("av", "Antivírus (ClamAV)", "SKIP", "ClamAV não existe neste ambiente; use o hash no VirusTotal")
        return
    upd = "assinaturas da imagem"
    try:
        r = run(["freshclam", "--datadir=/var/lib/clamav", "--log=/tmp/freshclam.log", "--quiet"], 300)
        upd = "assinaturas atualizadas agora" if r.returncode == 0 else f"falha ao atualizar (código {r.returncode}); usando a base da imagem"
    except Exception as e:  # noqa: BLE001
        upd = f"falha ao atualizar ({type(e).__name__}); usando a base da imagem"
    try:
        ver = run(["clamscan", "--version"], 60).stdout.strip()
        # alert-encrypted-doc: avisa de documentos criptografados (o antivírus não vê dentro);
        # alert-exceeds-max: avisa se algum limite impediu o scan completo, em vez de passar em silêncio
        r = run(["clamscan", "--no-summary", "--max-filesize=4000M", "--max-scansize=4000M",
                 "--alert-encrypted-doc=yes", "--alert-exceeds-max=yes", path], 3000)
    except Exception as e:  # noqa: BLE001
        add("av", "Antivírus (ClamAV)", "WARN", f"scan não concluiu: {type(e).__name__}: {e}")
        return
    facts["clamav"] = ver
    if r.returncode == 0:
        add("av", "Antivírus (ClamAV)", "PASS", f"nenhuma ameaça ({ver}; {upd})")
    elif r.returncode == 1:
        sigs = [m.group(1).strip() for m in (re.match(r"^.*: (.+) FOUND$", l) for l in r.stdout.splitlines()) if m]
        enc = [s for s in sigs if s.startswith("Heuristics.Encrypted")]
        lim = [s for s in sigs if s.startswith("Heuristics.Limits")]
        real = [s for s in sigs if s not in enc and s not in lim]
        if real:  # assinatura de malware de verdade
            add("av", "Antivírus (ClamAV)", "FAIL", "ameaça detectada: " + ", ".join(real[:3]))
        else:  # só alertas de limitação: não é malware, mas o antivírus não conseguiu olhar tudo
            why = []
            if enc:
                why.append("documento criptografado: o antivírus não consegue ver o conteúdo")
            if lim:
                why.append("o arquivo passou de um limite do ClamAV (tamanho ou profundidade): parte dele NÃO foi escaneada")
            add("av", "Antivírus (ClamAV)", "WARN", "; ".join(why) + f" ({ver})")
    else:
        add("av", "Antivírus (ClamAV)", "WARN", "erro no scan: " + ((r.stderr or r.stdout).strip()[:160] or f"código {r.returncode}"))


def main():
    local_marker = os.path.join(IN_DIR, "local.txt")
    local = os.path.exists(local_marker)  # modo arquivo local: nada é baixado
    path = os.path.join(os.environ.get("DATA_DIR", "/data"), "target.bin") if local else os.path.join(WORK_DIR, "target.bin")
    facts["python"] = sys.version.split()[0]
    report = {"environment": "contêiner Docker (safecheck-guest: ClamAV, ffmpeg, poppler, qpdf)", "checks": checks, "facts": facts}
    try:
        t0 = time.time()
        if local:
            hs = hash_set()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    for h in hs.values():
                        h.update(chunk)
            size, sha = os.path.getsize(path), finish_hashes(hs)
            facts.update(size=size, sha256=sha, local_name=open(local_marker, encoding="utf-8").read().strip())
            add("download", "Arquivo recebido (somente leitura)", "PASS", f"{size} bytes, sha256 {sha[:16]}…")
        else:
            url = open(os.path.join(IN_DIR, "url.txt")).read().strip()
            size, sha = download(url, path)
            facts.update(size=size, sha256=sha, download_s=round(time.time() - t0, 1))
            add("download", "Download dentro do sandbox", "PASS", f"{size} bytes, sha256 {sha[:16]}…")
            if os.environ.get("MODE") == "download":  # só baixar (alternativa quando o PC não consegue): sem análise
                return
        info = analyze(path, size)
        if info.get("expect"):
            media_checks(path, info)
        elif info.get("kind") == "pdf":
            for cid, nm in (("ffprobe", "ffprobe: estrutura do áudio ou vídeo"), ("decode", "Decodificação da mídia")):
                add(cid, nm, "SKIP", "não se aplica a PDF")
        if info.get("kind"):
            validators(path, info["kind"])
            second_opinions(path, info["kind"], size)
        yara_scan(path, facts.get("ext", ""))
        av_scan(path)
    except Exception as e:  # noqa: BLE001
        add("download", "Obter o arquivo no sandbox", "FAIL", f"{type(e).__name__}: {e}")
    finally:
        os.makedirs(OUT_DIR, exist_ok=True)
        tmp = os.path.join(OUT_DIR, "report.tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(report, f)
        os.replace(tmp, os.path.join(OUT_DIR, "report.json"))


if __name__ == "__main__":
    sys.exit(main())
