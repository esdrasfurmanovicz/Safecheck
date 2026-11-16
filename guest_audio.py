"""Análise estrutural de áudio (MP3, AAC/ADTS, WAV, FLAC, OGG). Roda dentro do sandbox.

Cada função devolve (problemas_de_estrutura, problemas_de_tags_e_blocos, detalhes). Nada aqui executa ou decodifica o áudio.
"""
import struct

MB = 1024 * 1024


def syncsafe(b):
    return (b[0] << 21) | (b[1] << 14) | (b[2] << 7) | b[3]


# ---------------------------------------------------------------- MP3
MPEG1_BR = {1: [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
            2: [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
            3: [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]}
MPEG2_BR = {1: [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
            2: [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]}
SAMPLE_RATE = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}


def mp3_frame(h):
    """Decodifica o cabeçalho de 4 bytes. Retorna (tamanho_do_quadro, bitrate, taxa) ou None se inválido."""
    if len(h) < 4 or h[0] != 0xFF or (h[1] & 0xE0) != 0xE0:
        return None
    ver, layer_bits = (h[1] >> 3) & 3, (h[1] >> 1) & 3
    if ver == 1 or layer_bits == 0:
        return None
    layer = 4 - layer_bits  # 1, 2 ou 3
    br_i, sr_i, pad = (h[2] >> 4) & 15, (h[2] >> 2) & 3, (h[2] >> 1) & 1
    if br_i in (0, 15) or sr_i == 3:
        return None
    table = MPEG1_BR[layer] if ver == 3 else MPEG2_BR[1 if layer == 1 else 2]
    br, sr = table[br_i] * 1000, SAMPLE_RATE[ver][sr_i]
    if layer == 1:
        length = (12 * br // sr + pad) * 4
    elif layer == 3 and ver != 3:
        length = 72 * br // sr + pad
    else:
        length = 144 * br // sr + pad
    return length, br, sr


def _next_sync(f, pos, end, limit=65536):
    """Procura o próximo quadro válido (confirmado por um segundo quadro em seguida)."""
    f.seek(pos)
    chunk = f.read(min(limit, end - pos))
    i = 0
    while True:
        i = chunk.find(b"\xff", i)
        if i < 0:
            return None
        fr = mp3_frame(chunk[i:i + 4])
        if fr:
            f.seek(pos + i + fr[0])
            if mp3_frame(f.read(4)):
                return pos + i
        i += 1


def parse_id3v2(f, size):
    """Retorna (fim_da_tag, problemas, detalhes) ou None se não houver ID3v2."""
    f.seek(0)
    h = f.read(10)
    if h[:3] != b"ID3" or len(h) < 10:
        return None
    ver, flags, tsize = h[3], h[5], syncsafe(h[6:10])
    end = 10 + tsize + (10 if flags & 0x10 else 0)
    issues, details, text = [], [], {}
    if end > size:
        issues.append(f"a tag ID3 ({end} bytes) é maior que o arquivo")
        return min(end, size), issues, details
    body = f.read(min(tsize, 32 * MB))
    pos = 0
    if ver in (3, 4):
        if flags & 0x40 and len(body) >= 4:  # cabeçalho estendido
            pos = (syncsafe(body[:4]) if ver == 4 else struct.unpack(">I", body[:4])[0] + 4)
        while pos + 10 <= len(body):
            fid = body[pos:pos + 4]
            if fid[0] == 0:
                break  # início do preenchimento
            fsz = syncsafe(body[pos + 4:pos + 8]) if ver == 4 else struct.unpack(">I", body[pos + 4:pos + 8])[0]
            if not all(48 <= c <= 57 or 65 <= c <= 90 for c in fid):
                issues.append("quadro de tag com identificador inválido")
                break
            if fsz == 0 or pos + 10 + fsz > len(body):
                issues.append(f"quadro {fid.decode('latin1')} com tamanho impossível ({fsz} bytes)")
                break
            data = body[pos + 10:pos + 10 + fsz]
            name = fid.decode("latin1")
            if name in ("TIT2", "TPE1", "TALB", "TDRC", "TYER", "TCON") and fsz < 2000:
                text[name] = data[1:].decode("utf-16" if data[:1] in (b"\x01", b"\x02") else "latin1", "replace").strip("\x00 ")
            if name == "APIC":
                mime_end = data.find(b"\x00", 1)
                mime = data[1:mime_end] if mime_end > 0 else b""
                img = data[mime_end + 1:mime_end + 300] if mime_end > 0 else b""
                if not mime.startswith(b"image/") or not (b"\xff\xd8\xff" in img or b"\x89PNG" in img or b"GIF8" in img or b"RIFF" in img):
                    issues.append("capa do álbum (APIC) que não é uma imagem válida")
            if name == "GEOB" and fsz > 64 * 1024:
                issues.append(f"objeto embutido (GEOB) de {fsz / 1e6:.1f} MB na tag")
            elif name in ("PRIV", "COMM", "USLT") and fsz > MB:
                issues.append(f"quadro {name} de {fsz / 1e6:.1f} MB")
            elif fsz > 20 * MB:
                issues.append(f"quadro {name} de {fsz / 1e6:.1f} MB")
            pos += 10 + fsz
    padding = len(body) - pos
    if padding > MB:
        issues.append(f"preenchimento de {padding / 1e6:.1f} MB na tag (espaço que pode esconder dados)")
    for k, label in (("TIT2", "Título"), ("TPE1", "Artista"), ("TALB", "Álbum"), ("TDRC", "Ano"), ("TYER", "Ano"), ("TCON", "Gênero")):
        if text.get(k):
            details.append([label, text[k][:120]])
    return end, issues, details


def analyze_mp3(f, size):
    st, au, det = [], [], []
    start = 0
    tag = parse_id3v2(f, size)
    if tag:
        start, au, det = tag[0], list(tag[1]), list(tag[2])
        det.insert(0, ["Tag ID3v2", f"{start} bytes"])
    end = size
    f.seek(max(0, size - 128))
    tail = f.read(128)
    if len(tail) == 128 and tail[:3] == b"TAG":
        end = size - 128
        det.append(["Tag ID3v1", "presente"])
    pos, frames, resyncs, junk, bitrates, sr = start, 0, 0, 0, set(), 0
    while pos + 4 <= end:
        f.seek(pos)
        fr = mp3_frame(f.read(4))
        if fr and pos + fr[0] <= end:
            frames += 1
            bitrates.add(fr[1])
            sr = fr[2]
            pos += fr[0]
            continue
        nxt = _next_sync(f, pos, end)
        if nxt is None:
            break
        junk += nxt - pos
        resyncs += 1
        pos = nxt
    rest = end - pos
    f.seek(pos)
    leftover = f.read(min(rest, 64 * 1024)) if rest > 0 else b""
    if frames == 0:
        st.append("nenhum quadro MP3 válido foi encontrado")
    else:
        det.append(["Quadros MP3 válidos", f"{frames}" + (" (taxa variável)" if len(bitrates) > 1 else "")])
    if resyncs > 3 or junk > 4096:
        st.append(f"{junk} bytes fora de quadros em {resyncs} trechos (dados estranhos no meio do áudio)")
    if rest > 2048 and leftover.strip(b"\x00") and not leftover.startswith((b"APETAGEX", b"LYRICS")):
        st.append(f"{rest} bytes depois do último quadro de áudio (dados anexados?)")
    return st, au, det


# ---------------------------------------------------------------- AAC (ADTS)
def analyze_aac(f, size):
    st, au, det = [], [], []
    start = 0
    tag = parse_id3v2(f, size)
    if tag:
        start, au, det = tag[0], list(tag[1]), list(tag[2])
    pos, frames, bad = start, 0, 0
    while pos + 7 <= size:
        f.seek(pos)
        h = f.read(7)
        if h[0] == 0xFF and (h[1] & 0xF6) == 0xF0:
            fl = ((h[3] & 3) << 11) | (h[4] << 3) | (h[5] >> 5)
            if fl >= 7 and pos + fl <= size:
                frames += 1
                pos += fl
                continue
        bad += 1
        break
    if frames == 0:
        st.append("nenhum quadro AAC válido foi encontrado")
    else:
        det.append(["Quadros AAC (ADTS)", str(frames)])
    if size - pos > 2048:
        st.append(f"{size - pos} bytes depois do último quadro AAC (dados anexados ou corrompidos)")
    return st, au, det


# ---------------------------------------------------------------- WAV
def analyze_wav(f, size):
    st, au, det = [], [], []
    f.seek(0)
    h = f.read(12)
    declared = struct.unpack("<I", h[4:8])[0] + 8
    if declared + 1 < size:
        st.append(f"{size - declared} bytes depois do fim declarado no cabeçalho RIFF (dados anexados?)")
    elif declared > size + 1:
        st.append(f"o cabeçalho diz {declared} bytes, mas o arquivo tem {size} (truncado)")
    pos, names, has_fmt, has_data = 12, [], False, False
    while pos + 8 <= min(size, declared if declared <= size else size):
        f.seek(pos)
        cid, csz = struct.unpack("<4sI", f.read(8))
        name = cid.decode("latin1")
        if pos + 8 + csz > size:
            st.append(f"bloco '{name}' passa do fim do arquivo")
            break
        names.append(name)
        has_fmt |= name == "fmt "
        has_data |= name == "data"
        if name not in ("fmt ", "data", "fact", "LIST", "bext", "cue ", "smpl", "inst", "id3 ", "ID3 ", "JUNK", "PAD ", "iXML", "_PMX") \
                and csz > 64 * 1024:
            au.append(f"bloco desconhecido '{name}' de {csz / 1e6:.1f} MB")
        elif name in ("LIST", "JUNK", "PAD ", "id3 ", "ID3 ", "bext", "iXML") and csz > MB:
            au.append(f"bloco '{name}' de {csz / 1e6:.1f} MB (espaço que pode esconder dados)")
        pos += 8 + csz + (csz & 1)
    if not has_fmt or not has_data:
        st.append("faltam os blocos 'fmt ' e 'data' de um WAV válido")
    det.append(["Blocos WAV", ", ".join(dict.fromkeys(names))[:200]])
    return st, au, det


# ---------------------------------------------------------------- FLAC
FLAC_TYPES = {0: "STREAMINFO", 1: "PADDING", 2: "APPLICATION", 3: "SEEKTABLE", 4: "VORBIS_COMMENT", 5: "CUESHEET", 6: "PICTURE"}


def analyze_flac(f, size):
    st, au, det = [], [], []
    pos, first, last, names = 4, True, False, []
    while not last:
        f.seek(pos)
        h = f.read(4)
        if len(h) < 4:
            st.append("a cadeia de metadados termina antes do fim do bloco")
            break
        last, typ, ln = bool(h[0] >> 7), h[0] & 0x7F, int.from_bytes(h[1:4], "big")
        if typ == 127 or typ > 6:
            st.append(f"bloco de metadados com tipo inválido ({typ})")
            break
        if first and typ != 0:
            st.append("o primeiro bloco não é STREAMINFO")
        if typ == 0 and ln != 34:
            st.append(f"STREAMINFO com {ln} bytes em vez de 34")
        if pos + 4 + ln > size:
            st.append(f"bloco {FLAC_TYPES[typ]} passa do fim do arquivo")
            break
        names.append(FLAC_TYPES[typ])
        if typ == 1 and ln > MB:
            au.append(f"preenchimento (PADDING) de {ln / 1e6:.1f} MB (espaço que pode esconder dados)")
        elif typ == 2 and ln > 64 * 1024:
            au.append(f"bloco APPLICATION de {ln / 1e6:.1f} MB")
        elif typ == 6 and ln > 20 * MB:
            au.append(f"imagem (PICTURE) de {ln / 1e6:.1f} MB")
        first = False
        pos += 4 + ln
    else:
        f.seek(pos)
        sync = f.read(2)
        if len(sync) < 2 or sync[0] != 0xFF or (sync[1] & 0xFC) != 0xF8:
            st.append("não há quadro de áudio FLAC depois dos metadados")
    det.append(["Blocos de metadados", ", ".join(names)])
    return st, au, det


# ---------------------------------------------------------------- OGG
def analyze_ogg(f, size):
    st, au, det = [], [], []
    pos, pages, eos = 0, 0, False
    while pos + 27 <= size and pages < 3_000_000:
        f.seek(pos)
        h = f.read(27)
        if h[:4] != b"OggS":
            break
        segs = f.read(h[26])
        plen = 27 + h[26] + sum(segs)
        if pos + plen > size:
            st.append("a última página OGG está truncada")
            break
        eos = bool(h[5] & 4)
        pages += 1
        pos += plen
    if pages == 0:
        st.append("nenhuma página OGG válida")
    rest = size - pos
    if rest > 2048:
        st.append(f"{rest} bytes depois da última página OGG (dados anexados ou corrompidos)")
    if pages and not eos:
        det.append(["Fim do fluxo", "a última página não marca o fim (arquivo cortado?)"])
    det.append(["Páginas OGG", str(pages)])
    return st, au, det


ANALYZERS = {"mp3": analyze_mp3, "aac": analyze_aac, "wav": analyze_wav, "flac": analyze_flac, "ogg": analyze_ogg}
