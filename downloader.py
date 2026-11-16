"""Baixa o arquivo já analisado para o seu PC e confere se é idêntico ao que foi analisado no sandbox.

Só HTTPS (inclusive nos redirecionamentos), novas tentativas com retomada (Range), grava em .part e só
renomeia depois de conferir o SHA-256. Se o hash não bater, apaga o arquivo.
"""
import hashlib
import http.client
import os
import shutil
import time
import urllib.error
import urllib.request

IDLE_TIMEOUT = 60
ATTEMPTS = 8
RETRY_HTTP = {408, 425, 429, 500, 502, 503, 504}
HTTP_HINT = {401: "exige login", 403: "link expirado ou bloqueado", 404: "arquivo removido", 410: "arquivo removido"}


class Cancelled(Exception):
    pass


class HashMismatch(Exception):
    pass


class Stalled(RuntimeError):
    """O servidor (ou algo no caminho de rede) corta a conexão sem deixar o download avançar."""


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"redirecionamento para destino não-HTTPS bloqueado: {newurl[:60]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_space(folder, needed):
    free = shutil.disk_usage(folder).free
    margin = 200 * 1024 * 1024
    if free < needed + margin:
        raise OSError(f"pouco espaço em disco: faltam {(needed + margin - free) / 1e9:.1f} GB livres em {folder}")


def download_file(url, dest, expected_sha256, expected_size=None, on_progress=None, cancel=None):
    """Retorna o caminho final. Levanta Cancelled, HashMismatch, OSError ou RuntimeError.
    Em qualquer falha, o arquivo parcial (.part) é apagado."""
    try:
        return _download(url, dest, expected_sha256, expected_size, on_progress, cancel)
    except BaseException:
        cleanup_part(dest)
        raise


def _download(url, dest, expected_sha256, expected_size, on_progress, cancel):
    folder = os.path.dirname(os.path.abspath(dest))
    if expected_size:
        check_space(folder, expected_size)
    part = dest + ".part"
    opener = urllib.request.build_opener(_HttpsOnly)
    h, pos, total, attempt, err = hashlib.sha256(), 0, expected_size, 0, None
    best, no_progress, diag = 0, 0, {}  # maior posição já alcançada; tentativas seguidas sem byte novo; última resposta
    notify = on_progress or (lambda d: None)
    with open(part, "wb") as f:
        while True:
            attempt += 1
            headers = {"User-Agent": "Mozilla/5.0"}
            if pos:
                headers["Range"] = f"bytes={pos}-"
            t0, p0, last, best_before = time.time(), pos, 0.0, best
            try:
                with opener.open(urllib.request.Request(url, headers=headers), timeout=IDLE_TIMEOUT) as r:
                    status = getattr(r, "status", 200)
                    diag = {"status": status, "server": r.headers.get("Server", ""),
                            "range": ("aceito (206)" if status == 206 else "ignorado (200)") if pos else ""}
                    if pos and status != 206:  # servidor ignorou o Range: recomeça
                        pos, p0 = 0, 0
                        f.seek(0)
                        f.truncate()
                        h = hashlib.sha256()
                    if status == 206:
                        tail = r.headers.get("Content-Range", "").rsplit("/", 1)[-1]
                        total = int(tail) if tail.isdigit() else total
                    else:
                        cl = r.headers.get("Content-Length", "")
                        total = int(cl) if cl.isdigit() else total
                    while total is None or pos < total:
                        if cancel is not None and cancel.is_set():
                            raise Cancelled()
                        chunk = r.read(1024 * 1024)
                        if not chunk:
                            break
                        f.write(chunk)
                        h.update(chunk)
                        pos += len(chunk)
                        now = time.time()
                        if now - last >= 0.5:
                            last = now
                            notify({"done": pos, "total": total, "attempt": attempt, "max_attempts": ATTEMPTS,
                                    "speed": int((pos - p0) / max(now - t0, 0.001)), "note": ""})
                if total is None or pos >= total:
                    break
                raise ConnectionError(f"o servidor encerrou a conexão em {pos} de {total} bytes")
            except urllib.error.HTTPError as e:
                e.close()  # libera a conexão do erro (o código e a mensagem continuam disponíveis)
                if e.code == 416 and pos:
                    break
                if e.code not in RETRY_HTTP:
                    raise RuntimeError(f"o servidor respondeu HTTP {e.code} ({HTTP_HINT.get(e.code, 'erro do servidor')})")
                err = e
            except (Cancelled, RuntimeError):
                raise
            except (OSError, http.client.HTTPException) as e:
                err = e
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            best = max(best, pos)
            no_progress = no_progress + 1 if best == best_before else 0
            where = f"{pos} de {total or '?'} bytes"
            if no_progress >= 3:  # 3 tentativas seguidas sem nenhum byte novo: insistir não adianta
                info = ", ".join(x for x in (f"HTTP {diag.get('status')}" if diag else "", f"Range {diag['range']}" if diag.get("range") else "",
                                             f"servidor {diag['server']}" if diag.get("server") else "") if x)
                raise Stalled(f"o servidor encerrou a conexão sem enviar bytes novos {no_progress} vezes seguidas, "
                              f"parando em {best} de {total or '?'} bytes" + (f" (última resposta: {info})" if info else ""))
            if attempt >= ATTEMPTS:
                raise RuntimeError(f"falhou após {attempt} tentativas e parou em {where}: {type(err).__name__}: {err}")
            wait = min(30, 3 * attempt)
            notify({"done": pos, "total": total, "attempt": attempt, "max_attempts": ATTEMPTS, "speed": 0,
                    "note": f"conexão caiu ({type(err).__name__}); tentativa {attempt + 1} de {ATTEMPTS} em {wait} s, retomando de {where}"})
            for _ in range(wait):  # espera interrompível
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
                time.sleep(1)
    got = h.hexdigest()
    if got != expected_sha256:
        os.remove(part)
        raise HashMismatch(got)
    os.replace(part, dest)
    return dest


def cleanup_part(dest):
    try:
        os.remove(dest + ".part")
    except OSError:
        pass
