"""Configurações do safecheck: guarda a chave do VirusTotal sem deixá-la em texto puro quando possível.

Windows: criptografada com DPAPI (só a sua conta de usuário no seu PC consegue ler).
Outros sistemas: arquivo com permissão 600 (sem criptografia; é o melhor que a biblioteca padrão oferece).
A variável de ambiente VT_API_KEY, se existir, tem prioridade.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"  # arquivo de teste de antivírus, público


def config_path():
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "safecheck", "config.json")
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "safecheck", "config.json")


# ---------------------------------------------------------------- DPAPI (Windows)
def _blob(data):
    import ctypes
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    buf = ctypes.create_string_buffer(data, len(data))
    return DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf, DataBlob


def _dpapi(data, encrypt):
    import ctypes
    inb, keep, DataBlob = _blob(data)
    out = DataBlob()
    fn = ctypes.windll.crypt32.CryptProtectData if encrypt else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI falhou")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))
        del keep


# ---------------------------------------------------------------- leitura e gravação
def _load():
    try:
        with open(config_path(), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save(cfg):
    p = config_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    if sys.platform != "win32":
        os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def saved_vt_key():
    entry = _load().get("vt_key")
    if not entry:
        return ""
    try:
        if entry.get("scheme") == "dpapi":
            return _dpapi(base64.b64decode(entry["data"]), False).decode("utf-8")
        return entry.get("data", "")
    except (OSError, ValueError, KeyError):
        return ""


def get_vt_key():
    """Chave usada nas consultas: a variável de ambiente, se existir; senão a salva."""
    return (os.environ.get("VT_API_KEY") or "").strip() or saved_vt_key()


def vt_key_source():
    if (os.environ.get("VT_API_KEY") or "").strip():
        return "env"
    return "saved" if saved_vt_key() else None


def set_vt_key(key):
    key = key.strip()
    cfg = _load()
    if sys.platform == "win32":
        try:
            cfg["vt_key"] = {"scheme": "dpapi", "data": base64.b64encode(_dpapi(key.encode("utf-8"), True)).decode()}
        except OSError:
            cfg["vt_key"] = {"scheme": "plain", "data": key}
    else:
        cfg["vt_key"] = {"scheme": "plain", "data": key}
    _save(cfg)
    return cfg["vt_key"]["scheme"]


def clear_vt_key():
    cfg = _load()
    cfg.pop("vt_key", None)
    _save(cfg)


def valid_key_format(key):
    key = key.strip()
    return len(key) == 64 and all(c in "0123456789abcdefABCDEF" for c in key)


def test_vt_key(key):
    """Consulta o hash do arquivo de teste EICAR para validar a chave. Retorna (ok, mensagem). Só a chave e um hash público saem do PC."""
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{EICAR_SHA256}", headers={"x-apikey": key.strip()})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return (True, "Chave válida.") if r.status == 200 else (False, f"Resposta inesperada: HTTP {r.status}")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, "O VirusTotal recusou a chave. Confira se copiou inteira."
        if e.code == 429:
            return True, "Chave válida, mas o limite de consultas foi atingido por agora (a conta gratuita tem poucas por minuto e por dia)."
        return False, f"O VirusTotal respondeu HTTP {e.code}."
    except Exception as e:  # noqa: BLE001
        return False, f"Não consegui falar com o VirusTotal ({type(e).__name__}). Confira a internet."
