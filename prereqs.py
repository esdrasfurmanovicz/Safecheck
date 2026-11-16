"""Pendências do programa: descobre o que falta no computador, avisa e, se o usuário aceitar, instala.

Só usa a biblioteca padrão e não importa o tkinter, para poder rodar mesmo quando ele é justamente o que falta.
Cada pendência é um dicionário: id, label, why, cmds (lista de comandos), admin (precisa de administrador),
relogin (só vale depois de sair e entrar na sessão) e manual (sem instalação automática: só orientação).
"""
import getpass
import importlib.util
import os
import platform
import shutil
import subprocess
import sys

SYSTEM = platform.system()


def _run(argv, timeout=20):
    try:
        return subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None


def package_manager():
    """Gerenciador de pacotes do sistema, ou None se não reconhecer nenhum."""
    if SYSTEM == "Windows":
        return "winget" if shutil.which("winget") else None
    if SYSTEM == "Darwin":
        return "brew" if shutil.which("brew") else None
    for pm in ("dnf", "apt-get", "pacman", "zypper"):
        if shutil.which(pm):
            return pm
    return None


def _pkg_cmd(pm, packages):
    return {
        "dnf": ["dnf", "install", "-y"],
        "apt-get": ["apt-get", "install", "-y"],
        "pacman": ["pacman", "-S", "--noconfirm"],
        "zypper": ["zypper", "--non-interactive", "install"],
    }[pm] + packages


def tkinter_missing():
    return importlib.util.find_spec("tkinter") is None


def _tk_item(pm):
    item = {"id": "tkinter", "label": "Tkinter (a janela do programa)",
            "why": "A interface gráfica precisa dele. O modo terminal funciona sem.",
            "cmds": [], "admin": True, "relogin": False, "manual": False}
    pkgs = {"dnf": ["python3-tkinter"], "apt-get": ["python3-tk"], "pacman": ["tk"], "zypper": ["python3-tk"]}
    if SYSTEM == "Darwin":
        item.update(cmds=[["brew", "install", "python-tk"]], admin=False, manual=pm != "brew")
    elif SYSTEM == "Windows" or pm not in pkgs:
        item["manual"] = True  # no Windows o tkinter vem no instalador do Python (marque "tcl/tk")
    else:
        item["cmds"] = [_pkg_cmd(pm, pkgs[pm])]
    return item


def docker_state():
    """'ok', 'missing' (não instalado), 'stopped' (instalado, serviço parado) ou 'permission' (Linux, sem acesso)."""
    docker = shutil.which("docker")
    if not docker:
        return "missing"
    r = _run([docker, "info"], timeout=30)
    if r is None:
        return "stopped"
    if r.returncode == 0:
        return "ok"
    err = ((r.stderr or "") + (r.stdout or "")).lower()
    return "permission" if "permission denied" in err else "stopped"


def windows_sandbox_available():
    if SYSTEM != "Windows":
        return False
    return bool(shutil.which("WindowsSandbox.exe")) or os.path.exists(r"C:\Windows\System32\WindowsSandbox.exe")


def _docker_item(state, pm):
    item = {"id": "docker", "label": "Docker (o sandbox onde o arquivo é analisado)",
            "why": "O arquivo é analisado dentro de um contêiner descartável, nunca no seu sistema.",
            "cmds": [], "admin": True, "relogin": False, "manual": False}
    if state == "missing":
        if SYSTEM == "Windows":
            item.update(cmds=[["winget", "install", "-e", "--id", "Docker.DockerDesktop"]] if pm else [], admin=False,
                        manual=not pm, note="Depois abra o Docker Desktop e deixe-o rodando.")
        elif SYSTEM == "Darwin":
            item.update(cmds=[["brew", "install", "--cask", "docker"]] if pm else [], admin=False, manual=not pm,
                        note="Depois abra o Docker uma vez e deixe-o rodando.")
        elif pm:
            pkg = {"dnf": ["moby-engine"], "apt-get": ["docker.io"], "pacman": ["docker"], "zypper": ["docker"]}[pm]
            item["cmds"] = [_pkg_cmd(pm, pkg), ["systemctl", "enable", "--now", "docker"]] + _group_cmds()
            item["relogin"] = True
        else:
            item["manual"] = True
        return item
    if state == "stopped":
        item["label"] = "Docker instalado, mas parado"
        item["why"] = "O serviço do Docker precisa estar rodando para criar o sandbox."
        if SYSTEM == "Linux":
            item["cmds"] = [["systemctl", "enable", "--now", "docker"]]
        elif SYSTEM == "Darwin":
            item.update(cmds=[["open", "-a", "Docker"]], admin=False)
        else:
            item["manual"] = True
            item["note"] = "Abra o Docker Desktop e espere ele ficar pronto."
        return item
    item["label"] = "Permissão para usar o Docker"
    item["why"] = "Seu usuário não está no grupo 'docker', então o programa não consegue falar com ele."
    item["cmds"] = _group_cmds()
    item["relogin"] = True
    return item


def _group_cmds():
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    return [["usermod", "-aG", "docker", user]]


def find_pending(gui=False):
    """Lista o que falta. Com gui=True, inclui o Tkinter."""
    pm = package_manager()
    pending = []
    if gui and tkinter_missing():
        pending.append(_tk_item(pm))
    if not windows_sandbox_available():  # no Windows o Sandbox do sistema substitui o Docker (só para MP4/MOV)
        state = docker_state()
        if state != "ok":
            pending.append(_docker_item(state, pm))
    return pending


def describe(pending):
    lines = []
    for p in pending:
        lines.append(f"  - {p['label']}: {p['why']}")
        if p.get("note"):
            lines.append(f"      {p['note']}")
    return "\n".join(lines)


def commands_text(item):
    return "; ".join(" ".join(c) for c in item["cmds"])


def _elevate(argv, graphical):
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return argv
    tool = ("pkexec" if graphical and shutil.which("pkexec") else "sudo") if shutil.which("sudo") or shutil.which("pkexec") else None
    return ([tool] + argv) if tool else argv


def install(pending, log=print, graphical=False):
    """Roda os comandos de cada pendência. Devolve (feitas, falhas). O instalador escreve em `log` linha a linha."""
    done, failed = [], []
    for item in pending:
        if item["manual"] or not item["cmds"]:
            failed.append(item)
            continue
        ok = True
        for cmd in item["cmds"]:
            argv = _elevate(cmd, graphical) if item["admin"] and SYSTEM == "Linux" else cmd
            log("$ " + " ".join(argv))
            try:
                proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
                for line in proc.stdout:
                    log(line.rstrip())
                ok = proc.wait() == 0
            except OSError as e:
                log(f"não consegui executar: {e}")
                ok = False
            if not ok:
                break
        (done if ok else failed).append(item)
    return done, failed


def guided_terminal(gui=False, ask=input, out=print):
    """Fluxo do terminal: lista pendências, pergunta, instala, confere de novo. Devolve True se pode seguir."""
    pending = find_pending(gui=gui)
    if not pending:
        return True
    out("Antes de começar, faltam algumas coisas neste computador:\n" + describe(pending) + "\n")
    if not sys.stdin.isatty():
        out("Instale o que falta e rode de novo (este terminal não é interativo, então não posso perguntar).")
        return False
    auto = [p for p in pending if not p["manual"] and p["cmds"]]
    for p in pending:
        if p in auto:
            out(f"Vou rodar: {commands_text(p)}" + ("  (pede sua senha de administrador)" if p["admin"] and SYSTEM == "Linux" else ""))
    if not auto:
        out("Não consigo instalar isso sozinho neste sistema. Instale manualmente e rode de novo.")
        return False
    try:
        answer = ask("Posso instalar agora? [s/N] ").strip().lower()
    except EOFError:
        answer = ""
    if answer not in ("s", "sim", "y", "yes"):
        out("Tudo bem. O programa precisa disso para funcionar, então vou encerrar.")
        return False
    _done, failed = install(auto)
    return _after_install(pending, failed, out, gui)


def _after_install(pending, failed, out, gui):
    if failed:
        out("\nNão consegui resolver: " + ", ".join(p["label"] for p in failed) + ". Instale manualmente e rode de novo.")
        return False
    left = find_pending(gui=gui)
    if left:
        if any(p["relogin"] for p in pending):
            out("\nInstalado. Falta só aplicar a mudança de grupo: saia da sessão e entre de novo (ou reinicie) e abra o programa outra vez.")
        else:
            out("\nO que foi instalado ainda não aparece pronto:\n" + describe(left))
        return False
    out("\nTudo pronto.\n")
    return True


def ensure_tkinter():
    """Chamar antes de importar o tkinter. Se faltar, oferece instalar (no terminal) e reabre o programa; senão, sai."""
    if not tkinter_missing():
        return
    if not guided_terminal(gui=True):
        raise SystemExit(1)
    os.execv(sys.executable, [sys.executable] + sys.argv)
