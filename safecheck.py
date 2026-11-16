#!/usr/bin/env python3
"""safecheck: verifica um link de arquivo MP4 dentro de um sandbox descartável.

Fluxo:
  1. valida o link no seu PC (sem baixar o arquivo);
  2. sobe um ambiente isolado conforme o SO e baixa/analisa o arquivo LÁ;
  3. consulta o hash no VirusTotal (opcional: chave configurada na janela ou em VT_API_KEY);
  4. lista o que foi feito, o que passou e as limitações.

O arquivo baixado nunca é copiado para o seu PC; só o relatório sai do sandbox.
"""
import argparse
import base64
import ipaddress
import glob
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import prereqs
import settings
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from xml.sax.saxutils import escape

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BYTES = 3 * 1024**3
SANDBOX_TIMEOUT = 90 * 60  # inclui download + atualização do ClamAV + scan
IMAGE = "safecheck-guest:5"
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "ow.ly", "rebrand.ly", "shorturl.at"}
LOG = print  # a interface gráfica troca isto para receber o progresso
SYMBOL = {"PASS": "[OK]    ", "FAIL": "[FALHA] ", "WARN": "[AVISO] ", "SKIP": "[PULADO]", "INFO": "[INFO]  "}

LIMITATIONS = [
    "Tipos suportados: MP4/MOV, áudio (MP3, M4A, AAC, WAV, FLAC, OGG) e PDF. Outros tipos ainda não são analisados e executáveis e scripts são recusados de propósito.",
    "PDF: a análise é estática (palavras-chave de risco, fluxos descompactados com limites, qpdf e pdfinfo). O documento não é renderizado, então exploits que dependem de como o leitor interpreta o arquivo podem passar, e PDF criptografado não é inspecionado.",
    "Nenhum veredito 'seguro': nada detectado não significa nada malicioso. Exploits novos em players de vídeo e malware sem assinatura passam.",
    "O servidor pode entregar um arquivo diferente ao sandbox do que entregaria a você (cloaking), e links com captcha/senha não funcionam.",
    "A resolução de páginas do MediaFire usa regex sobre o HTML e pode quebrar se o site mudar.",
    "Windows Sandbox (alternativa só para MP4/MOV, usada quando o Docker não está disponível): o antivírus é o Defender do sandbox, com assinaturas possivelmente defasadas; só roda uma instância por vez e exige Windows Pro/Enterprise com virtualização.",
    "Docker (preferido, por cobrir mais testes): contêiner compartilha o kernel do host, isolamento mais fraco que uma VM. O antivírus é o ClamAV, que detecta bem menos que os 70+ motores do VirusTotal.",
    "ffprobe/ffmpeg só decodificam uma amostra de 30 s: corrupção ou truques no resto do arquivo podem passar.",
    "A pasta de saída é gravável pelo guest: um malware poderia escrever lá. Por isso só se lê o report.json e nada é executado.",
    "Ferramentas de segunda opinião: o pdfid e o pdf-parser são baixados do GitHub do autor na construção da imagem (o SHA-256 fica no manifest da imagem). Binwalk, steghide e ssdeep são heurísticos: podem apontar falsos positivos ou não achar nada, e o steghide só testa a senha vazia. O pdfresurrect não lê PDFs com menos de 1 KB.",
    "As regras YARA são embutidas na construção da imagem e não são atualizadas a cada execução (as assinaturas do ClamAV são). São poucas e focadas em PDF e documentos: ajudam pouco com áudio e vídeo.",
    "Microsoft Defender no seu PC: só no Windows, para arquivos locais e para o arquivo depois de baixado. Ele lê o arquivo, não o executa, mas se o Defender estiver desativado (por outro antivírus, por exemplo) o teste é pulado.",
    "VirusTotal só ajuda se você configurar a chave (botão na janela ou VT_API_KEY) e o hash já for conhecido; hash desconhecido não é prova de limpeza.",
    "Não avalia qualidade subjetiva (som, imagem, legendas, cortes); só duração, resolução, bitrate e metadados técnicos.",
    "Não avalia legalidade: um arquivo sem vírus ainda pode ser cópia não autorizada.",
]


def chk(cid, name, status, detail):
    return {"id": cid, "name": name, "status": status, "detail": detail}


# Plano de testes: a interface lista tudo isto de antemão e vai marcando conforme termina.
PLAN_LINK_HOST = [("scheme", "Link usa HTTPS"), ("host", "Domínio sem sinais óbvios de golpe"),
                  ("dns", "Domínio resolve para IP público")]
PLAN_LINK_PROBE = [("probe", "Servidor responde ao link"), ("clen", "Tamanho anunciado dentro do limite")]
PLAN_LOCAL_HOST = [("ext", "Tipo de arquivo suportado"), ("size_cap", "Tamanho dentro do limite"),
                   ("defender", "Microsoft Defender (no seu PC)")]
PLAN_GUEST_COMMON = [("download", "Obter o arquivo no sandbox"), ("size", "Tamanho plausível para o tipo"),
                     ("header", "Tipo de arquivo confere com o conteúdo"), ("structure", "Estrutura do arquivo consistente"),
                     ("quality", "Metadados de qualidade")]
PLAN_GUEST_END = [("embedded", "Sem executável ou arquivo embutido")]

# Tipos aceitos (a detecção real é pelo conteúdo, dentro do sandbox; a extensão é só a expectativa)
MP4_EXT = {".mp4", ".m4v", ".mov", ".m4a", ".3gp", ".3g2"}
SUPPORTED_EXT = MP4_EXT | {".mp3", ".aac", ".wav", ".flac", ".ogg", ".oga", ".pdf"}
DANGEROUS_EXT = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".scr", ".lnk", ".jar", ".apk",
                 ".dmg", ".com", ".hta", ".pif", ".iso", ".img", ".dll", ".sys", ".reg", ".docm", ".xlsm", ".pptm"}


def ext_status(ext):
    """(status, detalhe) para a extensão informada."""
    if ext in SUPPORTED_EXT:
        return "PASS", f"extensão '{ext}'"
    if ext in DANGEROUS_EXT:
        return "FAIL", (f"'{ext}' é um tipo que executa código: este programa não analisa e abrir pode ser perigoso. "
                        "Confira o hash no VirusTotal e escaneie com o Defender, ou não abra.")
    return "FAIL", f"o tipo '{ext or '(sem extensão)'}' ainda não é suportado (suportados: MP4/MOV, áudio e PDF)"


def url_ext(url):
    """Extensão que o link sugere (ex.: .../Filme.mp4/file). Vazia se não houver."""
    for part in reversed([x for x in urllib.parse.urlparse(url).path.split("/") if x]):
        e = os.path.splitext(urllib.parse.unquote(part))[1].lower()
        if e in SUPPORTED_EXT or e in DANGEROUS_EXT:
            return e
    return ""
PLAN_VT = [("vt", "VirusTotal (hash)")]

DESCR = {
    "scheme": "Exige HTTPS, para que o download não possa ser alterado no caminho.",
    "host": "Rejeita links com usuário/senha na URL, IP no lugar de domínio e domínios com caracteres disfarçados (punycode).",
    "dns": "Confere que o domínio resolve para um endereço público, e não para a sua rede local.",
    "resolve": "Lê a página do MediaFire (só o HTML) para achar o link direto do arquivo e confirma que ele está no próprio MediaFire.",
    "probe": "Pede só os cabeçalhos ao servidor, seguindo redirecionamentos e exigindo HTTPS em cada um. Nada é baixado.",
    "clen": "Compara o tamanho anunciado com o limite do programa (3 GB).",
    "ext": "A extensão precisa ser de um tipo suportado (MP4/MOV, áudio ou PDF). Executáveis e scripts são recusados aqui, antes de chegar ao sandbox.",
    "size_cap": "Confere que o arquivo não está vazio e cabe no limite do programa (3 GB).",
    "download": "Obtém o arquivo dentro do sandbox (baixando, ou lendo o arquivo local montado só para leitura) e calcula o SHA-256.",
    "size": "Compara o tamanho com o esperado para o tipo (um filme costuma ter centenas de MB). Arquivos minúsculos são típicos de isca de malware.",
    "header": "Descobre o tipo pelo conteúdo (primeiros bytes) e compara com a extensão. Executáveis, compactados, scripts e páginas HTML são recusados, e um '.mp3' que na verdade é PDF acusa disfarce.",
    "structure": "Percorre a estrutura inteira: caixas (MP4), quadros e blocos (áudio) ou %%EOF, objetos e startxref (PDF). Tudo deve fechar com o tamanho do arquivo; sobra ou lixo pode esconder dados anexados.",
    "audit": "Procura anomalias internas. MP4: caixas desconhecidas, espaço livre enorme, tabelas com contagens impossíveis. Áudio: tags e blocos com tamanhos impossíveis ou enormes. PDF: JavaScript, ações automáticas, arquivos embutidos, nomes ofuscados e links suspeitos, inclusive dentro de fluxos compactados. Só no Docker.",
    "quality": "Lê os metadados: duração, resolução e bitrate (vídeo), bitrate e taxa de amostragem (áudio) ou páginas, produtor e data (PDF).",
    "embedded": "Procura no arquivo todo (e dentro dos fluxos descompactados do PDF) por executáveis do Windows e arquivos RAR/7z escondidos.",
    "ffprobe": "O ffprobe, dentro do sandbox, confirma o formato e lista os codecs de vídeo e áudio. Não se aplica a PDF.",
    "decode": "O ffmpeg decodifica a mídia dentro do sandbox para ver se os dados são válidos: 30 s de vídeo ou o áudio inteiro (áudio decodifica rápido). Não se aplica a PDF.",
    "validators": "Programas independentes releem o arquivo e conferem a estrutura: flac -t (FLAC, inclusive o MD5 do áudio), mp3val (MP3), ogginfo (OGG), mutool (PDF) e o exiftool (todos). Quando dois leitores discordam, algo está estranho.",
    "second": "Mais ferramentas conhecidas olham o mesmo arquivo como segunda opinião: file (tipo pelo libmagic), binwalk (executáveis, ZIP e outros arquivos embutidos), pdfid e pdf-parser (palavras-chave de risco em PDF, as versões originais da lógica que reimplementamos), pdfresurrect (revisões antigas de PDF), steghide (dados escondidos em WAV, só com senha vazia) e ssdeep (hash por similaridade, só informativo). Se alguma discorda da análise do programa, vira aviso.",
    "yara": "Aplica regras YARA da comunidade (Neo23x0/signature-base e Yara-Rules), escolhidas para PDF, documentos e executáveis escondidos. As regras são embutidas na construção da imagem.",
    "defender": "O Microsoft Defender do seu PC lê o arquivo e procura ameaças conhecidas. Ele não abre nem executa o arquivo. É um segundo motor, além do ClamAV do sandbox. Só no Windows.",
    "av": "Antivírus dentro do sandbox (ClamAV no Docker, Microsoft Defender no Windows Sandbox). No ClamAV, também avisa de documentos criptografados e de arquivos que passaram de um limite e não foram escaneados por inteiro.",
    "vt": "Consulta o hash SHA-256 no VirusTotal (precisa da chave do VirusTotal, configurada no botão da janela ou em VT_API_KEY). Só o hash sai do sandbox.",
    "sandbox": "Execução do sandbox em si.",
    "input": "Confere se o caminho informado aponta para um arquivo que existe.",
}


VT_LIMIT = 650_000_000  # ~650 MB, vale para o site e para a API; confirme na documentação do VirusTotal

# O que o programa cobre. "parcial" = só o que está descrito; o resto continua sem verificação.
COVERAGE = [
    ("Arquivo disfarçado (extensão falsa, executável, ZIP/RAR, página HTML)", "coberto",
     "o tipo é descoberto pelo conteúdo e comparado com a extensão; executáveis, compactados, scripts e páginas HTML são recusados"),
    ("Dados anexados ou escondidos no arquivo", "parcial",
     "caixas (MP4), quadros e blocos (áudio), %%EOF e objetos (PDF), espaço livre grande, busca por executável/RAR embutido e binwalk (ELF, ZIP e outros embutidos); não detecta dados cifrados, e esteganografia só em WAV com senha vazia (steghide)"),
    ("Contêiner ou documento malformado (padrão de exploits de parser)", "parcial",
     "MP4: contagens impossíveis e offsets fora do arquivo; áudio: tags e blocos com tamanhos impossíveis; PDF: qpdf e estrutura (só no Docker); não substitui fuzzing nem assinaturas de CVEs específicos"),
    ("Conteúdo ativo em PDF (JavaScript, ações automáticas, arquivos embutidos)", "parcial",
     "palavras-chave de risco, nomes ofuscados e fluxos descompactados com limites; o PDF não é renderizado e PDF criptografado não é inspecionado"),
    ("Malware já conhecido (assinaturas)", "parcial",
     "ClamAV no sandbox, Microsoft Defender no seu PC (arquivo local e após baixar) e regras YARA da comunidade, com assinaturas atualizadas; são 2 motores e algumas regras, contra os 70+ do VirusTotal"),
    ("Mídia corrompida ou codec estranho", "parcial", "ffprobe completo e 30 s de decodificação com ffmpeg"),
    ("Falhas em codecs e no seu player ou leitor de PDF", "não coberto",
     "mantenha o player e o leitor atualizados; este programa nunca reproduz a mídia inteira nem abre o PDF em um leitor"),
    ("Comportamento ao executar ou abrir", "não coberto", "o arquivo nunca é executado nem aberto; não há análise dinâmica"),
    ("Reputação do link/domínio", "parcial", "só sinais básicos (HTTPS, IP, punycode, redirecionamentos); sem base de reputação"),
]


def guidance(checks, facts, is_link):
    """Próximos passos conforme o resultado e o caso (tamanho, hash conhecido, link ou arquivo local)."""
    by = {c["id"]: c for c in checks}
    st = [c["status"] for c in checks]
    size, sha = facts.get("size"), facts.get("sha256")
    kind = facts.get("kind")  # mp4, mp3, wav, flac, ogg, aac ou pdf (descoberto pelo conteúdo)
    out = []
    if "FAIL" in st:
        out.append(("Não abra o arquivo",
                    "Pelo menos um teste falhou. Apague o arquivo, não volte ao link e não tente 'só ver rapidinho'. "
                    "Se achar que foi falso positivo, confirme com uma segunda ferramenta (abaixo) antes de abrir."))
    elif "WARN" in st:
        out.append(("Revise os avisos antes de abrir",
                    "Clique em cada teste com AVISO para ver o motivo. Arquivos reais às vezes têm estrutura estranha por "
                    "causa de ferramentas de conversão ruins, mas desconfie, principalmente se houver aviso de estrutura ou de caixas."))
    if sha:
        vt = by.get("vt", {})
        if size and size > VT_LIMIT:
            out.append(("VirusTotal: use só o hash",
                        f"Este arquivo tem {size/1e9:.1f} GB. O VirusTotal aceita uploads de até cerca de {VT_LIMIT//10**6} MB, "
                        f"no site e na API (confirme no site, o limite pode mudar). Por isso só dá para consultar o hash: {vt_link(sha)}. "
                        "Se ele for desconhecido, não existe como enviar o arquivo inteiro."))
        elif "nunca viu" in vt.get("detail", ""):
            out.append(("VirusTotal: hash desconhecido, mas o arquivo pode ser enviado",
                        f"Ele cabe no limite de ~{VT_LIMIT//10**6} MB. Em virustotal.com, aba File, envie o arquivo. "
                        "Lembre que o conteúdo enviado fica acessível a fornecedores de segurança."))
        elif vt.get("status") == "SKIP":
            out.append(("VirusTotal: confira o hash",
                        f"Abra {vt_link(sha)}. Para o programa consultar sozinho, configure a chave gratuita do VirusTotal (botão 'Chave do VirusTotal' na janela, ou a variável VT_API_KEY)."))
    out.append(("Mais uma opinião de antivírus, localmente (sem limite de tamanho)",
                "O Defender do seu PC já escaneia arquivos locais e o arquivo depois de baixado. Para um terceiro motor, use os scanners "
                "gratuitos de Malwarebytes, ESET Online Scanner ou Kaspersky Virus Removal Tool (baixe só dos sites oficiais). "
                "Para repetir o do Defender à mão: Start-MpScan -ScanType CustomScan -ScanPath \"C:\\caminho\\do\\arquivo\"."))
    if is_link:
        out.append(("Reputação do link",
                    "Cole o link na aba URL do virustotal.com, em urlscan.io e em transparencyreport.google.com/safe-browsing/search. "
                    "No site de download, use só o botão do próprio serviço e ignore anúncios com 'Download' ou 'Play'."))
    if kind == "pdf":
        out.append(("Olhar o PDF mais a fundo",
                    "Ferramentas gratuitas que listam o que há dentro sem abrir o documento: pdfid.py e pdf-parser.py (Didier Stevens) "
                    "e 'qpdf --check arquivo.pdf'. Procure /JavaScript, /OpenAction, /Launch e /EmbeddedFile. "
                    "Para um PDF suspeito de verdade, um analisador online com análise de comportamento (como o Hybrid Analysis) mostra o que o arquivo faz."))
    else:
        out.append(("Decodificação completa (mais fundo)",
                    "No PowerShell: ffmpeg -v error -i \"arquivo\" -f null -  . É lento (percorre a mídia toda), mas qualquer erro "
                    "listado indica corrupção ou adulteração. Funciona dentro do Windows Sandbox/VM se preferir isolar."))
    out.append(("Metadados",
                "Rode exiftool \"arquivo\" ou abra no MediaInfo (mídia) e procure URLs, nomes de programas, autor ou campos estranhos."))
    if by.get("audit", {}).get("status") == "SKIP":
        out.append(("Auditoria interna não rodou",
                    "Ela (caixas MP4, tags de áudio, conteúdo ativo de PDF) só existe no sandbox Docker. Instale o Docker Desktop e rode de novo para cobrir esse teste."))
    q = by.get("quality", {})
    if q.get("status") == "WARN" and "baixos" in q.get("detail", ""):
        out.append(("Qualidade baixa",
                    "Resolução ou bitrate abaixo do esperado. Se a qualidade importa, compare com uma versão oficial "
                    "(aluguel ou compra digital)."))
    if kind == "pdf":
        out.append(("Ao abrir o PDF",
                    "Abra no navegador (Edge, Chrome ou Firefox), cujo leitor de PDF é isolado, ou em um leitor atualizado com o JavaScript desativado. "
                    "Não clique em 'Permitir', 'Habilitar edição' ou avisos para abrir anexos e links. Se o PDF pedir senha ou a instalação de algo, feche."))
    else:
        out.append(("Ao reproduzir",
                    "Use um player atualizado (VLC, mpv), de preferência dentro do Windows Sandbox ou de uma VM na primeira vez. "
                    "A maior parte dos exploits de mídia ataca players desatualizados. Se algo pedir 'codec' ou 'atualização', feche."))
    return out


MEANING = {
    "scheme": "Sem HTTPS o download pode ser trocado no caminho. Não use o link.",
    "host": "O endereço tem sinais de golpe (IP no lugar de domínio, usuário na URL ou caracteres disfarçados). Não use o link.",
    "dns": "O domínio aponta para um endereço que não é público. Pode ser tentativa de acessar a sua rede. Não use o link.",
    "resolve": "Não foi possível achar o arquivo na página: pode ter sido removido, exigir captcha ou o site mudou.",
    "probe": "O servidor não respondeu como esperado. O sandbox ainda tenta baixar, mas confira o link.",
    "clen": "Arquivo acima do limite (3 GB) ou sem tamanho informado. O programa não analisa arquivos acima do limite.",
    "ext": "Tipo não suportado ou perigoso. Um executável com nome de documento ou mídia é o disfarce mais comum. Não abra.",
    "size_cap": "Arquivo vazio ou acima do limite de 3 GB.",
    "download": "O sandbox não conseguiu obter o arquivo. Pode ser link expirado, bloqueio ou o antivírus removeu o arquivo ao baixar.",
    "size": "Arquivo pequeno demais para o tipo. Isca de malware costuma ter poucos KB ou MB. Desconfie.",
    "header": "O conteúdo não é do tipo que a extensão diz, ou é executável, compactado, script ou página HTML. Não abra.",
    "structure": "A estrutura não fecha com o tamanho do arquivo. Pode ser corrupção ou dados anexados (ex.: um executável colado no fim). Desconfie.",
    "audit": "Anomalias internas: padrão usado para explorar falhas de players e leitores. Em PDF, conteúdo ativo (JavaScript, ações automáticas, arquivos embutidos) é a via mais comum de ataque.",
    "quality": "Resolução ou bitrate baixos, ou metadados ilegíveis. Não é perigo, mas indica qualidade ruim ou arquivo adulterado.",
    "embedded": "Há um executável ou arquivo compactado escondido dentro do arquivo. Apague-o.",
    "ffprobe": "O ffprobe não reconhece o arquivo como mídia válida do tipo esperado, ou achou erros. Apague ou confirme em outra ferramenta.",
    "decode": "A mídia não decodifica sem erro. Pode ser corrupção, codec incomum ou adulteração.",
    "validators": "Um validador independente achou problema de estrutura (ou dois leitores discordam). Pode ser corrupção ou adulteração; desconfie, principalmente se outros testes também avisaram.",
    "second": "Uma ferramenta de segunda opinião discorda da análise do programa ou achou um executável ou arquivo compactado escondido. Pode ser falso positivo; desconfie se outros testes também avisaram.",
    "yara": "Uma regra da comunidade casou. Leia o nome e a descrição da regra: regras com pontuação alta indicam malware conhecido; as demais, comportamento suspeito.",
    "defender": "O Defender encontrou uma ameaça (ou não conseguiu escanear). Não abra o arquivo.",
    "av": "O antivírus identificou uma ameaça conhecida, ou avisou que não conseguiu olhar o arquivo por inteiro (criptografado ou acima de um limite). Apague ou confirme em outra ferramenta.",
    "vt": "Mecanismos do VirusTotal classificaram o arquivo como malicioso ou suspeito. Um hash desconhecido é só informativo: o VirusTotal nunca viu o arquivo, o que não indica problema nem prova que está limpo.",
    "sandbox": "O sandbox não concluiu, então a maior parte dos testes não rodou. Confira o Docker/Windows Sandbox e tente de novo.",
}

GLOSSARY = [
    ("Sandbox", "Ambiente isolado e descartável (Windows Sandbox ou contêiner Docker) onde o arquivo é analisado. Se algo der errado, o seu PC não é afetado e o ambiente some ao terminar."),
    ("Hash (SHA-256, SHA-1, MD5)", "Impressão digital do arquivo. Dois arquivos idênticos têm o mesmo hash. Serve para consultar serviços como o VirusTotal sem enviar o arquivo."),
    ("MP4 e caixas (ftyp, moov, mdat)", "Um MP4 é uma sequência de blocos chamados caixas. 'ftyp' identifica o formato, 'moov' guarda o índice e 'mdat' guarda o vídeo e o áudio."),
    ("ClamAV / Microsoft Defender", "Antivírus usados dentro do sandbox. Cada um compara o arquivo com assinaturas de malware conhecido."),
    ("ffprobe / ffmpeg", "Ferramentas que leem e decodificam vídeo. Aqui confirmam o formato, os codecs e se os dados são válidos."),
    ("Bitrate", "Quantidade de dados por segundo de vídeo. Muito baixo para a resolução indica qualidade ruim."),
    ("Falso positivo / falso negativo", "Falso positivo é um aviso sobre um arquivo bom. Falso negativo é uma ameaça que passou. Nenhuma verificação elimina os dois."),
]


def PROGRESS(plan, checks):  # noqa: N802 - a interface gráfica substitui isto
    """Chamado a cada mudança: plan = [(id, nome)], checks = testes já concluídos."""


TOOL_VERSION = "safecheck 1.0"
RUN = {"start": 0.0, "times": {}}  # instante de início e quando cada teste foi visto (aproximado)


def reset_run():
    RUN["start"], RUN["times"] = time.time(), {}
    RUN["source_url"], RUN["direct_url"] = "", ""  # só em memória: o link direto tem token e não vai para relatórios


def _emit(plan, checks):
    now = time.time()
    for c in checks:
        RUN["times"].setdefault(c["id"], now)
    PROGRESS(plan, checks)


_DOCKER = {}


def docker_ready():
    if "ok" not in _DOCKER:
        d = shutil.which("docker")
        _DOCKER["ok"] = bool(d) and subprocess.run([d, "info"], capture_output=True).returncode == 0
    return _DOCKER["ok"]


def sandbox_choice():
    """Docker é preferido (cobre mais testes e todos os tipos). O Windows Sandbox só entra sem Docker, e só para MP4."""
    if docker_ready():
        return "docker"
    return "windows" if windows_sandbox_available() else "docker"


def guest_plan():
    if sandbox_choice() == "windows":
        return PLAN_GUEST_COMMON + PLAN_GUEST_END + [("av", "Antivírus (Microsoft Defender)")]
    common = list(PLAN_GUEST_COMMON)
    common.insert(4, ("audit", "Anomalias internas do arquivo"))  # logo depois de "structure"
    return (common + PLAN_GUEST_END + [("ffprobe", "ffprobe: leitura da mídia"),
            ("decode", "Decodificação da mídia"), ("validators", "Validadores independentes"),
            ("second", "Ferramentas de segunda opinião"),
            ("yara", "Regras YARA da comunidade"), ("av", "Antivírus (ClamAV)")])


def finalize(plan, checks):
    """Põe os testes na ordem do plano e marca como PULADO os que não chegaram a rodar."""
    ids = {i for i, _ in plan}
    by, extras = {}, []
    for c in checks:
        if c["id"] in ids and c["id"] not in by:
            by[c["id"]] = c
        else:
            extras.append(c)
    out = [by.get(i) or chk(i, n, "SKIP", "não executado (uma etapa anterior reprovou ou o teste não existe neste ambiente)")
           for i, n in plan]
    return out + extras


def is_mediafire_page(url):
    p = urllib.parse.urlparse(url)
    h = (p.hostname or "").lower()
    return (h == "mediafire.com" or h.endswith(".mediafire.com")) and "/file" in url


# ---------------------------------------------------------------- validação do link (host)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def public_ip_ok(host):
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return False, f"DNS não resolve ({e})"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return False, f"resolve para endereço não público ({ip})"
    return True, infos[0][4][0]


def validate_url(url):
    out = []
    p = urllib.parse.urlparse(url)
    out.append(chk("scheme", "Link usa HTTPS", "PASS" if p.scheme == "https" else "FAIL", p.scheme or "sem esquema"))
    if p.scheme != "https" or not p.hostname:
        return out, False
    host = p.hostname.lower()
    problems = []
    if p.username or p.password:
        problems.append("contém usuário/senha na URL")
    try:
        ipaddress.ip_address(host)
        problems.append("host é um IP literal")
    except ValueError:
        pass
    if "xn--" in host:
        problems.append("domínio com punycode (possível imitação)")
    out.append(chk("host", "Domínio sem sinais óbvios de golpe", "FAIL" if problems else "PASS",
                   "; ".join(problems) or host))
    if problems:
        return out, False
    ok, info = public_ip_ok(host)
    out.append(chk("dns", "Domínio resolve para IP público", "PASS" if ok else "FAIL", info))
    if not ok:
        return out, False
    if host in SHORTENERS:
        out.append(chk("shortener", "Não é encurtador de link", "WARN", "encurtador esconde o destino final"))
    return out, True


def fetch_text(url, limit=2_000_000):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read(limit).decode("utf-8", "replace")


def resolve_mediafire(url):
    """Retorna (direct_url|None, check). Só busca o HTML da página; nada é baixado."""
    host = urllib.parse.urlparse(url).hostname.lower()
    if not (host == "mediafire.com" or host.endswith(".mediafire.com")) or "/file" not in url:
        return url, None
    try:
        html = fetch_text(url)
    except Exception as e:  # noqa: BLE001
        return None, chk("resolve", "Resolver link direto do MediaFire", "FAIL", f"{type(e).__name__}: {e}")
    m = re.search(r'data-scrambled-url="([^"]+)"', html)
    direct = None
    if m:
        try:
            direct = base64.b64decode(m.group(1)).decode()
        except Exception:  # noqa: BLE001
            pass
    if not direct:
        m = re.search(r'href="(https://download[^"]+\.mediafire\.com/[^"]+)"', html)
        direct = m.group(1) if m else None
    if not direct:
        return None, chk("resolve", "Resolver link direto do MediaFire", "FAIL",
                         "não achei o botão de download (arquivo removido, captcha ou site mudou)")
    dh = (urllib.parse.urlparse(direct).hostname or "").lower()
    if not dh.endswith("mediafire.com") or not direct.startswith("https://"):
        return None, chk("resolve", "Resolver link direto do MediaFire", "FAIL", f"link direto aponta para outro domínio: {dh}")
    return direct, chk("resolve", "Resolver link direto do MediaFire", "PASS", f"download em {dh}")


def probe(url):
    """Segue redirecionamentos manualmente exigindo HTTPS e lê cabeçalhos sem baixar o corpo."""
    opener = urllib.request.build_opener(NoRedirect)
    hops = [urllib.parse.urlparse(url).hostname]
    for _ in range(6):
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        try:
            r = opener.open(req, timeout=20)
            return url, dict(r.headers), hops, None
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                url = urllib.parse.urljoin(url, e.headers.get("Location", ""))
                if not url.startswith("https://"):
                    return url, {}, hops, "redirecionamento para destino não-HTTPS"
                hops.append(urllib.parse.urlparse(url).hostname)
                continue
            return url, dict(e.headers or {}), hops, f"HTTP {e.code}"
        except Exception as e:  # noqa: BLE001
            return url, {}, hops, f"{type(e).__name__}: {e}"
    return url, {}, hops, "redirecionamentos demais"


def safe_url(url):
    """URL sem query nem fragmento (tokens de download não vão para o relatório)."""
    p = urllib.parse.urlparse(url)
    return urllib.parse.urlunparse((p.scheme, p.netloc, p.path, "", "", "")) + (" (parâmetros omitidos)" if p.query else "")


def probe_checks(url, ctx=None):
    final, hdr, hops, err = probe(url)
    out = []
    if ctx is not None:
        ctx["direct_host"] = (urllib.parse.urlparse(final).hostname or "")
        ctx["hops"] = list(dict.fromkeys(h for h in hops if h))
    if err:
        out.append(chk("probe", "Servidor responde ao link", "WARN", err + " (o sandbox ainda tentará baixar)"))
        return out, True
    h = {k.lower(): v for k, v in hdr.items()}
    if ctx is not None:
        ctx["announced_type"], ctx["announced_length"] = h.get("content-type", ""), h.get("content-length", "")
    out.append(chk("probe", "Servidor responde ao link", "PASS", "caminho: " + " → ".join(dict.fromkeys(hops))))
    ctype = h.get("content-type", "?")
    if "text/html" in ctype:
        out.append(chk("ctype", "Tipo de conteúdo anunciado", "WARN", f"{ctype}: parece página, não vídeo"))
    else:
        out.append(chk("ctype", "Tipo de conteúdo anunciado", "INFO", ctype))
    if h.get("content-length", "").isdigit():
        n = int(h["content-length"])
        if n > MAX_BYTES:
            out.append(chk("clen", "Tamanho anunciado dentro do limite", "FAIL", f"{n/1e9:.1f} GB > {MAX_BYTES/1e9:.0f} GB"))
            return out, False
        out.append(chk("clen", "Tamanho anunciado dentro do limite", "PASS", f"{n/1e6:.0f} MB"))
    else:
        out.append(chk("clen", "Tamanho anunciado dentro do limite", "WARN", "servidor não informou o tamanho"))
    return out, True


# ---------------------------------------------------------------- sandboxes
class SandboxUnavailable(Exception):
    pass


DOWNLOAD = {}  # estado do download dentro do sandbox: done, total, speed, attempt, note


def DL_LINE(text):  # noqa: N802 - o terminal e a janela substituem isto
    """Chamado com uma linha de status do download (ex.: '1,2 GB de 2,7 GB (44%) a 3,1 MB/s')."""


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000 or unit == "GB":
            return (f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}").replace(".", ",")
        n /= 1000


def download_text(d):
    """Texto curto do estado do download, para a janela e o terminal."""
    if d.get("note"):
        return d["note"]
    done, total = d.get("done", 0), d.get("total")
    txt = f"{fmt_bytes(done)} de {fmt_bytes(total)} ({done * 100 // total}%)" if total else f"{fmt_bytes(done)} baixados"
    if d.get("speed"):
        txt += f" a {fmt_bytes(d['speed'])}/s"
        if total and done < total:
            left = int((total - done) / d["speed"])
            txt += f", faltam cerca de {left // 60} min {left % 60:02d} s" if left >= 60 else f", faltam cerca de {left} s"
    if d.get("attempt", 1) > 1:
        txt += f" (tentativa {d['attempt']} de {d.get('max_attempts', '?')})"
    return txt


def wait_report(out_dir, proc=None, on_progress=None):
    path = os.path.join(out_dir, "report.json")
    prog = os.path.join(out_dir, "progress.json")
    t0, last = time.time(), None
    DOWNLOAD.clear()
    while time.time() - t0 < SANDBOX_TIMEOUT:
        if os.path.exists(path):
            with open(path, encoding="utf-8-sig") as f:
                return json.load(f)
        if os.path.exists(prog):
            try:
                m = os.path.getmtime(prog)
                if m != last:
                    with open(prog, encoding="utf-8-sig") as f:
                        data = json.load(f)
                    last = m
                    DOWNLOAD.clear()
                    DOWNLOAD.update(data.get("download") or {})
                    if DOWNLOAD:
                        DL_LINE(download_text(DOWNLOAD))
                    if on_progress:
                        on_progress(data.get("checks", []))
            except (OSError, ValueError):
                pass  # arquivo sendo trocado; tenta no próximo ciclo
        if proc is not None and proc.poll() is not None and not os.path.exists(path):
            raise RuntimeError(f"sandbox terminou sem relatório (código {proc.returncode})")
        time.sleep(1)
    raise RuntimeError("tempo esgotado esperando o sandbox")


def stage_inputs(work, url, local, expect_ext=""):
    """Prepara as pastas de entrada/saída. Arquivo local entra por hard link (sem copiar) e montado só para leitura."""
    in_dir, out_dir = os.path.join(work, "in"), os.path.join(work, "out")
    os.makedirs(in_dir)
    os.makedirs(out_dir)
    data_dir = None
    if local:
        data_dir = os.path.join(work, "data")
        os.makedirs(data_dir)
        dst = os.path.join(data_dir, "target.bin")  # nome neutro dentro do sandbox
        try:
            os.link(local, dst)
        except OSError:
            LOG(f"Copiando o arquivo ({os.path.getsize(local)/1e9:.1f} GB) para uma pasta temporária...")
            shutil.copyfile(local, dst)
        with open(os.path.join(in_dir, "local.txt"), "w", encoding="utf-8") as f:
            f.write(os.path.basename(local))
    else:
        with open(os.path.join(in_dir, "url.txt"), "w") as f:
            f.write(url)
    with open(os.path.join(in_dir, "ext.txt"), "w", encoding="utf-8") as f:  # extensão esperada (o sandbox compara com o conteúdo)
        f.write(expect_ext or (os.path.splitext(local)[1].lower() if local else ""))
    return in_dir, out_dir, data_dir


def run_windows_sandbox(url, work, local=None, on_progress=None, expect_ext=""):
    exe = shutil.which("WindowsSandbox.exe") or r"C:\Windows\System32\WindowsSandbox.exe"
    if not os.path.exists(exe):
        raise SandboxUnavailable("Windows Sandbox não está ativado")
    in_dir, out_dir, data_dir = stage_inputs(work, url, local, expect_ext)
    shutil.copy(os.path.join(HERE, "guest_windows.ps1"), in_dir)
    data_map = (f"\n    <MappedFolder><HostFolder>{escape(data_dir)}</HostFolder><SandboxFolder>C:\\data</SandboxFolder>"
                "<ReadOnly>true</ReadOnly></MappedFolder>") if data_dir else ""
    wsb = f"""<Configuration>
  <VGpu>Disable</VGpu><Networking>Enable</Networking><ProtectedClient>Enable</ProtectedClient>
  <ClipboardRedirection>Disable</ClipboardRedirection><PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>
  <MappedFolders>
    <MappedFolder><HostFolder>{escape(in_dir)}</HostFolder><SandboxFolder>C:\\in</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>{escape(out_dir)}</HostFolder><SandboxFolder>C:\\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>{data_map}
  </MappedFolders>
  <LogonCommand><Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\in\\guest_windows.ps1</Command></LogonCommand>
</Configuration>"""
    wsb_path = os.path.join(work, "safecheck.wsb")
    with open(wsb_path, "w", encoding="utf-8") as f:
        f.write(wsb)
    LOG("Abrindo Windows Sandbox (uma janela vai aparecer; ela fecha sozinha ao terminar)...")
    subprocess.Popen([exe, wsb_path])
    return wait_report(out_dir, on_progress=on_progress)


def ensure_image(docker):
    if subprocess.run([docker, "image", "inspect", IMAGE], capture_output=True).returncode == 0:
        return
    LOG("Primeira execução: construindo a imagem do sandbox (ClamAV + ffmpeg). Pode levar vários minutos...")
    r = subprocess.run([docker, "build", "-q", "-t", IMAGE, HERE], capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        raise RuntimeError("falha ao construir a imagem Docker: " + (r.stderr.strip().splitlines() or ["?"])[-1])


def run_docker(url, work, local=None, on_progress=None, expect_ext=""):
    docker = shutil.which("docker")
    if not docker:
        raise SandboxUnavailable("Docker não encontrado. Instale o Docker Desktop (ou ative o Windows Sandbox para MP4).")
    if subprocess.run([docker, "info"], capture_output=True).returncode != 0:
        raise SandboxUnavailable("O Docker está instalado, mas não está rodando. Abra o Docker Desktop e tente de novo.")
    in_dir, out_dir, data_dir = stage_inputs(work, url, local, expect_ext)
    os.chmod(out_dir, 0o777)
    for fn in ("guest_linux.py", "guest_audio.py", "guest_pdf.py"):
        shutil.copy(os.path.join(HERE, fn), in_dir)
    cname = f"safecheck-{os.getpid()}-{int(time.time())}"
    cmd = [docker, "run", "--rm", "--name", cname, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--pids-limit", "256", "--memory", "3g", "--read-only",
           "--tmpfs", "/tmp:rw,size=256m,noexec,nosuid", "-v", "/work", "-v", "/var/lib/clamav",
           "-v", f"{in_dir}:/in:ro", "-v", f"{out_dir}:/out:rw",
           ] + (["-v", f"{data_dir}:/data:ro"] if data_dir else []) + [
           "-e", f"MAX_BYTES={MAX_BYTES}", IMAGE, "python3", "-I", "/in/guest_linux.py"]
    ensure_image(docker)
    LOG("Subindo contêiner Docker descartável (atualiza o ClamAV e analisa o arquivo)...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        return wait_report(out_dir, proc, on_progress)
    finally:
        if proc.poll() is None:
            proc.kill()
        # garante que o contêiner (e o volume anônimo) não fiquem para trás
        subprocess.run([docker, "rm", "-f", "-v", cname], capture_output=True)


def find_mpcmdrun():
    """Localiza o MpCmdRun.exe (linha de comando do Microsoft Defender). Só existe no Windows."""
    if platform.system() != "Windows":
        return None
    cands = []
    base = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform")
    if os.path.isdir(base):
        def version_key(p):  # "4.18.2410.7" vira [4, 18, 2410, 7]; "CurrentVersion" (atalho) fica por último
            v = os.path.basename(os.path.dirname(p))
            return [int(x) for x in re.findall(r"\d+", v)] if re.match(r"^\d+(\.\d+)+", v) else []
        cands += sorted(glob.glob(os.path.join(base, "*", "MpCmdRun.exe")), key=version_key, reverse=True)  # a mais nova primeiro
    cands.append(os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe"))
    return next((c for c in cands if os.path.exists(c)), None)


def defender_scan(path, timeout=1800):
    """Escaneia o arquivo com o Defender do seu PC. O Defender lê o arquivo; ele não é aberto nem executado.
    -DisableRemediation: só relata, não mexe no arquivo."""
    name = "Microsoft Defender (no seu PC)"
    exe = find_mpcmdrun()
    if not exe:
        return chk("defender", name, "SKIP", "só no Windows, com o Microsoft Defender instalado")
    ver = os.path.basename(os.path.dirname(exe))
    try:
        r = subprocess.run([exe, "-Scan", "-ScanType", "3", "-File", path, "-DisableRemediation"],
                           capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        return chk("defender", name, "WARN", f"o scan passou de {timeout // 60} minutos e foi interrompido")
    except OSError as e:
        return chk("defender", name, "SKIP", f"não consegui iniciar o Defender ({type(e).__name__})")
    out = (r.stdout or "") + "\n" + (r.stderr or "")
    low = out.lower()
    m = re.search(r"found (\d+) threats?", low)
    if "found no threats" in low or (m and m.group(1) == "0"):
        return chk("defender", name, "PASS", f"nenhuma ameaça encontrada (Defender, plataforma {ver}); o arquivo foi lido, não aberto nem executado")
    if m:
        names = re.findall(r"^\s*Threat\s*:\s*(.+)$", out, re.M | re.I)
        return chk("defender", name, "FAIL", f"{m.group(1)} ameaça(s) encontrada(s)" + (": " + ", ".join(names[:3]) if names else ""))
    first = next((l.strip() for l in out.splitlines() if l.strip()), "sem resposta")
    return chk("defender", name, "SKIP", "o Defender não conseguiu escanear (pode estar desativado ou ser gerenciado por outro antivírus): " + first[:120])


def download_via_container(url, dest, expected_sha256, expected_size=None, on_progress=None, cancel=None):
    """Alternativa quando o PC não consegue baixar: o contêiner Docker baixa (usa outra rota de rede) para uma pasta temporária
    ao lado do destino. O SHA-256 é conferido no PC e só então o arquivo é movido para o destino."""
    import downloader
    docker = shutil.which("docker")
    if not docker or subprocess.run([docker, "info"], capture_output=True).returncode != 0:
        raise RuntimeError("o Docker não está disponível para baixar pelo contêiner (abra o Docker Desktop)")
    folder = os.path.dirname(os.path.abspath(dest))
    if expected_size:
        downloader.check_space(folder, expected_size)
    ensure_image(docker)
    tmp = tempfile.mkdtemp(prefix=".safecheck_dl_", dir=folder)  # mesma pasta do destino: mover o arquivo vira só um rename
    in_dir, out_dir = os.path.join(tmp, "in"), os.path.join(tmp, "out")
    os.makedirs(in_dir)
    os.makedirs(out_dir)
    os.chmod(out_dir, 0o777)
    shutil.copy(os.path.join(HERE, "guest_linux.py"), in_dir)
    for fn in ("guest_audio.py", "guest_pdf.py"):
        shutil.copy(os.path.join(HERE, fn), in_dir)
    with open(os.path.join(in_dir, "url.txt"), "w") as f:
        f.write(url)
    cname = f"safecheck-dl-{os.getpid()}-{int(time.time())}"
    cmd = [docker, "run", "--rm", "--name", cname, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--pids-limit", "128", "--memory", "1g", "--read-only", "--tmpfs", "/tmp:rw,size=64m,noexec,nosuid",
           "-v", f"{in_dir}:/in:ro", "-v", f"{out_dir}:/out:rw",
           "-e", f"MAX_BYTES={MAX_BYTES}", "-e", "MODE=download", "-e", "WORK_DIR=/out", IMAGE, "python3", "-I", "/in/guest_linux.py"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    rp, prog, last = os.path.join(out_dir, "report.json"), os.path.join(out_dir, "progress.json"), None
    try:
        while True:
            if cancel is not None and cancel.is_set():
                raise downloader.Cancelled()
            if os.path.exists(rp):
                with open(rp, encoding="utf-8-sig") as f:
                    rep = json.load(f)
                break
            if on_progress and os.path.exists(prog):
                try:
                    m = os.path.getmtime(prog)
                    if m != last:
                        with open(prog, encoding="utf-8-sig") as f:
                            data = json.load(f)
                        last = m
                        if data.get("download"):
                            on_progress(dict(data["download"]))
                except (OSError, ValueError):
                    pass
            if proc.poll() is not None and not os.path.exists(rp):
                raise RuntimeError(f"o contêiner terminou sem relatório (código {proc.returncode})")
            time.sleep(1)
        bad = next((c for c in rep.get("checks", []) if c["id"] == "download" and c["status"] == "FAIL"), None)
        if bad:
            raise RuntimeError(bad["detail"])
        got = rep.get("facts", {}).get("sha256")
        if got != expected_sha256:
            raise downloader.HashMismatch(got or "?")
        os.replace(os.path.join(out_dir, "target.bin"), dest)
        return dest
    finally:
        if proc.poll() is None:
            proc.kill()
        subprocess.run([docker, "rm", "-f", "-v", cname], capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


def windows_sandbox_available():
    return platform.system() == "Windows" and os.path.exists(
        shutil.which("WindowsSandbox.exe") or r"C:\Windows\System32\WindowsSandbox.exe")


def run_sandbox(url, work, local=None, on_progress=None, expect_ext=""):
    """Escolhe o sandbox. Retorna (relatório, método). Docker é preferido; o Windows Sandbox só serve para MP4."""
    ext = expect_ext or (os.path.splitext(local)[1].lower() if local else "")
    if sandbox_choice() == "windows":
        if ext and ext not in MP4_EXT:
            raise SandboxUnavailable("Este tipo de arquivo precisa do Docker (o Windows Sandbox só analisa MP4). Abra o Docker Desktop.")
        return run_windows_sandbox(url, work, local, on_progress, expect_ext), "Windows Sandbox"
    return run_docker(url, work, local, on_progress, expect_ext), "Docker"


# ---------------------------------------------------------------- VirusTotal
def vt_link(sha256):
    return f"https://www.virustotal.com/gui/file/{sha256}"


def virustotal(sha256, size=None):
    link = vt_link(sha256)
    key = settings.get_vt_key()
    if not key:
        return chk("vt", "VirusTotal (hash)", "SKIP", f"sem chave do VirusTotal configurada; confira manualmente: {link}")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            stats = json.load(r)["data"]["attributes"]["last_analysis_stats"]
    except urllib.error.HTTPError as e:
        e.close()
        if e.code == 404:  # a consulta funcionou: o VirusTotal só nunca viu este arquivo (comum em arquivos pessoais ou grandes)
            tail = (f" Como ele tem {size / 1e9:.1f} GB, o VirusTotal não aceita o envio (limite de cerca de {VT_LIMIT // 10**6} MB)."
                    if size and size > VT_LIMIT else " Você pode enviá-lo em virustotal.com, se quiser.")
            return chk("vt", "VirusTotal (hash)", "INFO",
                       "A consulta com a sua chave funcionou, mas o VirusTotal nunca viu este arquivo (comum em arquivos pessoais ou grandes). "
                       "Isso não indica problema, e também não confirma que está limpo." + tail + f" {link}")
        if e.code in (401, 403):
            return chk("vt", "VirusTotal (hash)", "WARN",
                       "O VirusTotal recusou a chave. Abra 'Chave do VirusTotal' na janela e use Testar.")
        if e.code == 429:
            return chk("vt", "VirusTotal (hash)", "WARN",
                       "Limite de consultas da chave gratuita atingido por agora. Tente de novo em alguns minutos.")
        return chk("vt", "VirusTotal (hash)", "WARN", f"O VirusTotal respondeu HTTP {e.code}.")
    except Exception as e:  # noqa: BLE001
        return chk("vt", "VirusTotal (hash)", "WARN", f"Não consegui falar com o VirusTotal ({type(e).__name__}).")
    bad = stats.get("malicious", 0) + stats.get("suspicious", 0)
    detail = f"{stats.get('malicious', 0)} malicioso, {stats.get('suspicious', 0)} suspeito, {stats.get('harmless', 0)} limpo. {link}"
    return chk("vt", "VirusTotal (hash)", "FAIL" if bad else "PASS", detail)


# ---------------------------------------------------------------- relatório
def verdict(checks):
    st = [c["status"] for c in checks]
    if "FAIL" in st:
        return "NÃO ABRA ESTE ARQUIVO: pelo menos um teste falhou."
    if "WARN" in st:
        return "ATENÇÃO: nenhum teste falhou, mas há avisos. Revise antes de abrir."
    return "Nenhum problema encontrado nos testes realizados (isto NÃO garante que o arquivo é seguro; veja as limitações)."


def print_report(url, method, checks, facts):
    print("\n" + "=" * 70)
    print(f"Alvo: {url}\nSandbox: {method}")
    if facts.get("sha256"):
        print(f"SHA-256: {facts['sha256']}")
    print("=" * 70 + "\nTestes executados:")
    for c in checks:
        print(f"  {SYMBOL[c['status']]} {c['name']}: {c['detail']}")
    n = {s: sum(c["status"] == s for c in checks) for s in SYMBOL}
    print(f"\nResumo: {n['PASS']} passaram, {n['FAIL']} falharam, {n['WARN']} avisos, {n['SKIP']} pulados.")
    print(f"\nVEREDITO: {verdict(checks)}")
    if facts.get("sha256"):
        print(f"\nConferir no VirusTotal: {vt_link(facts['sha256'])}")
    print("\nO que foi coberto:")
    for cat, level, how in COVERAGE:
        print(f"  [{level.upper():11}] {cat}: {how}")
    print("\nPróximos passos (o que fazer a mais, conforme o seu caso):")
    for i, (title, text) in enumerate(guidance(checks, facts, not os.path.isfile(clean_input(url))), 1):
        print(f"  {i}. {title}\n     {text}")
    print("\nLimitações deste programa:")
    for i, l in enumerate(LIMITATIONS, 1):
        print(f"  {i}. {l}")


def analyze_link(url):
    """Pipeline completo. Retorna (checks, facts, method)."""
    reset_run()
    expect = url_ext(url)
    plan = (PLAN_LINK_HOST + ([("resolve", "Resolver link direto do MediaFire")] if is_mediafire_page(url) else [])
            + PLAN_LINK_PROBE + guest_plan() + PLAN_VT)
    checks = []
    ctx = {"kind": "link", "url": safe_url(url)}
    _emit(plan, checks)
    LOG("[1/3] Validando o link (nada é baixado no seu PC)...")
    # validate_url devolve tudo de uma vez; revela um teste por vez para a interface mostrar o avanço
    vchecks, ok = validate_url(url)
    for c in vchecks:
        checks.append(c)
        _emit(plan, checks)
    direct = url
    if ok:
        direct, rc = resolve_mediafire(url)
        RUN["source_url"], RUN["direct_url"] = url, direct or ""
        if rc:
            checks.append(rc)
            _emit(plan, checks)
        if direct:
            pc, ok = probe_checks(direct, ctx)
            for c in pc:
                checks.append(c)
                _emit(plan, checks)
        else:
            ok = False
    if ok and expect in DANGEROUS_EXT:  # link para executável/script: recusa antes de baixar
        checks.append(chk("ext", "Tipo de arquivo suportado", "FAIL", ext_status(expect)[1]))
        _emit(plan, checks)
        ok = False
    facts, method = {}, "não executado"
    if ok:
        LOG("[2/3] Baixando e analisando dentro do sandbox...")
        work = tempfile.mkdtemp(prefix="safecheck_")
        base = list(checks)
        try:
            report, method = run_sandbox(direct, work, on_progress=lambda part: _emit(plan, base + part), expect_ext=expect)
            checks += report["checks"]
            facts = report.get("facts", {})
            RUN["ext"] = facts.get("ext", "")
        except (SandboxUnavailable, RuntimeError) as e:
            checks.append(chk("sandbox", "Sandbox executou a análise", "FAIL", str(e)))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        _emit(plan, checks)
        if facts.get("sha256"):
            LOG("[3/3] Consultando hash no VirusTotal...")
            checks.append(virustotal(facts["sha256"], facts.get("size")))
    else:
        checks.append(chk("sandbox", "Sandbox executou a análise", "SKIP", "link reprovado na validação; nada foi baixado"))
    checks = finalize(plan, checks)
    _emit(plan, checks)
    facts["context"], facts["tool"] = ctx, TOOL_VERSION
    return checks, facts, method


def analyze_file(path):
    """Analisa um arquivo que você já baixou, sem abri-lo no seu PC. Retorna (checks, facts, method)."""
    reset_run()
    plan = PLAN_LOCAL_HOST + guest_plan() + PLAN_VT
    checks = []
    _emit(plan, checks)
    LOG("[1/3] Conferindo o arquivo local (ele não será aberto nem executado)...")
    path = os.path.realpath(path)
    size = os.path.getsize(path)
    st = os.stat(path)
    iso = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M:%S")  # noqa: E731
    ctx = {"kind": "arquivo", "path": path, "name": os.path.basename(path), "size": size,
           "modified": iso(st.st_mtime), "created": iso(st.st_ctime)}
    ext = os.path.splitext(path)[1].lower()
    st_ext, why_ext = ext_status(ext)
    checks.append(chk("ext", "Tipo de arquivo suportado", st_ext, why_ext))
    _emit(plan, checks)
    if size > MAX_BYTES:
        checks.append(chk("size_cap", "Tamanho dentro do limite", "FAIL", f"{size/1e9:.1f} GB > {MAX_BYTES/1e9:.0f} GB"))
    elif size == 0:
        checks.append(chk("size_cap", "Tamanho dentro do limite", "FAIL", "arquivo vazio"))
    else:
        checks.append(chk("size_cap", "Tamanho dentro do limite", "PASS",
                          f"{size/1e6:.0f} MB" if size >= 1e6 else f"{size/1e3:.0f} KB"))
    _emit(plan, checks)
    if not any(c["status"] == "FAIL" for c in checks):
        LOG("Conferindo com o Microsoft Defender do seu PC (ele lê o arquivo, não o abre)...")
        checks.append(defender_scan(path))  # segundo motor de antivírus, além do ClamAV do sandbox
        _emit(plan, checks)
    facts, method = {}, "não executado"
    if any(c["status"] == "FAIL" for c in checks):
        checks.append(chk("sandbox", "Sandbox executou a análise", "SKIP", "arquivo reprovado na conferência; nada foi enviado ao sandbox"))
    else:
        LOG("[2/3] Analisando dentro do sandbox (arquivo montado só para leitura)...")
        work = tempfile.mkdtemp(prefix="safecheck_")
        base = list(checks)
        try:
            report, method = run_sandbox(None, work, local=path, on_progress=lambda part: _emit(plan, base + part), expect_ext=ext)
            checks += report["checks"]
            facts = report.get("facts", {})
        except (SandboxUnavailable, RuntimeError) as e:
            checks.append(chk("sandbox", "Sandbox executou a análise", "FAIL", str(e)))
        finally:
            shutil.rmtree(work, ignore_errors=True)
        _emit(plan, checks)
        if facts.get("sha256"):
            LOG("[3/3] Consultando hash no VirusTotal...")
            checks.append(virustotal(facts["sha256"], facts.get("size")))
    checks = finalize(plan, checks)
    _emit(plan, checks)
    facts["context"], facts["tool"] = ctx, TOOL_VERSION
    return checks, facts, method


def clean_input(text):
    return text.strip().strip('"').strip("'")


def looks_like_path(t):
    return bool(re.match(r"^[A-Za-z]:[\\/]", t)) or t.startswith(("/", "\\\\", "~")) or "\\" in t


def analyze_input(text):
    """Aceita um link ou o caminho de um arquivo local."""
    t = clean_input(text)
    if os.path.isfile(t):
        return analyze_file(t)
    if looks_like_path(t):  # parece caminho, mas o arquivo não existe: avisa em vez de tratar como link
        reset_run()
        plan = [("input", "Arquivo encontrado")]
        checks = [chk("input", "Arquivo encontrado", "FAIL",
                      "Não achei esse arquivo no seu PC. Confira o caminho e o nome, ou escolha o arquivo pelo botão.")]
        _emit(plan, checks)
        return checks, {"context": {"kind": "arquivo", "path": t}, "tool": TOOL_VERSION}, "não executado"
    return analyze_link(t)


def summarize(checks):
    """Veredito em linguagem simples: (nível, título, texto). Usado pela janela e pelo relatório HTML."""
    by = lambda st: ", ".join(c["name"] for c in checks if c["status"] == st)  # noqa: E731
    miss = next((c for c in checks if c["id"] == "input" and c["status"] == "FAIL"), None)
    if miss:
        return "warn", "Não consegui começar", miss["detail"]
    if any(c["status"] == "FAIL" for c in checks):
        return "bad", "Não abra este arquivo", f"Reprovou em: {by('FAIL')}. Apague o arquivo e veja os próximos passos."
    if any(c["status"] == "WARN" for c in checks):
        return "warn", "Atenção antes de abrir", f"Nenhum teste reprovou, mas há avisos em: {by('WARN')}. Abra cada um para entender antes de decidir."
    return "ok", "Nada suspeito encontrado", "Isto não garante que o arquivo é seguro. Veja em Cobertura o que não foi verificado."


def can_download(checks, facts):
    """O botão de baixar vale para análise por link com hash calculado e nenhuma falha.
    Com avisos ele aparece, mas a janela pede confirmação (e o botão fica âmbar). Com falha, nunca."""
    ctx = facts.get("context", {})
    return (ctx.get("kind") == "link" and bool(facts.get("sha256")) and bool(RUN.get("direct_url"))
            and not any(c["status"] == "FAIL" for c in checks))


def fresh_download_url():
    """Link direto para baixar no PC. Páginas do MediaFire são resolvidas de novo, porque o link direto expira."""
    src = RUN.get("source_url", "")
    if src and is_mediafire_page(src):
        direct, _ = resolve_mediafire(src)
        if direct:
            return direct
    return RUN.get("direct_url", "")


def suggest_filename():
    src = RUN.get("source_url", "")
    parts = [p for p in urllib.parse.urlparse(src).path.split("/") if p]  # MediaFire termina em /file
    name = next((p for p in reversed(parts) if os.path.splitext(p)[1].lower() in SUPPORTED_EXT), "")
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", urllib.parse.unquote(name)).strip(". ")
    return name or "arquivo_verificado" + (RUN.get("ext") or ".bin")


def html_path_for(json_path):
    return os.path.splitext(json_path)[0] + ".html"


def mmss(sec):
    sec = max(0, int(sec))
    return f"+{sec // 60:02d}:{sec % 60:02d}"


def sandbox_info(method, facts):
    local = facts.get("context", {}).get("kind") == "arquivo"
    if method == "Windows Sandbox":
        rows = [("Isolamento", "Windows Sandbox com cliente protegido, sem área de transferência, impressora, áudio ou vídeo; rede ligada para o download")]
    else:
        rows = [("Isolamento", "contêiner Docker descartável, usuário não-root, sem capabilities, sistema de arquivos somente leitura, "
                               "3 GB de memória, até 256 processos, removido ao terminar"),
                ("Imagem", IMAGE)]
    rows.append(("Rede do sandbox", "ligada, porque é necessária para baixar o arquivo e atualizar as assinaturas do antivírus"))
    if local:
        rows.append(("Arquivo local", "montado somente para leitura; o original não é alterado, aberto nem executado"))
    return rows


def build_report_data(url, method, checks, facts):
    import report_html  # noqa: F401  (só para falhar cedo se o módulo faltar)
    level, title, text = summarize(checks)
    start = RUN["start"] or time.time()
    return {
        "url": url, "method": method, "checks": checks, "facts": facts,
        "verdict_level": level, "verdict_title": title, "verdict_text": text,
        "steps": guidance(checks, facts, not os.path.isfile(clean_input(url))),
        "coverage": COVERAGE, "limitations": LIMITATIONS, "descr": DESCR, "meaning": MEANING, "glossary": GLOSSARY,
        "times": {k: mmss(v - start) for k, v in RUN["times"].items()}, "times_raw": dict(RUN["times"]),
        "started": datetime.fromtimestamp(start).strftime("%d/%m/%Y %H:%M:%S"), "duration": mmss(time.time() - start)[1:],
        "vt_link": vt_link(facts["sha256"]) if facts.get("sha256") else "", "tool": TOOL_VERSION,
        "os_info": f"{platform.system()} {platform.release()}", "sandbox_info": sandbox_info(method, facts),
    }


def save_report(url, method, checks, facts, folder):
    """Grava o JSON e o relatório HTML completo. Retorna o caminho do JSON (o HTML tem o mesmo nome, com .html)."""
    import report_html
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, datetime.now().strftime("%Y%m%d-%H%M%S") + ".json")
    data = build_report_data(url, method, checks, facts)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"url": url, "sandbox": method, "checks": checks, "facts": facts,
                   "verdict": verdict(checks), "coverage": COVERAGE,
                   "next_steps": [{"title": t, "text": x} for t, x in data["steps"]],
                   "limitations": LIMITATIONS}, f, ensure_ascii=False, indent=2)
    with open(html_path_for(path), "w", encoding="utf-8") as f:
        f.write(report_html.build_html(data))
    return path


def open_in_browser(path):
    import pathlib
    import webbrowser
    return webbrowser.open(pathlib.Path(path).resolve().as_uri())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", nargs="?", help="link do MP4 ou caminho de um .mp4 já baixado (se omitido, será perguntado)")
    ap.add_argument("--reports", default=settings.reports_dir(),
                    help="pasta para salvar os relatórios (padrão: a pasta de dados do usuário, fora do repositório)")
    ap.add_argument("--open", action="store_true", help="abre o relatório HTML no navegador ao terminar, sem perguntar")
    args = ap.parse_args()
    if not prereqs.guided_terminal():
        return 1
    url = clean_input(args.url or input("Cole o link ou o caminho do arquivo MP4: "))
    print()
    if sys.stdout.isatty():  # linha única que se atualiza durante o download
        globals()["DL_LINE"] = lambda t: print("\r  Download: " + t[:90].ljust(90), end="", flush=True)
    checks, facts, method = analyze_input(url)
    if sys.stdout.isatty():
        print()
    print_report(url, method, checks, facts)
    path = save_report(url, method, checks, facts, args.reports)
    html_file = html_path_for(path)
    print(f"\nRelatório completo (HTML): {html_file}\nRelatório em JSON:         {path}")
    if args.open or (sys.stdin.isatty() and input("\nAbrir o relatório no navegador agora? [S/n] ").strip().lower() in ("", "s", "sim", "y")):
        open_in_browser(html_file)
    return 1 if any(c["status"] == "FAIL" for c in checks) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):  # Ctrl+C / Ctrl+D é o jeito normal de sair: sem traceback
        print("\nCancelado.")
        sys.exit(130)
