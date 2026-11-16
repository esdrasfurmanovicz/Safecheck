"""Roda na construção da imagem Docker: baixa os scripts pdfid.py e pdf-parser.py (Didier Stevens, gratuitos).

Eles não existem como pacote do Debian. Ficam em /opt/tools, junto com um manifest que registra a data e o SHA-256 de cada arquivo
(o relatório mostra isso). Se o download falhar, a imagem é construída sem eles e o teste de segunda opinião só pula essas duas.
Fonte: https://github.com/DidierStevens/DidierStevensSuite
Uso: python3 build_extra_tools.py [pasta_de_saida]
"""
import datetime
import hashlib
import os
import sys
import urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/tools"
BASE = "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/"
FILES = ["pdfid.py", "pdf-parser.py"]


def main():
    os.makedirs(OUT, exist_ok=True)
    lines = [f"gerado em {datetime.datetime.utcnow():%Y-%m-%d} (UTC)"]
    for name in FILES:
        try:
            data = urllib.request.urlopen(BASE + name, timeout=60).read()
            if b"python" not in data[:200].lower():
                raise ValueError("conteúdo inesperado")
            with open(os.path.join(OUT, name), "wb") as f:
                f.write(data)
            lines.append(f"{name} OK sha256 {hashlib.sha256(data).hexdigest()[:16]}")
        except Exception as e:  # noqa: BLE001
            lines.append(f"{name} falhou ({type(e).__name__})")
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
