"""Roda na construção da imagem Docker: baixa regras YARA da comunidade, testa cada arquivo e compila as que funcionam.

Fontes (ambas gratuitas):
  - Neo23x0/signature-base (Detection Rule License 1.1)
  - Yara-Rules/rules (GPL-2.0)
Só um conjunto pequeno e relevante para PDF, documentos e arquivos com executáveis escondidos, para o scan ficar rápido
e com poucos falsos positivos. Se o download falhar, a imagem é construída sem regras e o teste YARA aparece como PULADO.
Uso: python3 build_yara_rules.py [pasta_de_saida]
"""
import datetime
import io
import os
import subprocess
import sys
import tarfile
import urllib.request

OUT = sys.argv[1] if len(sys.argv) > 1 else "/opt/yara"
SOURCES = [
    ("signature-base", "https://codeload.github.com/Neo23x0/signature-base/tar.gz/refs/heads/master", "Neo23x0/signature-base (DRL 1.1)",
     ["yara/gen_bad_pdf.yar", "yara/crime_cobalt_gang_pdf.yar", "yara/gen_file_anomalies.yar", "yara/general_cloaking.yar",
      "yara/gen_embedded_exe.yar", "yara/gen_susp_js_obfuscatorio.yar"]),
    ("yara-rules", "https://codeload.github.com/Yara-Rules/rules/tar.gz/refs/heads/master", "Yara-Rules/rules (GPL-2.0)",
     ["maldocs/Maldoc_PDF.yar", "maldocs/Maldoc_Hidden_PE_file.yar", "maldocs/maldoc_somerules.yar",
      "packers/Javascript_exploit_and_obfuscation.yar", "malware/MALW_Cloaking.yar"]),
]
# variáveis externas que algumas regras do signature-base esperam (definidas vazias na compilação e no scan)
DEFINES = ["-d", "filename=", "-d", "filepath=", "-d", "extension=", "-d", "filetype=", "-d", "owner="]


def compile_rules(files, out):
    r = subprocess.run(["yarac", *DEFINES, *files, out], capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip().splitlines()[:1]


def main():
    os.makedirs(os.path.join(OUT, "src"), exist_ok=True)
    manifest = [f"gerado em {datetime.datetime.utcnow():%Y-%m-%d} (UTC)"]
    accepted = []
    for repo, url, label, wanted in SOURCES:
        try:
            blob = urllib.request.urlopen(url, timeout=120).read()
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz")
        except Exception as e:  # noqa: BLE001
            manifest.append(f"{label}: download falhou ({type(e).__name__})")
            continue
        members = {m.name.split("/", 1)[-1]: m for m in tf.getmembers() if m.isfile()}
        for rel in wanted:
            m = members.get(rel)
            if m is None:
                manifest.append(f"{label}: {rel} não existe mais")
                continue
            dst = os.path.join(OUT, "src", repo + "__" + os.path.basename(rel))
            with open(dst, "wb") as f:
                f.write(tf.extractfile(m).read())
            ok, why = compile_rules(accepted + [dst], os.path.join(OUT, "test.yarc"))  # acumulando: evita nomes de regra repetidos
            if ok:
                accepted.append(dst)
                manifest.append(f"{label}: {rel} OK")
            else:
                os.remove(dst)
                manifest.append(f"{label}: {rel} ignorado ({why[0][:90] if why else 'erro'})")
    if accepted:
        compile_rules(accepted, os.path.join(OUT, "rules.yarc"))
    if os.path.exists(os.path.join(OUT, "test.yarc")):
        os.remove(os.path.join(OUT, "test.yarc"))
    manifest.append(f"{len(accepted)} arquivos de regra compilados")
    with open(os.path.join(OUT, "manifest.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(manifest) + "\n")
    print("\n".join(manifest))


if __name__ == "__main__":
    main()
