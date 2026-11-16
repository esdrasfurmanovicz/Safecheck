# Imagem do sandbox Linux do safecheck:
#   Python + ClamAV + ffmpeg/ffprobe + poppler (pdfinfo, pdfdetach) + qpdf + mupdf (mutool)
#   + exiftool + validadores de áudio (flac, mp3val, ogginfo) + YARA com regras da comunidade
#   + ferramentas de segunda opinião: file, binwalk, pdfresurrect, steghide, ssdeep, pdfid e pdf-parser.
# A base de assinaturas do ClamAV é embutida no build e atualizada de novo a cada execução.
# As regras YARA e os scripts pdfid/pdf-parser são embutidos no build (para atualizá-los, suba o número da imagem em safecheck.py).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 clamav clamav-freshclam ffmpeg poppler-utils qpdf mupdf-tools \
      libimage-exiftool-perl flac mp3val vorbis-tools yara ca-certificates \
      file binwalk pdfresurrect steghide ssdeep \
 && rm -rf /var/lib/apt/lists/*
RUN freshclam --quiet || true
COPY build_yara_rules.py build_extra_tools.py /opt/
RUN python3 /opt/build_yara_rules.py /opt/yara || true
RUN python3 /opt/build_extra_tools.py /opt/tools || true
RUN mkdir /work && chmod 1777 /work
# roda sem root: o freshclam já é o dono da base e não precisa trocar de usuário
USER clamav
