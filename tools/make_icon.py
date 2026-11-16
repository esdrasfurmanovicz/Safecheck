"""Gera o ícone do safecheck (assets/icon.png e assets/icon.ico). Ferramenta de desenvolvimento: precisa do Pillow.

    pip install pillow
    python tools/make_icon.py

O ícone é desenhado em 1024 px e reduzido, para ficar nítido em todos os tamanhos (16 a 256 px).
Cores iguais às da interface: azul-petróleo, branco e o verde de "aprovado".
"""
import os

from PIL import Image, ImageDraw

S = 1024
TEAL, FOLD, WHITE, GREEN, LINE = (20, 96, 107), (186, 212, 216), (255, 255, 255), (46, 125, 79), (205, 220, 223)
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")


def draw():
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=int(S * 0.22), fill=TEAL)  # fundo

    x0, y0, x1, y1, fold = int(S * 0.26), int(S * 0.15), int(S * 0.74), int(S * 0.82), int(S * 0.17)
    d.polygon([(x0, y0), (x1 - fold, y0), (x1, y0 + fold), (x1, y1), (x0, y1)], fill=WHITE)  # folha com o canto dobrado
    d.polygon([(x1 - fold, y0), (x1 - fold, y0 + fold), (x1, y0 + fold)], fill=FOLD)
    for i, frac in enumerate((0.36, 0.45, 0.54)):  # linhas de texto do documento
        right = x1 - int(S * (0.20 if i else 0.12))
        d.rounded_rectangle((x0 + int(S * 0.06), int(S * frac), right, int(S * frac) + int(S * 0.04)), radius=int(S * 0.02), fill=LINE)

    cx, cy, r = int(S * 0.69), int(S * 0.71), int(S * 0.21)  # selo de verificação
    ring = int(S * 0.03)
    d.ellipse((cx - r - ring, cy - r - ring, cx + r + ring, cy + r + ring), fill=TEAL)  # anel na cor do fundo separa o selo da folha
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=GREEN)
    pts = [(cx - 0.52 * r, cy + 0.02 * r), (cx - 0.10 * r, cy + 0.44 * r), (cx + 0.56 * r, cy - 0.36 * r)]
    w = int(S * 0.058)
    d.line(pts, fill=WHITE, width=w, joint="curve")
    for x, y in (pts[0], pts[-1]):  # pontas arredondadas
        d.ellipse((x - w / 2, y - w / 2, x + w / 2, y + w / 2), fill=WHITE)
    return img


def main():
    os.makedirs(OUT, exist_ok=True)
    big = draw()
    big.resize((256, 256), Image.LANCZOS).save(os.path.join(OUT, "icon.png"))
    big.resize((256, 256), Image.LANCZOS).save(
        os.path.join(OUT, "icon.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    # prévia lado a lado em vários tamanhos, para conferir a legibilidade (não vai para o repositório)
    strip = Image.new("RGBA", (256 + 10 * 5 + 16 + 24 + 32 + 48 + 64, 256), (240, 244, 245, 255))
    x = 0
    for size in (256, 64, 48, 32, 24, 16):
        small = big.resize((size, size), Image.LANCZOS)
        strip.paste(small, (x, 0), small)
        x += size + 10
    strip.save(os.path.join(OUT, "_previa.png"))
    print("gerado em", OUT)


if __name__ == "__main__":
    main()
