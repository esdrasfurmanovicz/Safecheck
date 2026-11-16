"""Testes dos analisadores de áudio e da detecção de tipo pelo conteúdo, com arquivos sintéticos montados na hora."""
import io
import struct
import unittest

import context  # noqa: F401
import guest_audio as ga
import guest_linux as gl


def analyze(kind, data):
    return ga.ANALYZERS[kind](io.BytesIO(data), len(data))


def mp3_frames(n=40):
    """MPEG-1 camada III, 128 kbps, 44,1 kHz: 417 bytes por quadro."""
    return (b"\xff\xfb\x90\x00" + bytes(413)) * n


def id3(frames=b"", ver=3):
    size = len(frames)
    sync = bytes([(size >> 21) & 127, (size >> 14) & 127, (size >> 7) & 127, size & 127])
    return b"ID3" + bytes([ver, 0, 0]) + sync + frames


def id3_frame(fid, data, size=None):
    return fid + struct.pack(">I", len(data) if size is None else size) + b"\x00\x00" + data


def wav(data=bytes(2000), extra=b""):
    fmt = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
    body = b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt + b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body + extra


def flac(padding=0):
    block = bytes([0x00 if padding else 0x80]) + (34).to_bytes(3, "big") + bytes(34)
    if padding:
        block += bytes([0x81]) + padding.to_bytes(3, "big") + bytes(padding)
    return b"fLaC" + block + b"\xff\xf8" + bytes(100)


def ogg_page(seq, eos=False):
    body = b"x" * 10
    kind = 0x04 if eos else (0x02 if seq == 0 else 0x00)
    return b"OggS" + bytes([0, kind]) + bytes(8) + bytes(4) + struct.pack("<I", seq) + bytes(4) + bytes([1, len(body)]) + body


class Mp3Test(unittest.TestCase):
    def test_quadro_valido(self):
        self.assertEqual(ga.mp3_frame(b"\xff\xfb\x90\x00"), (417, 128000, 44100))
        self.assertIsNone(ga.mp3_frame(b"\x00\x00\x00\x00"))

    def test_arquivo_limpo(self):
        tag = id3(id3_frame(b"TIT2", b"\x00Titulo"))
        st, au, det = analyze("mp3", tag + mp3_frames())
        self.assertEqual((st, au), ([], []))
        self.assertIn(["Título", "Titulo"], det)

    def test_dados_anexados_no_fim(self):
        st, _, _ = analyze("mp3", mp3_frames() + b"junk" * 1000)
        self.assertTrue(any("depois do último quadro" in s for s in st), st)

    def test_lixo_no_meio(self):
        quadros = mp3_frames()
        meio = len(quadros) // 2
        st, _, _ = analyze("mp3", quadros[:meio] + bytes(range(1, 120)) * 200 + quadros[meio:])
        self.assertTrue(any("fora de quadros" in s for s in st), st)

    def test_sem_nenhum_quadro(self):
        st, _, _ = analyze("mp3", id3() + bytes(range(1, 120)) * 200)
        self.assertTrue(any("nenhum quadro" in s for s in st), st)

    def test_quadro_de_tag_com_tamanho_impossivel(self):
        tag = id3(id3_frame(b"TIT2", b"\x00Titulo", size=0x0FFFFFFF))
        _, au, _ = analyze("mp3", tag + mp3_frames())
        self.assertTrue(any("tamanho impossível" in a for a in au), au)

    def test_objeto_grande_na_tag(self):
        tag = id3(id3_frame(b"GEOB", bytes(70000)))
        _, au, _ = analyze("mp3", tag + mp3_frames())
        self.assertTrue(any("GEOB" in a for a in au), au)

    def test_capa_que_nao_e_imagem(self):
        tag = id3(id3_frame(b"APIC", b"\x00image/png\x00\x03\x00" + b"isto nao e uma imagem" * 10))
        _, au, _ = analyze("mp3", tag + mp3_frames())
        self.assertTrue(any("APIC" in a for a in au), au)


class WavTest(unittest.TestCase):
    def test_limpo(self):
        self.assertEqual(analyze("wav", wav())[:2], ([], []))

    def test_dados_depois_do_fim_declarado(self):
        st, _, _ = analyze("wav", wav(extra=b"MZjunk" * 50))
        self.assertTrue(any("fim declarado" in s for s in st), st)

    def test_arquivo_truncado(self):
        dados = wav()
        st, _, _ = analyze("wav", dados[: len(dados) // 2])
        self.assertTrue(st)


class FlacTest(unittest.TestCase):
    def test_limpo(self):
        self.assertEqual(analyze("flac", flac())[:2], ([], []))

    def test_preenchimento_enorme(self):
        _, au, _ = analyze("flac", flac(padding=2_000_000))
        self.assertTrue(any("PADDING" in a for a in au), au)


class OggTest(unittest.TestCase):
    def test_limpo(self):
        self.assertEqual(analyze("ogg", ogg_page(0) + ogg_page(1, eos=True))[:2], ([], []))

    def test_dados_depois_da_ultima_pagina(self):
        st, _, _ = analyze("ogg", ogg_page(0) + ogg_page(1, eos=True) + b"junk" * 1000)
        self.assertTrue(any("depois da última página" in s for s in st), st)


class TipoPeloConteudoTest(unittest.TestCase):
    def kind(self, head):
        return gl.detect_kind(io.BytesIO(head), head)

    def test_tipos_reconhecidos(self):
        casos = {"mp3": mp3_frames(1)[:512], "flac": flac()[:512], "wav": wav()[:512], "ogg": ogg_page(0),
                 "pdf": b"%PDF-1.7\n" + bytes(100), "mp4": b"\x00\x00\x00\x20ftypisom" + bytes(100)}
        for esperado, head in casos.items():
            self.assertEqual(self.kind(head), (esperado, None), esperado)

    def test_id3_seguido_de_mp3(self):
        self.assertEqual(self.kind(id3() + mp3_frames(2))[0], "mp3")

    def test_executavel_e_recusado(self):
        kind, why = self.kind(b"MZ\x90\x00" + bytes(100))
        self.assertIsNone(kind)
        self.assertIn("executável", why)

    def test_compactado_e_pagina_html_sao_recusados(self):
        self.assertIsNone(self.kind(b"PK\x03\x04" + bytes(100))[0])
        self.assertIsNone(self.kind(b"<!DOCTYPE html><html>captcha</html>")[0])

    def test_riff_que_nao_e_wav(self):
        kind, why = self.kind(b"RIFF" + bytes(4) + b"AVI " + bytes(100))
        self.assertIsNone(kind)
        self.assertIn("AVI", why)


if __name__ == "__main__":
    unittest.main()
