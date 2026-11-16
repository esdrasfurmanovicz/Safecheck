"""Testes da análise estática de PDF com arquivos sintéticos e inofensivos.

Os PDFs com padrões reais de ataque (eval/unescape, /Launch, executável embutido) não são gravados em disco aqui, porque o
antivírus do computador (e dos servidores de CI) os barra. Esses casos foram validados dentro do contêiner Docker."""
import os
import tempfile
import unittest
import zlib
from unittest import mock

import context  # noqa: F401
import guest_pdf as gp

PAGES = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
PAGE = b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>"


def build(extra=(), catalog=b"", trailer=b"", before=b"", after=b""):
    objs = [b"<< /Type /Catalog /Pages 2 0 R " + catalog + b">>", PAGES, PAGE, *extra]
    out, offs = before + b"%PDF-1.7\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R %s>>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, trailer, xref)
    return out + after


def stream(dic, body):
    return b"<< %s /Length %d >>\nstream\n" % (dic, len(body)) + body + b"\nendstream"


class PdfTest(unittest.TestCase):
    def analisa(self, dados):
        with tempfile.TemporaryDirectory() as pasta, mock.patch.object(gp.shutil, "which", return_value=None):
            caminho = os.path.join(pasta, "t.pdf")
            with open(caminho, "wb") as f:
                f.write(dados)
            return gp.analyze_pdf(caminho, len(dados))

    def avisos(self, res):
        return " | ".join(t for _, t in res["audit"])

    def test_pdf_limpo(self):
        res = self.analisa(build())
        self.assertEqual((res["structure"], res["audit"], res["embedded"]), ([], [], []))

    def test_links_e_formulario_sao_comuns(self):
        res = self.analisa(build(catalog=b"/AcroForm << /Fields [] >> ", extra=[b"<< /A << /S /URI /URI (https://exemplo.com/doc) >> >>"]))
        self.assertEqual(res["audit"], [])

    def test_javascript_ao_abrir_avisa(self):
        res = self.analisa(build(catalog=b"/OpenAction 4 0 R ", extra=[b"<< /S /JavaScript /JS (app.alert('oi');) >>"]))
        self.assertEqual(res["audit"][0][0], "WARN")
        self.assertIn("JavaScript", self.avisos(res))
        self.assertIn("executado ao abrir", self.avisos(res))

    def test_javascript_escondido_em_fluxo_compactado(self):
        escondido = zlib.compress(b"<< /S /JavaScript /JS (app.alert('x');) >> ")
        res = self.analisa(build(catalog=b"/OpenAction 5 0 R ", extra=[b"<< /Type /Foo >>", stream(b"/Type /ObjStm /N 1 /First 8 /Filter /FlateDecode", escondido)]))
        self.assertIn("JavaScript", self.avisos(res))

    def test_nome_ofuscado_com_javascript_reprova(self):
        res = self.analisa(build(catalog=b"/OpenAction 4 0 R ", extra=[b"<< /S /J#61vaScript /JS (app.alert(1);) >>"]))
        self.assertEqual(res["audit"][0][0], "FAIL")
        self.assertIn("disfarçados", self.avisos(res))

    def test_executavel_embutido_pelo_nome(self):
        res = self.analisa(build(extra=[b"<< /Type /Filespec /F (setup.exe) /EF << /F 5 0 R >> >>",
                                        stream(b"/Type /EmbeddedFile", b"conteudo inofensivo")]))
        self.assertEqual(res["audit"][0][0], "FAIL")
        self.assertIn("setup.exe", self.avisos(res))

    def test_lixo_depois_do_eof(self):
        res = self.analisa(build(after=bytes(range(1, 250))))
        self.assertTrue(any("depois do último %%EOF" in s for s in res["structure"]), res["structure"])

    def test_lixo_antes_do_cabecalho(self):
        res = self.analisa(build(before=b"GIF89a" + bytes(200)))
        self.assertTrue(any("antes do cabeçalho" in s for s in res["structure"]), res["structure"])

    def test_pdf_criptografado_avisa(self):
        self.assertIn("criptografado", self.avisos(self.analisa(build(trailer=b"/Encrypt 9 0 R "))))

    def test_link_para_ip_e_suspeito(self):
        res = self.analisa(build(extra=[b"<< /A << /S /URI /URI (http://185.12.3.4/x) >> >>"]))
        self.assertIn("suspeitos", self.avisos(res))

    def test_bomba_de_descompressao_e_contida(self):
        bomba = zlib.compress(bytes(50 * 1024 * 1024))  # 50 MB de zeros em ~50 KB
        res = self.analisa(build(extra=[stream(b"/Filter /FlateDecode", bomba)]))
        self.assertIn("fluxo", self.avisos(res))


if __name__ == "__main__":
    unittest.main()
