"""Testes da leitura da saída do YARA e da classificação por região do MP4, com a saída do `yara` simulada
(o programa `yara` e as regras só existem dentro da imagem Docker)."""
import tempfile
import types
import unittest
from unittest import mock

import context  # noqa: F401
import guest_linux as gl

ARQ = "/work/target.bin"
CAIXAS = [["ftyp", 32], ["moov", 100], ["free", 50], ["mdat", 1000]]  # deslocamentos: 0-31, 32-131, 132-181, 182-1181


def cabecalho(nome, meta=""):
    return f"{nome} [{meta}] {ARQ}" if meta else f"{nome} {ARQ}"


class RegiaoTest(unittest.TestCase):
    def test_regiao_de_cada_deslocamento(self):
        with mock.patch.dict(gl.facts, {"boxes": CAIXAS}):
            self.assertEqual(gl.mp4_region(10), "ftyp")
            self.assertEqual(gl.mp4_region(40), "moov")
            self.assertEqual(gl.mp4_region(140), "free")
            self.assertEqual(gl.mp4_region(500), "mdat")
            self.assertIn("anexados", gl.mp4_region(5000))


class YaraTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for alvo, valor in (("OUT_DIR", self.tmp.name),):
            p = mock.patch.object(gl, alvo, valor)
            p.start()
            self.addCleanup(p.stop)
        gl.checks.clear()
        gl.facts.clear()
        gl.facts["boxes"] = CAIXAS

    def varre(self, saida, kind="mp4"):
        falso = types.SimpleNamespace(stdout=saida, stderr="", returncode=0)
        with mock.patch.object(gl.shutil, "which", return_value="/usr/bin/yara"), \
                mock.patch.object(gl.os.path, "exists", return_value=True), \
                mock.patch.object(gl, "run", return_value=falso):
            gl.yara_scan(ARQ, ".mp4", kind)
        return gl.checks[-1]

    def test_nada_casou(self):
        self.assertEqual(self.varre("")["status"], "PASS")

    def test_regra_de_documentos_dentro_do_video_e_so_informacao(self):
        c = self.varre(cabecalho("maldoc_getEIP_method_1", 'author="Didier Stevens"') + "\n0x1f4:$a: E8 00 00 00 00 58\n")
        self.assertEqual(c["status"], "INFO")
        self.assertIn("0x1f4", c["detail"])
        self.assertIn("mdat", c["detail"])

    def test_dentro_do_indice_tambem_e_informacao(self):
        c = self.varre(cabecalho("maldoc_getEIP_method_1") + "\n0x28:$a: E8 00 00 00 00 58\n")
        self.assertEqual(c["status"], "INFO")

    def test_em_espaco_livre_continua_aviso_com_o_deslocamento(self):
        c = self.varre(cabecalho("maldoc_getEIP_method_1") + "\n0x8c:$a: E8 00 00 00 00 58\n")
        self.assertEqual(c["status"], "WARN")
        self.assertIn("0x8c", c["detail"])
        self.assertIn("free", c["detail"])

    def test_depois_do_fim_das_caixas_e_aviso(self):
        c = self.varre(cabecalho("maldoc_getEIP_method_1") + "\n0x1000:$a: E8 00 00 00 00 58\n")
        self.assertEqual(c["status"], "WARN")
        self.assertIn("anexados", c["detail"])

    def test_em_pdf_continua_aviso(self):
        c = self.varre(cabecalho("maldoc_getEIP_method_1") + "\n0x1f4:$a: E8 00 00 00 00 58\n", kind="pdf")
        self.assertEqual(c["status"], "WARN")

    def test_pontuacao_alta_reprova_mesmo_dentro_do_video(self):
        c = self.varre(cabecalho("regra_grave", 'description="malware conhecido",score=90') + "\n0x1f4:$a: 41 42\n")
        self.assertEqual(c["status"], "FAIL")

    def test_regra_escondida_ou_de_baixo_sinal_e_ignorada(self):
        saida = cabecalho("auxiliar", "hide=true") + "\n0x10:$a: 41\n" + cabecalho("fraca", "score =30") + "\n0x20:$a: 42\n"
        c = self.varre(saida)
        self.assertEqual(c["status"], "PASS")
        self.assertIn("2 regra(s) de baixo sinal", c["detail"])


if __name__ == "__main__":
    unittest.main()
