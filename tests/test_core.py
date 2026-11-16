"""Testes da lógica do host: tipos aceitos, veredito, guia de próximos passos, VirusTotal, Defender, chave e relatório HTML.
Nada aqui usa rede, Docker nem o Defender de verdade (tudo que sairia do computador é simulado)."""
import io
import os
import shutil
import sys
import tempfile
import types
import unittest
import urllib.error
from unittest import mock

import context  # noqa: F401
import report_html
import safecheck as sc
import settings


def chk(cid, status, detail="x"):
    return sc.chk(cid, cid, status, detail)


class TiposTest(unittest.TestCase):
    def test_suportados(self):
        for ext in (".pdf", ".mp3", ".flac", ".wav", ".ogg", ".aac", ".mp4", ".mov", ".m4a"):
            self.assertEqual(sc.ext_status(ext)[0], "PASS", ext)

    def test_executaveis_sao_recusados(self):
        for ext in (".exe", ".msi", ".ps1", ".lnk", ".bat"):
            status, why = sc.ext_status(ext)
            self.assertEqual(status, "FAIL", ext)
            self.assertIn("executa código", why)

    def test_tipo_ainda_nao_suportado(self):
        status, why = sc.ext_status(".zip")
        self.assertEqual(status, "FAIL")
        self.assertIn("ainda não é suportado", why)

    def test_extensao_pela_url(self):
        self.assertEqual(sc.url_ext("https://www.mediafire.com/file/abc/Musica.MP3/file?x=1"), ".mp3")
        self.assertEqual(sc.url_ext("https://exemplo.com/a/b/c"), "")
        self.assertEqual(sc.url_ext("https://exemplo.com/setup.exe"), ".exe")

    def test_pagina_do_mediafire(self):
        self.assertTrue(sc.is_mediafire_page("https://www.mediafire.com/file/abc/x.pdf/file"))
        self.assertFalse(sc.is_mediafire_page("https://exemplo.com/file/abc"))


class VeredictoTest(unittest.TestCase):
    def test_finalize_ordena_e_preenche_pulados(self):
        plan = [("a", "A"), ("b", "B"), ("c", "C")]
        out = sc.finalize(plan, [chk("c", "PASS"), chk("a", "FAIL"), chk("extra", "WARN")])
        self.assertEqual([c["id"] for c in out], ["a", "b", "c", "extra"])
        self.assertEqual(out[1]["status"], "SKIP")

    def test_niveis(self):
        self.assertEqual(sc.summarize([chk("a", "PASS")])[0], "ok")
        self.assertEqual(sc.summarize([chk("a", "PASS"), chk("b", "WARN")])[0], "warn")
        self.assertEqual(sc.summarize([chk("a", "WARN"), chk("b", "FAIL")])[0], "bad")

    def test_informacao_nao_vira_aviso(self):
        self.assertEqual(sc.summarize([chk("a", "PASS"), chk("vt", "INFO")])[0], "ok")

    def test_arquivo_inexistente_tem_titulo_proprio(self):
        level, title, _ = sc.summarize([chk("input", "FAIL", "não achei")])
        self.assertEqual((level, title), ("warn", "Não consegui começar"))


class BaixarTest(unittest.TestCase):
    def setUp(self):
        sc.RUN["direct_url"] = "https://exemplo.com/x"
        self.facts = {"context": {"kind": "link"}, "sha256": "ab" * 32}

    def tearDown(self):
        sc.RUN["direct_url"] = ""

    def test_verde_e_com_avisos_podem_baixar(self):
        self.assertTrue(sc.can_download([chk("a", "PASS")], self.facts))
        self.assertTrue(sc.can_download([chk("a", "WARN")], self.facts))

    def test_falha_nunca_baixa(self):
        self.assertFalse(sc.can_download([chk("a", "FAIL")], self.facts))

    def test_arquivo_local_e_sem_hash_nao_baixam(self):
        self.assertFalse(sc.can_download([chk("a", "PASS")], {"context": {"kind": "arquivo"}, "sha256": "ab" * 32}))
        self.assertFalse(sc.can_download([chk("a", "PASS")], {"context": {"kind": "link"}}))


class GuiaTest(unittest.TestCase):
    def titles(self, checks, facts, is_link=False):
        return [t for t, _ in sc.guidance(checks, facts, is_link)]

    def test_arquivo_grande_so_consulta_o_hash(self):
        t = self.titles([chk("vt", "SKIP")], {"sha256": "ab" * 32, "size": 2_900_000_000, "kind": "mp4"})
        self.assertIn("VirusTotal: use só o hash", t)

    def test_hash_desconhecido_pequeno_pode_ser_enviado(self):
        vt = chk("vt", "INFO", "o VirusTotal nunca viu este arquivo")
        t = self.titles([vt], {"sha256": "ab" * 32, "size": 5_000_000, "kind": "mp3"})
        self.assertIn("VirusTotal: hash desconhecido, mas o arquivo pode ser enviado", t)

    def test_pdf_tem_guia_proprio(self):
        t = self.titles([chk("a", "PASS")], {"kind": "pdf"})
        self.assertIn("Ao abrir o PDF", t)
        self.assertNotIn("Ao reproduzir", t)

    def test_midia_tem_guia_de_player(self):
        t = self.titles([chk("a", "PASS")], {"kind": "mp3"})
        self.assertIn("Ao reproduzir", t)

    def test_link_ganha_dicas_de_reputacao(self):
        self.assertIn("Reputação do link", self.titles([chk("a", "PASS")], {"kind": "pdf"}, is_link=True))


class LinkTest(unittest.TestCase):
    def test_http_e_recusado(self):
        _, ok = sc.validate_url("http://exemplo.com/a.mp4")
        self.assertFalse(ok)

    def test_usuario_na_url_ip_e_punycode(self):
        for url in ("https://user:senha@exemplo.com/a", "https://127.0.0.1/a", "https://xn--pple-43d.com/a"):
            checks, ok = sc.validate_url(url)
            self.assertFalse(ok, url)
            self.assertEqual(checks[-1]["status"], "FAIL")

    def test_parametros_do_link_nao_vao_para_o_relatorio(self):
        self.assertNotIn("token", sc.safe_url("https://h/p?token=segredo"))

    def test_nome_sugerido(self):
        sc.RUN["source_url"], sc.RUN["ext"] = "https://www.mediafire.com/file/abc/Relatorio.pdf/file", ""
        self.assertEqual(sc.suggest_filename(), "Relatorio.pdf")
        sc.RUN["source_url"], sc.RUN["ext"] = "https://exemplo.com/dl?id=3", ".mp3"
        self.assertEqual(sc.suggest_filename(), "arquivo_verificado.mp3")


class VirusTotalTest(unittest.TestCase):
    def consulta(self, **kw):
        with mock.patch.object(sc.settings, "get_vt_key", return_value="k" * 64), \
                mock.patch.object(sc.urllib.request, "urlopen", **kw):
            return sc.virustotal("ab" * 32, 2_900_000_000)

    @staticmethod
    def erro(code):
        return urllib.error.HTTPError("u", code, "x", {}, io.BytesIO(b""))

    def test_hash_desconhecido_e_so_informacao(self):
        c = self.consulta(side_effect=self.erro(404))
        self.assertEqual(c["status"], "INFO")
        self.assertIn("nunca viu", c["detail"])
        self.assertIn("não aceita o envio", c["detail"])  # 2,9 GB passa do limite do VirusTotal

    def test_chave_recusada_e_limite_de_consultas(self):
        self.assertEqual(self.consulta(side_effect=self.erro(401))["status"], "WARN")
        self.assertIn("recusou a chave", self.consulta(side_effect=self.erro(403))["detail"])
        self.assertIn("Limite de consultas", self.consulta(side_effect=self.erro(429))["detail"])

    def test_resultado_limpo_e_malicioso(self):
        def resp(stats):
            body = ('{"data":{"attributes":{"last_analysis_stats":%s}}}' % stats).encode()
            return io.BytesIO(body)
        self.assertEqual(self.consulta(return_value=resp('{"malicious":0,"suspicious":0,"harmless":70}'))["status"], "PASS")
        self.assertEqual(self.consulta(return_value=resp('{"malicious":3,"suspicious":0,"harmless":60}'))["status"], "FAIL")

    def test_sem_chave_pula(self):
        with mock.patch.object(sc.settings, "get_vt_key", return_value=""):
            self.assertEqual(sc.virustotal("ab" * 32)["status"], "SKIP")


class DefenderTest(unittest.TestCase):
    def varrer(self, saida, rc=0, exe="C:/x/4.18.1/MpCmdRun.exe"):
        fake = types.SimpleNamespace(stdout=saida, stderr="", returncode=rc)
        with mock.patch.object(sc, "find_mpcmdrun", return_value=exe), mock.patch.object(sc.subprocess, "run", return_value=fake):
            return sc.defender_scan("C:/arquivo")

    def test_sem_ameacas(self):
        self.assertEqual(self.varrer("Scanning C:/x found no threats.")["status"], "PASS")

    def test_ameaca_encontrada(self):
        c = self.varrer("found 1 threats.\nThreat                  : Virus:DOS/Teste\n", rc=2)
        self.assertEqual(c["status"], "FAIL")
        self.assertIn("Virus:DOS/Teste", c["detail"])

    def test_defender_desativado_pula(self):
        self.assertEqual(self.varrer("ERROR: MpCmdRun: Command failed with hr = 0x800106ba.", rc=2)["status"], "SKIP")

    def test_sem_defender_pula(self):
        with mock.patch.object(sc, "find_mpcmdrun", return_value=None):
            self.assertEqual(sc.defender_scan("C:/arquivo")["status"], "SKIP")


class ChaveTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        env = {"APPDATA": self.tmp, "LOCALAPPDATA": self.tmp, "XDG_CONFIG_HOME": self.tmp, "XDG_DATA_HOME": self.tmp,
               "HOME": self.tmp, "USERPROFILE": self.tmp}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.environ.pop("VT_API_KEY", None)

    def test_salvar_ler_e_remover(self):
        self.assertEqual(settings.get_vt_key(), "")
        settings.set_vt_key("a" * 64)
        self.assertEqual(settings.get_vt_key(), "a" * 64)
        self.assertEqual(settings.vt_key_source(), "saved")
        settings.clear_vt_key()
        self.assertEqual(settings.get_vt_key(), "")

    @unittest.skipUnless(sys.platform == "win32", "a criptografia DPAPI só existe no Windows")
    def test_no_windows_a_chave_nao_fica_em_texto_puro(self):
        settings.set_vt_key("b" * 64)
        with open(settings.config_path(), encoding="utf-8") as f:
            self.assertNotIn("b" * 64, f.read())

    def test_variavel_de_ambiente_tem_prioridade(self):
        settings.set_vt_key("a" * 64)
        os.environ["VT_API_KEY"] = "c" * 64
        self.assertEqual(settings.get_vt_key(), "c" * 64)
        self.assertEqual(settings.vt_key_source(), "env")

    def test_relatorios_ficam_na_pasta_de_dados_fora_do_repositorio(self):
        pasta = settings.reports_dir()
        self.assertTrue(pasta.startswith(self.tmp))
        self.assertTrue(pasta.endswith(os.path.join("safecheck", "reports")))
        raiz = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.assertFalse(os.path.abspath(pasta).startswith(raiz))

    def test_formato_da_chave(self):
        self.assertTrue(settings.valid_key_format("a" * 64))
        self.assertFalse(settings.valid_key_format("curta"))
        self.assertFalse(settings.valid_key_format("z" * 64))


class RelatorioTest(unittest.TestCase):
    def setUp(self):
        sc.reset_run()
        self.checks = [sc.chk("header", "Tipo confere", "PASS", "ok"),
                       sc.chk("audit", "Anomalias", "WARN", "<script>alert(1)</script>")]
        self.facts = {"sha256": "ab" * 32, "size": 1234, "kind": "pdf", "details": [["Versão", "1.7"]],
                      "context": {"kind": "arquivo", "path": "C:/x/a.pdf", "name": "a.pdf"}}

    def html(self):
        return report_html.build_html(sc.build_report_data("C:/x/a.pdf", "Docker", self.checks, self.facts))

    def test_estrutura_e_secoes(self):
        html = self.html()
        self.assertTrue(html.startswith("<!doctype html>"))
        for secao in ("arquivo", "testes", "proximos", "cobertura", "metodo", "limites", "glossario", "dados"):
            self.assertIn(f'id="{secao}"', html)

    def test_texto_do_arquivo_e_escapado(self):
        html = self.html()
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)", html)

    def test_sem_recursos_externos(self):
        html = self.html()
        self.assertNotIn("<script src", html)
        self.assertNotIn('rel="stylesheet"', html)

    def test_grava_json_e_html(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = sc.save_report("C:/x/a.pdf", "Docker", self.checks, self.facts, pasta)
            self.assertTrue(os.path.exists(caminho))
            self.assertTrue(os.path.exists(sc.html_path_for(caminho)))


if __name__ == "__main__":
    unittest.main()
