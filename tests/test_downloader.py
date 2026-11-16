"""Testes do download no PC: retomada, travamento, hash errado, cancelamento e redirecionamento só HTTPS.
Usa um servidor HTTP local em 127.0.0.1 que se comporta mal de propósito."""
import hashlib
import http.server
import os
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

import context  # noqa: F401
import downloader as d

DADOS = os.urandom(3 * 1024 * 1024)
SHA = hashlib.sha256(DADOS).hexdigest()
CORTE = 36962  # mesmo ponto de corte observado num caso real


class Servidor(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    chamadas = {}

    def log_message(self, *args):
        pass

    def do_GET(self):
        n = Servidor.chamadas[self.path] = Servidor.chamadas.get(self.path, 0) + 1
        if self.path == "/403":
            self.send_error(403)
            return
        faixa = self.headers.get("Range")
        inicio = int(faixa.split("=")[1].split("-")[0]) if faixa else 0
        if inicio:
            self.send_response(206)
            self.send_header("Content-Range", f"bytes {inicio}-{len(DADOS) - 1}/{len(DADOS)}")
        else:
            self.send_response(200)
        corpo = DADOS[inicio:]
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        if self.path == "/cai" and n == 1:  # a primeira conexão cai no meio; a retomada funciona
            self.wfile.write(corpo[: len(corpo) // 2])
            self.wfile.flush()
            self.connection.close()
            return
        if self.path == "/corta":  # corta SEMPRE no mesmo ponto e, nas retomadas, não envia nada
            if inicio == 0:
                self.wfile.write(corpo[:CORTE])
                self.wfile.flush()
            self.connection.close()
            return
        self.wfile.write(corpo)


class DownloadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Servidor)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Servidor.chamadas.clear()
        self.pasta = tempfile.TemporaryDirectory()
        self.addCleanup(self.pasta.cleanup)
        self.destino = os.path.join(self.pasta.name, "arquivo.bin")
        pausa = mock.patch.object(d.time, "sleep")  # sem esperar entre as tentativas
        pausa.start()
        self.addCleanup(pausa.stop)

    def baixa(self, caminho, sha=SHA, **kw):
        return d.download_file(self.base + caminho, self.destino, sha, len(DADOS), **kw)

    def test_download_normal_confere_o_hash(self):
        self.baixa("/ok")
        with open(self.destino, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), SHA)
        self.assertFalse(os.path.exists(self.destino + ".part"))

    def test_retoma_do_ponto_onde_caiu(self):
        self.baixa("/cai")
        with open(self.destino, "rb") as f:
            self.assertEqual(f.read(), DADOS)
        self.assertEqual(Servidor.chamadas["/cai"], 2)

    def test_hash_diferente_apaga_tudo(self):
        with self.assertRaises(d.HashMismatch):
            self.baixa("/ok", sha="0" * 64)
        self.assertEqual(os.listdir(self.pasta.name), [])

    def test_servidor_que_corta_sempre_e_detectado(self):
        with self.assertRaises(d.Stalled) as ctx:
            self.baixa("/corta")
        self.assertIn(str(CORTE), str(ctx.exception))
        self.assertEqual(Servidor.chamadas["/corta"], 4)  # 1 inicial + 3 sem progresso, em vez de insistir 8 vezes
        self.assertEqual(os.listdir(self.pasta.name), [])

    def test_erro_http_explica_o_motivo(self):
        with self.assertRaises(RuntimeError) as ctx:
            self.baixa("/403")
        self.assertIn("expirado ou bloqueado", str(ctx.exception))

    def test_cancelar(self):
        parar = threading.Event()
        parar.set()
        with self.assertRaises(d.Cancelled):
            self.baixa("/ok", cancel=parar)
        self.assertEqual(os.listdir(self.pasta.name), [])

    def test_pouco_espaco_em_disco(self):
        with self.assertRaises(OSError):
            d.check_space(self.pasta.name, 10 ** 18)


class RedirecionamentoTest(unittest.TestCase):
    def test_redirecionar_para_http_e_bloqueado(self):
        manipulador = d._HttpsOnly()
        with self.assertRaises(urllib.error.URLError):
            manipulador.redirect_request(mock.Mock(), None, 302, "Found", {}, "http://exemplo.com/x")


if __name__ == "__main__":
    unittest.main()
