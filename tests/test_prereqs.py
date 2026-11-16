"""Testes das pendências do programa. Nada instala, roda sudo nem fala com o Docker de verdade."""
import io
import unittest
from unittest import mock

import context  # noqa: F401
import prereqs


class PendenciasTest(unittest.TestCase):
    def test_docker_pronto_nao_gera_pendencia(self):
        with mock.patch.object(prereqs, "docker_state", return_value="ok"), \
                mock.patch.object(prereqs, "windows_sandbox_available", return_value=False):
            self.assertEqual(prereqs.find_pending(), [])

    def test_docker_ausente_no_fedora_instala_e_pede_nova_sessao(self):
        with mock.patch.object(prereqs, "SYSTEM", "Linux"):
            item = prereqs._docker_item("missing", "dnf")
        self.assertEqual(item["cmds"][0], ["dnf", "install", "-y", "moby-engine"])
        self.assertTrue(item["relogin"])
        self.assertFalse(item["manual"])

    def test_docker_sem_permissao_so_adiciona_ao_grupo(self):
        with mock.patch.object(prereqs, "SYSTEM", "Linux"):
            item = prereqs._docker_item("permission", "dnf")
        self.assertEqual(item["cmds"][0][:3], ["usermod", "-aG", "docker"])

    def test_sem_gerenciador_de_pacotes_vira_orientacao_manual(self):
        with mock.patch.object(prereqs, "SYSTEM", "Linux"):
            self.assertTrue(prereqs._docker_item("missing", None)["manual"])

    def test_tkinter_so_entra_na_janela(self):
        with mock.patch.object(prereqs, "tkinter_missing", return_value=True), \
                mock.patch.object(prereqs, "docker_state", return_value="ok"):
            self.assertEqual(prereqs.find_pending(gui=False), [])
            self.assertEqual(prereqs.find_pending(gui=True)[0]["id"], "tkinter")

    def test_windows_sandbox_dispensa_docker(self):
        with mock.patch.object(prereqs, "windows_sandbox_available", return_value=True), \
                mock.patch.object(prereqs, "docker_state", return_value="missing"):
            self.assertEqual(prereqs.find_pending(), [])


class FluxoTerminalTest(unittest.TestCase):
    ITEM = {"id": "docker", "label": "Docker", "why": "x", "cmds": [["true"]], "admin": False,
            "relogin": False, "manual": False}

    def run_flow(self, answer, tty=True):
        out = io.StringIO()
        with mock.patch.object(prereqs, "find_pending", side_effect=[[self.ITEM], []]), \
                mock.patch("sys.stdin.isatty", return_value=tty), \
                mock.patch.object(prereqs, "install", return_value=([self.ITEM], [])) as inst:
            ok = prereqs.guided_terminal(ask=lambda _p: answer, out=lambda t: out.write(t + "\n"))
        return ok, inst, out.getvalue()

    def test_aceitar_instala_e_segue(self):
        ok, inst, _ = self.run_flow("s")
        self.assertTrue(ok)
        inst.assert_called_once()

    def test_recusar_nao_instala_e_sai(self):
        ok, inst, texto = self.run_flow("n")
        self.assertFalse(ok)
        inst.assert_not_called()
        self.assertIn("encerrar", texto)

    def test_sem_terminal_interativo_nao_pergunta(self):
        ok, inst, _ = self.run_flow("s", tty=False)
        self.assertFalse(ok)
        inst.assert_not_called()


if __name__ == "__main__":
    unittest.main()
