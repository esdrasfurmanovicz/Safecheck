"""Garante que todos os arquivos Python do projeto compilam (inclusive a janela, que os outros testes não importam)."""
import glob
import os
import unittest

import context


class SintaxeTest(unittest.TestCase):
    def test_todos_os_arquivos_compilam(self):
        padroes = ("*.py", "*.pyw", os.path.join("tests", "*.py"), os.path.join("tools", "*.py"))
        arquivos = [f for p in padroes for f in glob.glob(os.path.join(context.ROOT, p))]
        self.assertGreater(len(arquivos), 10)
        for arquivo in arquivos:
            with self.subTest(arquivo=os.path.relpath(arquivo, context.ROOT)):
                with open(arquivo, encoding="utf-8") as f:
                    compile(f.read(), arquivo, "exec")  # só verifica a sintaxe: não grava nada em disco


if __name__ == "__main__":
    unittest.main()
