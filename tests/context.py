"""Coloca a raiz do repositório no caminho de importação, para os testes enxergarem os módulos do projeto."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
