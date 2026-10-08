"""Instalacao por copia, sem privilegios ou alteracoes de seguranca."""
import argparse
import os
import shutil
import sys
from pathlib import Path

from seguranca import VERSION

SOURCE = Path(__file__).resolve().parent
FILES = ("programa.py", "INICIAR.cmd", "INSTALAR.cmd", "instalar.py", "LE-ME-PRIMEIRO.txt",
         "README.md", "INVESTIGACAO.md", "ARQUITETURA.md", "AGENTES-IA.md", "VALIDACAO.md", "tests/test_programa.py",
         "seguranca/__init__.py", "seguranca/diagnostico.py", "seguranca/agentes.py", "seguranca/api.py",
         "seguranca/ps.py", "seguranca/exposicao.py", "seguranca/eventos.py", "seguranca/registo.py",
         "seguranca/notificar.py", "seguranca/vigilancia.py", "seguranca/endurecer.py", "seguranca/tarefa.py",
         "seguranca/totp.py", "seguranca/porteiro.py",
         "tests/test_vigilancia.py", "tests/test_totp.py", "tests/test_porteiro.py", "tests/test_dois_fatores.py", "LICENSE", "SECURITY.md", "CHANGELOG.md")


def install(target):
    target = Path(target).expanduser().absolute()
    if target.exists() or target.is_symlink():
        raise ValueError("O destino ja existe. Escolhe uma pasta nova para nao sobrescrever ficheiros.")
    # Refuse symlink/junction parents so a chosen destination cannot silently redirect.
    for parent in target.parents:
        if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
            raise ValueError("O destino nao pode atravessar ligacoes ou juncoes.")
    for name in FILES:
        path = SOURCE / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("Pacote incompleto ou ficheiro inesperado: " + name)
    target.mkdir(parents=True, exist_ok=False)
    for name in FILES:
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(SOURCE / name, destination)
    return target


def main():
    if sys.version_info < (3, 10):
        raise SystemExit("E necessario Python 3.10 ou superior.")
    parser = argparse.ArgumentParser(description="Copia o programa para uma pasta nova; sem administrador.")
    parser.add_argument("--destino", type=Path)
    args = parser.parse_args()
    target = args.destino
    if target is None:
        default = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / ("AlgoritmoSecuretySistens-" + VERSION)
        print("Instalacao por copia. Nao instala antivirus, servicos, drivers ou chaves API.")
        print("Destino proposto: " + str(default))
        entered = input("Enter aceita; escreve outro caminho ou CANCELAR: ").strip()
        if entered.upper() == "CANCELAR":
            return
        target = Path(entered) if entered else default
    try:
        destination = install(target)
        print("Instalado em: " + str(destination))
        print("Abre INICIAR.cmd nessa pasta. Para desinstalar, fecha o programa e elimina essa pasta.")
    except (OSError, ValueError) as error:
        print("Instalacao nao concluida: " + str(error))
        sys.exit(1)


if __name__ == "__main__":
    main()
