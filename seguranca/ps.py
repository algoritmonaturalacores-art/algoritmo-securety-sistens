"""Execucao controlada de PowerShell: scripts fixos, parametros so por variaveis de ambiente."""
import base64
import ctypes
import json
import os
import subprocess
from pathlib import Path

PREFIXO = "[Console]::OutputEncoding=[Text.Encoding]::UTF8\n$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n"
LIMITE_LINHA = 32000


class PSError(Exception):
    pass


def powershell():
    root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    native = root / "Sysnative/WindowsPowerShell/v1.0/powershell.exe"
    return native if native.exists() else root / "System32/WindowsPowerShell/v1.0/powershell.exe"


def e_windows():
    return os.name == "nt"


def e_admin():
    if not e_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def executar(script, timeout=60, parametros=None, json_saida=True):
    """Executa um script constante. Os parametros nunca sao interpolados no texto do script:
    passam como variaveis de ambiente AN_* e o script le-os com $env:AN_*."""
    if not e_windows():
        raise PSError("Disponivel apenas no Windows.")
    ambiente = dict(os.environ)
    for nome, valor in (parametros or {}).items():
        if not nome.startswith("AN_") or not isinstance(valor, str) or "\x00" in valor:
            raise PSError("Parametro invalido.")
        ambiente[nome] = valor
    codificado = base64.b64encode((PREFIXO + script).encode("utf-16-le")).decode("ascii")
    if len(codificado) > LIMITE_LINHA:
        raise PSError("Script demasiado longo.")
    try:
        resposta = subprocess.run(
            [str(powershell()), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", codificado],
            capture_output=True, timeout=timeout, env=ambiente,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise PSError(f"Consulta excedeu {timeout} segundos.") from None
    except OSError:
        raise PSError("Nao foi possivel iniciar o PowerShell.") from None
    if resposta.returncode != 0:
        detalhe = resposta.stderr.decode("utf-8", "replace").strip().splitlines()
        raise PSError("PowerShell devolveu erro: " + (detalhe[0][:200] if detalhe else "sem detalhe"))
    if not json_saida:
        return resposta.stdout.decode("utf-8-sig", "replace")
    texto = resposta.stdout.decode("utf-8-sig", "replace").strip()
    if not texto:
        return None
    try:
        return json.loads(texto)
    except ValueError:
        raise PSError("Resposta do PowerShell em formato inesperado.") from None
