"""Instalacao da vigilancia protegida: programa em Program Files, estado em ProgramData (so administradores
escrevem) e tarefa agendada ao iniciar sessao. Recusa configuracoes que permitiriam elevar privilegios."""
import os
import shutil
import sys
from pathlib import Path

from .ps import PSError, e_admin, executar

TAREFA = "AlgoritmoNatural-SecuretySistens-Vigilancia"
DESTINO = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "AlgoritmoNatural" / "SecuretySistens"
ESTADO = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AlgoritmoNatural" / "AlgoritmoSecuretySistens"
FICHEIROS = ("programa.py", "seguranca/__init__.py", "seguranca/ps.py", "seguranca/diagnostico.py", "seguranca/exposicao.py",
             "seguranca/eventos.py", "seguranca/registo.py", "seguranca/notificar.py", "seguranca/vigilancia.py",
             "seguranca/endurecer.py", "seguranca/tarefa.py", "seguranca/agentes.py", "seguranca/api.py",
             "LICENSE", "README.md", "LE-ME-PRIMEIRO.txt")

REGISTAR = r"""
$u = "$env:USERDOMAIN\$env:USERNAME"
$a = New-ScheduledTaskAction -Execute $env:AN_PYW -Argument ('"' + $env:AN_PROG + '" --vigiar') -WorkingDirectory $env:AN_DIR
$t = New-ScheduledTaskTrigger -AtLogOn -User $u
$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $env:AN_TAREFA -Action $a -Trigger $t -Principal $p -Settings $s -Description 'Algoritmo Natural - vigilancia de tentativas de entrada (Nuno Camara)' -Force | Out-Null
icacls $env:AN_ESTADO /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
Start-ScheduledTask -TaskName $env:AN_TAREFA
"""
REMOVER = r"""
Stop-ScheduledTask -TaskName $env:AN_TAREFA -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $env:AN_TAREFA -Confirm:$false -ErrorAction SilentlyContinue
"""
ESTADO_TAREFA = r"""
$t = Get-ScheduledTask -TaskName $env:AN_TAREFA -ErrorAction SilentlyContinue
if ($t) { [ordered]@{existe=$true; estado=[string]$t.State} | ConvertTo-Json -Compress } else { '{"existe":false}' }
"""


class TarefaError(Exception):
    pass


def pasta_do_utilizador(caminho):
    """Pastas onde um programa sem privilegios consegue escrever nao podem alimentar um processo elevado."""
    c = str(Path(caminho).resolve()).lower()
    perfis = [os.environ.get("USERPROFILE", ""), os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", ""),
              os.environ.get("TEMP", ""), r"c:\users"]
    return any(p and c.startswith(p.lower()) for p in perfis)


def pythonw():
    exe = Path(sys.executable)
    candidato = exe.with_name("pythonw.exe")
    return candidato if candidato.exists() else exe


def verificar_requisitos():
    problemas = []
    if not e_admin():
        problemas.append("Abre o programa como administrador (botao direito > Executar como administrador).")
    if pasta_do_utilizador(sys.executable):
        problemas.append(f"O Python esta numa pasta do utilizador ({Path(sys.executable).parent}). Um programa malicioso "
                         "poderia altera-lo e ganhar privilegios. Instala o Python 'para todos os utilizadores' "
                         "(Install for all users, em C:\\Program Files) e abre este programa com esse Python.")
    return problemas


def instalar(origem):
    problemas = verificar_requisitos()
    if problemas:
        raise TarefaError("\n".join(problemas))
    origem = Path(origem)
    for nome in FICHEIROS:
        if not (origem / nome).is_file():
            raise TarefaError("Ficheiro em falta: " + nome)
    if DESTINO.exists():
        shutil.rmtree(DESTINO)
    for nome in FICHEIROS:
        (DESTINO / nome).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(origem / nome, DESTINO / nome)
    ESTADO.mkdir(parents=True, exist_ok=True)
    # Nada e importado da pasta do utilizador: qualquer programa sem privilegios podia la ter deixado uma linha de
    # base, palavra-passe ou servidor de notificacoes falsos. A configuracao protegida comeca do zero.
    try:
        executar(REGISTAR, timeout=60, json_saida=False, parametros={
            "AN_PYW": str(pythonw()), "AN_PROG": str(DESTINO / "programa.py"), "AN_DIR": str(DESTINO),
            "AN_ESTADO": str(ESTADO), "AN_TAREFA": TAREFA})
    except PSError as erro:
        raise TarefaError(str(erro)) from None
    return DESTINO, ESTADO


def remover():
    if not e_admin():
        raise TarefaError("Abre o programa como administrador.")
    try:
        executar(REMOVER, timeout=60, json_saida=False, parametros={"AN_TAREFA": TAREFA})
    except PSError as erro:
        raise TarefaError(str(erro)) from None
    if DESTINO.exists():
        shutil.rmtree(DESTINO)


def estado():
    try:
        return executar(ESTADO_TAREFA, timeout=30, parametros={"AN_TAREFA": TAREFA}) or {"existe": False}
    except PSError:
        return {"existe": False}
