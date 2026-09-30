"""Endurecimento do Windows: lista fechada de alteracoes, cada uma confirmada pelo utilizador e registada.
Nenhuma alteracao e decidida pela IA ou aplicada automaticamente."""
import re

from .ps import PSError, e_admin, executar

GUID_AUDITORIA = {
    "Logon": "{0CCE9215-69AE-11D9-BED3-505054503030}",
    "Bloqueio de conta": "{0CCE9217-69AE-11D9-BED3-505054503030}",
    "Validacao de credenciais": "{0CCE923F-69AE-11D9-BED3-505054503030}",
    "Gestao de contas de utilizador": "{0CCE9235-69AE-11D9-BED3-505054503030}",
    "Gestao de grupos de seguranca": "{0CCE9237-69AE-11D9-BED3-505054503030}",
    "Outros eventos de sistema": "{0CCE9214-69AE-11D9-BED3-505054503030}",
    "Alteracao da politica de auditoria": "{0CCE922F-69AE-11D9-BED3-505054503030}",
}

ACOES = {
    "rdp": ("Desligar o Ambiente de Trabalho Remoto",
            "Ninguem consegue entrar neste PC por RDP. Podes voltar a ligar em Definicoes > Sistema.",
            r"Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 1 -Type DWord"
            "\nDisable-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue"),
    "assistencia": ("Desligar a Assistencia Remota",
                    "Deixa de ser possivel receber ajuda remota por convite do Windows.",
                    r"Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -Name fAllowToGetHelp -Value 0 -Type DWord"),
    "firewall": ("Ligar a firewall e bloquear entradas por omissao em todos os perfis",
                 "So entram ligacoes permitidas por regras explicitas.",
                 "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -NotifyOnListen True"),
    "auditoria": ("Registar todas as tentativas de entrada (auditoria)",
                  "Garante que o Windows regista entradas falhadas/aceites e contas criadas, para serem detetadas.",
                  "\n".join(f"auditpol /set /subcategory:'{g}' /success:enable /failure:enable | Out-Null" for g in GUID_AUDITORIA.values())
                  + "\nwevtutil sl Security /ms:268435456"),
    "bloqueio": ("Bloquear contas apos 10 palavras-passe erradas (15 minutos)",
                 "Trava ataques de adivinhacao de palavra-passe. O PIN do Windows Hello tem protecao propria.",
                 "net accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15 | Out-Null"),
    "defender": ("Ativar protecoes extra do Defender (PUA e protecao de rede)",
                 "Bloqueia programas indesejados e ligacoes a sites maliciosos conhecidos.",
                 "Set-MpPreference -PUAProtection Enabled -EnableNetworkProtection Enabled"),
    "smb1": ("Desligar o protocolo SMB1",
             "Protocolo antigo e inseguro (WannaCry).",
             "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"),
    "convidado": ("Desativar a conta Convidado",
                  "",
                  "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser"),
    "remoteregistry": ("Parar e desativar o Registo Remoto",
                       "",
                       "Stop-Service RemoteRegistry -Force -ErrorAction SilentlyContinue\nSet-Service RemoteRegistry -StartupType Disabled"),
}

REGRA_PUBLICA = r"""
$r = Get-NetFirewallRule -Name $env:AN_REGRA
$novo = @('Domain','Private') | Where-Object { $r.Profile.ToString() -match $_ -or $r.Profile.ToString() -eq 'Any' }
if ($novo) { Set-NetFirewallRule -Name $env:AN_REGRA -Profile ($novo -join ',') } else { Disable-NetFirewallRule -Name $env:AN_REGRA }
"""
ID_REGRA = re.compile(r"[A-Za-z0-9{}_.\- ]{1,200}")


class EndurecerError(Exception):
    pass


def aplicar(codigo, confirmado):
    if codigo not in ACOES:
        raise EndurecerError("Acao desconhecida.")
    if confirmado is not True:
        raise EndurecerError("Alteracao nao confirmada.")
    if not e_admin():
        raise EndurecerError("E preciso abrir o programa como administrador.")
    try:
        executar(ACOES[codigo][2], timeout=90, json_saida=False)
    except PSError as erro:
        raise EndurecerError(str(erro)) from None


def retirar_perfil_publico(id_regra, confirmado):
    if confirmado is not True:
        raise EndurecerError("Alteracao nao confirmada.")
    if not isinstance(id_regra, str) or not ID_REGRA.fullmatch(id_regra):
        raise EndurecerError("Identificador de regra invalido.")
    if not e_admin():
        raise EndurecerError("E preciso abrir o programa como administrador.")
    try:
        executar(REGRA_PUBLICA, timeout=60, json_saida=False, parametros={"AN_REGRA": id_regra})
    except PSError as erro:
        raise EndurecerError(str(erro)) from None
