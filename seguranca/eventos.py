"""Leitura dos registos do Windows e deteccao de tentativas de entrada."""
import ipaddress
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from .ps import PSError, executar

SCRIPT = r"""
$desde = [datetime]::Parse($env:AN_DESDE, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$max = [int]$env:AN_MAX
$tempo = "TimeCreated[@SystemTime>='$desde']"
$fontes = @(
  @('Security', "*[System[(EventID=4625) and $tempo]]"),
  @('Security', "*[System[(EventID=4624) and $tempo] and EventData[Data[@Name='LogonType']='10' or Data[@Name='LogonType']='3']]"),
  @('Security', "*[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4740 or EventID=1102 or EventID=4697 or EventID=4698) and $tempo]]"),
  @('System', "*[System[(EventID=7045 or EventID=104) and $tempo]]"),
  @('Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', "*[System[(EventID=1149) and $tempo]]"),
  @('Microsoft-Windows-Windows Defender/Operational', "*[System[(EventID=1006 or EventID=1015 or EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5010 or EventID=5012) and $tempo]]"),
  @('Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', "*[System[(EventID=2003 or EventID=2004 or EventID=2097) and $tempo]]"),
  @('OpenSSH/Operational', "*[System[(EventID=4) and $tempo]]")
)
$eventos = New-Object System.Collections.ArrayList
$falhas = New-Object System.Collections.ArrayList
foreach ($f in $fontes) {
  try {
    $lista = Get-WinEvent -LogName $f[0] -FilterXPath $f[1] -MaxEvents $max -ErrorAction Stop
    foreach ($e in $lista) {
      $x = [xml]$e.ToXml(); $d = [ordered]@{}; $texto = @()
      foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = [string]$n.'#text' } else { $texto += [string]$n.'#text' } }
      if ($x.Event.UserData) { foreach ($n in $x.Event.UserData.FirstChild.ChildNodes) { $d[$n.LocalName] = [string]$n.InnerText } }
      if ($texto) { $d['_texto'] = ($texto -join ' ') }
      [void]$eventos.Add([ordered]@{log=$f[0]; id=[int]$e.Id; hora=$e.TimeCreated.ToUniversalTime().ToString('o'); registo=[int64]$e.RecordId; dados=$d})
    }
  } catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { [void]$falhas.Add([ordered]@{log=$f[0]; erro=$_.Exception.GetType().Name}) }
  }
}
[ordered]@{eventos=@($eventos); inacessiveis=@($falhas)} | ConvertTo-Json -Depth 6 -Compress
"""

TIPOS_LOGON = {"2": "no teclado deste PC", "3": "pela rede (partilhas/SMB)", "4": "tarefa agendada", "5": "servico",
               "7": "desbloqueio do ecra", "8": "pela rede (palavra-passe em claro)", "9": "credenciais alternativas",
               "10": "Ambiente de Trabalho Remoto", "11": "credenciais em cache"}
GRUPO_ADMIN = "S-1-5-32-544"
LIMIAR_FORCA_BRUTA = 5
JANELA_FORCA_BRUTA = timedelta(minutes=10)


def ler(desde, maximo=300, timeout=90):
    try:
        dados = executar(SCRIPT, timeout=timeout, parametros={"AN_DESDE": desde.astimezone(timezone.utc).isoformat(), "AN_MAX": str(int(maximo))})
    except PSError as erro:
        return {"eventos": [], "inacessiveis": [{"log": "todos", "erro": str(erro)}]}
    if not isinstance(dados, dict):
        return {"eventos": [], "inacessiveis": []}
    eventos = dados.get("eventos") if isinstance(dados.get("eventos"), list) else []
    inacessiveis = dados.get("inacessiveis") if isinstance(dados.get("inacessiveis"), list) else []
    return {"eventos": [e for e in eventos if isinstance(e, dict)], "inacessiveis": [i for i in inacessiveis if isinstance(i, dict)]}


def _t(valor, limite=120):
    return "".join(c for c in str(valor or "") if c.isprintable())[:limite]


def ip_externo(ip):
    try:
        endereco = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return not endereco.is_loopback and not endereco.is_unspecified


FRACAO = re.compile(r"(\.\d{6})\d+")


def _hora(evento):
    # O Windows escreve 7 casas decimais; o Python 3.10 so aceita ate 6.
    try:
        return datetime.fromisoformat(FRACAO.sub(r"\1", str(evento.get("hora")).replace("Z", "+00:00")))
    except ValueError:
        return datetime.now(timezone.utc)


def _alerta(nivel, tipo, titulo, detalhe, evento=None, chave=None):
    return {"nivel": nivel, "tipo": tipo, "titulo": titulo, "detalhe": detalhe,
            "hora_evento": evento.get("hora") if evento else None,
            "origem": f"{evento.get('log')}#{evento.get('registo')}" if evento else None, "chave": chave}


PASTAS_PROTEGIDAS = ("c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\", "%systemroot%\\",
                     "\\systemroot\\", "system32\\", "\\??\\c:\\windows\\", "c:\\programdata\\microsoft\\windows defender\\")
PASTAS_UTILIZADOR = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\desktop\\", "\\users\\public\\", "\\programdata\\")


DEFENDER_CRITICOS = ("DisableRealtimeMonitoring", "DisableAntiSpyware", "DisableAntiVirus", "DisableBehaviorMonitoring",
                     "DisableIOAVProtection", "DisableOnAccessProtection", "DisableScriptScanning", "DisableBlockAtFirstSeen")


def nivel_caminho(caminho):
    """Servicos em pastas so de administrador sao normais em atualizacoes; em pastas de utilizador sao suspeitos."""
    c = caminho.lower().strip('"').lstrip('"')
    if any(p in c for p in PASTAS_UTILIZADOR) and not c.startswith("c:\\programdata\\microsoft\\windows defender\\"):
        return "critico"
    if c.startswith(PASTAS_PROTEGIDAS):
        return "info"
    return "aviso"


def agrupar(alertas):
    """Junta alertas iguais (mesmo titulo e detalhe) num so, com contagem."""
    vistos = {}
    for a in alertas:
        chave = (a["tipo"], a["titulo"], a["detalhe"])
        if chave in vistos:
            vistos[chave]["repeticoes"] = vistos[chave].get("repeticoes", 1) + 1
        else:
            vistos[chave] = dict(a)
    return list(vistos.values())


def analisar(eventos):
    return agrupar(_analisar(eventos))


def _analisar(eventos):
    """Transforma eventos em alertas. Tentativas falhadas sao agrupadas por origem."""
    alertas = []
    falhadas = defaultdict(list)
    for ev in eventos:
        d = ev.get("dados") if isinstance(ev.get("dados"), dict) else {}
        log, i = ev.get("log"), ev.get("id")
        if log == "Security" and i == 4625:
            origem = _t(d.get("IpAddress"), 60) if ip_externo(d.get("IpAddress")) else "este computador"
            falhadas[(origem, _t(d.get("LogonType"), 4))].append(ev)
        elif log == "Security" and i == 4624:
            ip, tipo = d.get("IpAddress"), _t(d.get("LogonType"), 4)
            if not ip_externo(ip):
                continue
            nivel = "critico" if tipo == "10" else "aviso"
            alertas.append(_alerta(nivel, "entrada-remota", f"Entrada com sucesso {TIPOS_LOGON.get(tipo, 'remota')}",
                                   f"Conta {_t(d.get('TargetUserName'), 60)} a partir de {_t(ip, 60)}", ev))
        elif log == "Security" and i == 4720:
            alertas.append(_alerta("critico", "conta-criada", "Foi criada uma conta de utilizador", f"Conta {_t(d.get('TargetUserName'), 60)} criada por {_t(d.get('SubjectUserName'), 60)}", ev))
        elif log == "Security" and i == 4722:
            alertas.append(_alerta("aviso", "conta-ativada", "Foi ativada uma conta de utilizador", f"Conta {_t(d.get('TargetUserName'), 60)}", ev))
        elif log == "Security" and i == 4724:
            alertas.append(_alerta("aviso", "password-reposta", "Palavra-passe de uma conta foi reposta", f"Conta {_t(d.get('TargetUserName'), 60)} por {_t(d.get('SubjectUserName'), 60)}", ev))
        elif log == "Security" and i in (4728, 4732, 4756):
            admin = d.get("TargetSid") == GRUPO_ADMIN
            alertas.append(_alerta("critico" if admin else "aviso", "grupo-alterado",
                                   "Conta adicionada aos ADMINISTRADORES" if admin else "Conta adicionada a um grupo",
                                   f"{_t(d.get('MemberName') or d.get('MemberSid'), 80)} -> {_t(d.get('TargetUserName'), 60)}", ev))
        elif log == "Security" and i == 4740:
            alertas.append(_alerta("aviso", "conta-bloqueada", "Conta bloqueada por demasiadas tentativas", f"Conta {_t(d.get('TargetUserName'), 60)}", ev))
        elif (log == "Security" and i == 1102) or (log == "System" and i == 104):
            alertas.append(_alerta("critico", "registo-apagado", "Um registo de eventos do Windows foi APAGADO",
                                   "Apagar registos e uma tecnica comum para esconder uma intrusao.", ev))
        elif (log == "Security" and i == 4697) or (log == "System" and i == 7045):
            caminho = _t(d.get("ImagePath") or d.get("ServiceFileName"), 200)
            nivel = nivel_caminho(caminho)
            titulo = ("Servico instalado a partir de uma pasta de utilizador (suspeito)" if nivel == "critico"
                      else "Foi instalado um servico novo")
            alertas.append(_alerta(nivel, "servico-instalado", titulo, f"{_t(d.get('ServiceName'), 80)}: {caminho}", ev))
        elif log == "Security" and i == 4698:
            alertas.append(_alerta("aviso", "tarefa-criada", "Foi criada uma tarefa agendada", _t(d.get("TaskName"), 160), ev))
        elif "TerminalServices" in str(log) and i == 1149:
            alertas.append(_alerta("critico", "rdp-autenticado", "Ligacao de Ambiente de Trabalho Remoto autenticada",
                                   f"Utilizador {_t(d.get('Param1'), 60)} a partir de {_t(d.get('Param3'), 60)}", ev))
        elif "Defender" in str(log):
            if i in (1006, 1015, 1116, 1117):
                alertas.append(_alerta("critico", "malware", "Antivirus detetou uma ameaca",
                                       f"{_t(d.get('Threat Name'), 100)} {_t(d.get('Path'), 160)}".strip(), ev))
            elif i in (5001, 5010, 5012):
                alertas.append(_alerta("critico", "defender-desligado", "Protecao do antivirus foi DESLIGADA", "", ev))
            elif i == 5007:
                novo = str(d.get("New Value") or "")
                if "\\Exclusions\\" in novo:
                    alertas.append(_alerta("critico", "defender-exclusao", "Foi adicionada uma EXCLUSAO ao antivirus",
                                           "Malware adiciona exclusoes para nao ser analisado. " + _t(novo, 200), ev))
                elif any(k in novo for k in DEFENDER_CRITICOS) and novo.rstrip().endswith(("= 0x1", "=0x1")):
                    alertas.append(_alerta("critico", "defender-desligado", "Uma protecao do antivirus foi desligada", _t(novo, 200), ev))
        elif "Firewall" in str(log):
            if i in (2004, 2097) and d.get("Direction") == "1" and d.get("Action") == "3":
                try:
                    perfis = int(d.get("Profiles") or 0)
                except ValueError:
                    perfis = 0
                caminho = _t(d.get("ApplicationPath"), 160)
                isolada = not caminho or "\\windowsapps\\" in caminho.lower() or str(d.get("RuleName", "")).startswith("@{")
                if nivel_caminho(caminho) == "critico":
                    nivel = "critico"
                elif isolada:
                    nivel = "info"
                else:
                    nivel = "aviso" if perfis & 4 else "info"
                alertas.append(_alerta(nivel, "firewall-regra", "Nova regra aceita ligacoes de entrada" + (" em redes publicas" if perfis & 4 else ""),
                                       f"{_t(d.get('RuleName'), 100)} {caminho}".strip(), ev))
            elif i == 2003:
                alertas.append(_alerta("aviso", "firewall-perfil", "Definicoes da firewall alteradas", "", ev))
        elif log == "OpenSSH/Operational":
            texto = _t(d.get("_texto"), 300)
            if "Failed" in texto or "Invalid user" in texto:
                alertas.append(_alerta("aviso", "ssh-falhado", "Tentativa de entrada por SSH falhada", texto, ev))
            elif "Accepted" in texto:
                alertas.append(_alerta("critico", "ssh-entrada", "Entrada por SSH aceite", texto, ev))
    for (origem, tipo), lista in falhadas.items():
        lista.sort(key=_hora)
        contas = sorted({_t((e.get("dados") or {}).get("TargetUserName"), 40) for e in lista})
        rajada = any(_hora(lista[k + LIMIAR_FORCA_BRUTA - 1]) - _hora(lista[k]) <= JANELA_FORCA_BRUTA
                     for k in range(len(lista) - LIMIAR_FORCA_BRUTA + 1))
        modo = TIPOS_LOGON.get(tipo, "modo desconhecido")
        if rajada:
            alertas.append(_alerta("critico", "forca-bruta", "Ataque de adivinhacao de palavra-passe",
                                   f"{len(lista)} tentativas falhadas {modo} a partir de {origem}; contas: {', '.join(contas)}",
                                   lista[-1], chave=f"fb:{origem}"))
        else:
            alertas.append(_alerta("aviso", "entrada-falhada", f"{len(lista)} tentativa(s) de entrada falhada(s)",
                                   f"{modo}, a partir de {origem}; contas: {', '.join(contas)}", lista[-1]))
    return alertas


def explicar_inacessiveis(inacessiveis):
    linhas = []
    for item in inacessiveis:
        log, erro = _t(item.get("log"), 80), _t(item.get("erro"), 120)
        if "Unauthorized" in erro:
            linhas.append(f"- {log}: precisa de administrador")
        elif "EventLogNotFound" in erro or "EventLogException" in erro:
            linhas.append(f"- {log}: nao existe neste computador")
        else:
            linhas.append(f"- {log}: nao foi possivel ler ({erro})")
    return linhas
