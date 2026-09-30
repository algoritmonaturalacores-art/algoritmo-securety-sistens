"""Fotografia da superficie de ataque do Windows (so leitura) e regras de analise."""
from .ps import PSError, executar

SCRIPT = r"""
$r = [ordered]@{}
function L($n, [scriptblock]$b) { try { $r[$n] = @(& $b) } catch { $r[$n] = [ordered]@{erro=$_.Exception.GetType().Name} } }
function O($n, [scriptblock]$b) { try { $r[$n] = (& $b) } catch { $r[$n] = [ordered]@{erro=$_.Exception.GetType().Name} } }
$remoto = 'teamviewer|anydesk|rustdesk|vnc|splashtop|logmein|screenconnect|connectwise|ammyy|supremo|parsec|remoting_host|atera|meshagent|ngrok|radmin|dwservice|zerotier|tailscale|hamachi|glidex|remotepc|getscreen|aeroadmin|ultraviewer|nomachine|quickassist|chrome remote'
$r.admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
L 'portas' { Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } | ForEach-Object {
  $p = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  [ordered]@{porta=[int]$_.LocalPort; endereco=[string]$_.LocalAddress; processo=[string]$p.ProcessName} } | Sort-Object { $_.porta } -Unique }
O 'rdp' { $ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
  $ra = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -ErrorAction SilentlyContinue
  $nla = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
  [ordered]@{ligado=($ts.fDenyTSConnections -eq 0); assistencia=($ra.fAllowToGetHelp -eq 1); nla=($nla.UserAuthentication -eq 1)} }
L 'servicos' { Get-Service WinRM,sshd,TermService,RemoteRegistry,TlntSvr,SNMP,FTPSVC,W3SVC -ErrorAction SilentlyContinue | ForEach-Object {
  [ordered]@{nome=[string]$_.Name; estado=[string]$_.Status; arranque=[string]$_.StartType} } }
L 'remoto_processos' { Get-Process | Where-Object { $_.ProcessName -match $remoto } | ForEach-Object { [string]$_.ProcessName } | Sort-Object -Unique }
L 'remoto_instalados' { Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*,HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*,HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -match $remoto } | ForEach-Object { [string]$_.DisplayName } | Sort-Object -Unique }
L 'firewall' { Get-NetFirewallProfile | ForEach-Object { [ordered]@{perfil=[string]$_.Name; ligado=[bool]($_.Enabled -eq 'True'); entrada=[string]$_.DefaultInboundAction} } }
L 'regras_publicas' { Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object {
  -not $_.DisplayGroup -and ($_.Profile.ToString() -match 'Public|Any') } | ForEach-Object {
  [ordered]@{id=[string]$_.Name; nome=[string]$_.DisplayName; perfis=$_.Profile.ToString()} } }
L 'redes' { Get-NetConnectionProfile | ForEach-Object { [ordered]@{nome=[string]$_.Name; categoria=[string]$_.NetworkCategory} } }
L 'contas' { Get-LocalUser | ForEach-Object { [ordered]@{nome=[string]$_.Name; ativa=[bool]$_.Enabled; exige_password=[bool]$_.PasswordRequired;
  rid=[int]($_.SID.Value.Split('-')[-1]); ultimo=$(if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { $null })} } }
L 'administradores' { Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [string]$_.Name } }
O 'smb' { $c = Get-SmbServerConfiguration
  [ordered]@{smb1=[bool]$c.EnableSMB1Protocol; partilhas=@(Get-SmbShare | Where-Object { -not $_.Special } | ForEach-Object { [string]$_.Name })} }
O 'politicas' { $s = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $l = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  [ordered]@{uac=($s.EnableLUA -ne 0); uac_pedido=[int]$s.ConsentPromptBehaviorAdmin; bloqueia_password_vazia=($l.LimitBlankPasswordUse -ne 0); lsa_protegida=($l.RunAsPPL -ge 1)} }
O 'defender' { $m = Get-MpComputerStatus; $p = Get-MpPreference
  [ordered]@{ativo=[bool]$m.AntivirusEnabled; tempo_real=[bool]$m.RealTimeProtectionEnabled; anti_adulteracao=[bool]$m.IsTamperProtected;
  desatualizado=[bool]$m.DefenderSignaturesOutOfDate; pua=[int]$p.PUAProtection; protecao_rede=[int]$p.EnableNetworkProtection; pastas_controladas=[int]$p.EnableControlledFolderAccess} }
L 'arranque' { foreach ($k in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') {
  $i = Get-ItemProperty $k -ErrorAction SilentlyContinue
  if ($i) { $i.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { ($k.Split(':')[0]) + '\' + $_.Name } } } }
L 'tarefas' { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' -and $_.State -ne 'Disabled' } | ForEach-Object { [string]($_.TaskPath + $_.TaskName) } }
O 'secureboot' { [bool](Confirm-SecureBootUEFI) }
O 'bitlocker' { [string](Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus }
O 'ultima_atualizacao' { $h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
  if ($h) { $h.InstalledOn.ToUniversalTime().ToString('o') } else { $null } }
$r | ConvertTo-Json -Depth 5 -Compress
"""

PROCESSOS_SISTEMA = {"System", "svchost", "lsass", "wininit", "services", "spoolsv", "Idle"}
PESO = {"critico": 20, "aviso": 5, "info": 0}


def recolher(timeout=120):
    try:
        dados = executar(SCRIPT, timeout=timeout)
    except PSError as erro:
        return {"erro_geral": str(erro)}
    return dados if isinstance(dados, dict) else {"erro_geral": "Resposta vazia."}


def _lista(dados, chave):
    valor = dados.get(chave)
    return valor if isinstance(valor, list) else []


def _dic(dados, chave):
    valor = dados.get(chave)
    return valor if isinstance(valor, dict) and "erro" not in valor else None


def _txt(valor, limite=120):
    return "".join(c for c in str(valor) if c.isprintable())[:limite]


def achado(nivel, codigo, titulo, detalhe, recomendacao, acao=None):
    return {"nivel": nivel, "codigo": codigo, "titulo": titulo, "detalhe": detalhe,
            "recomendacao": recomendacao, "acao": acao}


def analisar(dados):
    """Regras deterministicas. Informacao em falta nunca e tratada como segura."""
    a = []
    if "erro_geral" in dados:
        return [achado("aviso", "sem-dados", "Nao foi possivel analisar o computador", _txt(dados["erro_geral"]),
                       "Tenta de novo ou abre o programa como administrador.")]
    rdp = _dic(dados, "rdp")
    if rdp is None:
        a.append(achado("aviso", "rdp-desconhecido", "Estado do Ambiente de Trabalho Remoto desconhecido", "", "Verifica em Definicoes > Sistema > Ambiente de Trabalho Remoto."))
    else:
        if rdp.get("ligado"):
            nivel = "aviso" if rdp.get("nla") else "critico"
            a.append(achado(nivel, "rdp-ligado", "Ambiente de Trabalho Remoto LIGADO",
                            "Qualquer pessoa na rede pode tentar entrar com utilizador e palavra-passe." + ("" if rdp.get("nla") else " Sem autenticacao previa (NLA)."),
                            "Desliga se nao usas.", "rdp"))
        if rdp.get("assistencia"):
            a.append(achado("aviso", "assistencia", "Assistencia Remota permitida", "Permite convites de ajuda remota.",
                            "Desliga se nao usas.", "assistencia"))
    for s in _lista(dados, "servicos"):
        if not isinstance(s, dict) or s.get("estado") != "Running":
            continue
        nome = _txt(s.get("nome"))
        nivel = "critico" if nome in ("TlntSvr", "FTPSVC") else "aviso"
        if nome == "TermService" and rdp and not rdp.get("ligado"):
            continue
        a.append(achado(nivel, "servico-" + nome, f"Servico de acesso remoto a correr: {nome}",
                        "Aceita ligacoes vindas de outros computadores.", "Para e desativa o servico se nao o usas.",
                        "remoteregistry" if nome == "RemoteRegistry" else None))
    remotos = [_txt(n, 60) for n in _lista(dados, "remoto_processos")]
    if remotos:
        a.append(achado("aviso", "remoto-ativo", "Programa de controlo remoto a correr",
                        ", ".join(remotos) + ". Programas deste tipo deixam outra pessoa ver ou controlar o ecra.",
                        "Se nao o instalaste tu ou nao usas, desinstala-o."))
    instalados = [_txt(n, 60) for n in _lista(dados, "remoto_instalados")]
    if instalados:
        a.append(achado("info", "remoto-instalado", "Programas de acesso remoto instalados", ", ".join(instalados),
                        "Confirma que foste tu a instala-los."))
    por_processo = {}
    for p in _lista(dados, "portas"):
        if isinstance(p, dict):
            por_processo.setdefault(_txt(p.get("processo"), 60) or "desconhecido", []).append(str(p.get("porta")))
    for proc, portas in sorted(por_processo.items()):
        if proc in PROCESSOS_SISTEMA:
            continue
        a.append(achado("aviso", "portas-" + proc, f"{proc} tem {len(portas)} porta(s) aberta(s) a rede",
                        "Portas: " + ", ".join(portas[:20]) + ". Este programa aceita ligacoes de outros aparelhos.",
                        "Confirma que e um programa teu; se nao for preciso, desinstala-o ou bloqueia-o na firewall."))
    fw = _lista(dados, "firewall")
    if not fw:
        a.append(achado("aviso", "firewall-desconhecida", "Estado da firewall desconhecido", "", "Verifica em Seguranca do Windows."))
    for perfil in fw:
        if not isinstance(perfil, dict):
            continue
        if not perfil.get("ligado"):
            a.append(achado("critico", "firewall-" + _txt(perfil.get("perfil")), f"Firewall DESLIGADA no perfil {_txt(perfil.get('perfil'))}",
                            "Todas as portas ficam expostas.", "Liga a firewall.", "firewall"))
        elif perfil.get("entrada") == "Allow":
            a.append(achado("critico", "firewall-allow-" + _txt(perfil.get("perfil")), f"Firewall aceita entradas por omissao ({_txt(perfil.get('perfil'))})",
                            "", "Muda para bloquear entradas por omissao.", "firewall"))
    for regra in _lista(dados, "regras_publicas"):
        if isinstance(regra, dict):
            a.append(achado("aviso", "regra-" + _txt(regra.get("id"), 80), f"Regra da firewall aceita entradas em redes publicas: {_txt(regra.get('nome'))}",
                            "Em cafes, hoteis ou aeroportos, outros aparelhos podem ligar-se a este programa.",
                            "Retira o perfil Publico a esta regra.", "regras-publicas"))
    for conta in _lista(dados, "contas"):
        if not isinstance(conta, dict) or not conta.get("ativa"):
            continue
        nome = _txt(conta.get("nome"), 60)
        if conta.get("rid") == 501:
            a.append(achado("critico", "convidado", "Conta Convidado ATIVA", "", "Desativa a conta Convidado.", "convidado"))
        elif conta.get("rid") == 500:
            a.append(achado("aviso", "admin-integrado", "Conta Administrador integrada ativa", "E um alvo conhecido de ataques.", "Desativa-a se nao usas."))
        if not conta.get("exige_password") and not str(nome).startswith("CodexSandbox"):
            a.append(achado("aviso", "sem-password-" + nome, f"Conta '{nome}' pode nao ter palavra-passe",
                            "Contas locais sem palavra-passe sao faceis de usar por outra pessoa.", "Define uma palavra-passe forte (Ctrl+Alt+Del > Alterar palavra-passe)."))
    admins = _lista(dados, "administradores")
    if len(admins) > 2:
        a.append(achado("info", "admins", f"{len(admins)} contas com privilegios de administrador", ", ".join(_txt(x, 60) for x in admins),
                        "Confirma que conheces todas."))
    smb = _dic(dados, "smb")
    if smb and smb.get("smb1"):
        a.append(achado("critico", "smb1", "Protocolo SMB1 ligado", "Protocolo antigo usado pelo WannaCry.", "Desliga o SMB1.", "smb1"))
    if smb and smb.get("partilhas"):
        a.append(achado("info", "partilhas", "Pastas partilhadas na rede", ", ".join(_txt(x, 40) for x in smb["partilhas"]), "Confirma que sao intencionais."))
    pol = _dic(dados, "politicas")
    if pol:
        if not pol.get("uac"):
            a.append(achado("critico", "uac", "Controlo de Conta de Utilizador (UAC) desligado", "Programas ganham administrador sem aviso.", "Liga o UAC."))
        elif pol.get("uac_pedido") == 0:
            a.append(achado("aviso", "uac-silencioso", "UAC nao pede confirmacao", "", "Repoe o UAC para pedir confirmacao."))
        if not pol.get("bloqueia_password_vazia"):
            a.append(achado("critico", "password-vazia-rede", "Contas sem palavra-passe aceites pela rede", "", "Repoe LimitBlankPasswordUse=1."))
    d = _dic(dados, "defender")
    if d is None:
        a.append(achado("aviso", "defender-desconhecido", "Estado do Defender desconhecido", "Pode haver outro antivirus ativo.", "Verifica em Seguranca do Windows."))
    else:
        if not d.get("tempo_real"):
            a.append(achado("critico", "defender-rt", "Protecao em tempo real DESLIGADA", "", "Liga a protecao em tempo real."))
        if not d.get("anti_adulteracao"):
            a.append(achado("aviso", "defender-tamper", "Protecao contra adulteracao desligada", "Malware pode desligar o antivirus.", "Liga em Seguranca do Windows > Protecao contra virus."))
        if d.get("desatualizado"):
            a.append(achado("aviso", "defender-assinaturas", "Assinaturas do antivirus desatualizadas", "", "Executa o Windows Update."))
        if d.get("pua") != 1:
            a.append(achado("aviso", "defender-pua", "Bloqueio de aplicacoes potencialmente indesejadas desligado", "", "Liga o bloqueio PUA.", "defender"))
        if d.get("protecao_rede") != 1:
            a.append(achado("info", "defender-rede", "Protecao de rede do Defender desligada", "Bloqueia ligacoes a sites maliciosos.", "Liga a protecao de rede.", "defender"))
    sb = dados.get("secureboot")
    if sb is False:
        a.append(achado("aviso", "secureboot", "Arranque Seguro (Secure Boot) desligado", "", "Liga no firmware (BIOS/UEFI)."))
    bl = dados.get("bitlocker")
    if isinstance(bl, str) and bl == "Off":
        a.append(achado("aviso", "bitlocker", "Disco do sistema sem encriptacao BitLocker", "Se o portatil for roubado, os dados podem ser lidos.", "Ativa o BitLocker."))
    if isinstance(bl, dict) or isinstance(sb, dict):
        a.append(achado("info", "precisa-admin", "Algumas verificacoes precisam de administrador", "Secure Boot e BitLocker nao foram lidos.", "Abre o programa como administrador."))
    return sorted(a, key=lambda x: -PESO[x["nivel"]])


def pontuacao(achados):
    return max(0, 100 - sum(PESO[x["nivel"]] for x in achados))


def assinatura(dados):
    """Conjuntos comparaveis para detetar alteracoes entre fotografias."""
    def conjunto(chave, campo=None):
        itens = _lista(dados, chave)
        return sorted({_txt(i.get(campo) if campo and isinstance(i, dict) else i, 160) for i in itens})
    rdp = _dic(dados, "rdp") or {}
    return {
        "portas": sorted({f"{p.get('porta')}/{_txt(p.get('processo'), 60)}" for p in _lista(dados, "portas") if isinstance(p, dict)}),
        "regras_publicas": conjunto("regras_publicas", "nome"),
        "remoto": sorted(set(conjunto("remoto_processos")) | set(conjunto("remoto_instalados"))),
        "contas": sorted({_txt(c.get("nome"), 60) for c in _lista(dados, "contas") if isinstance(c, dict) and c.get("ativa")}),
        "administradores": conjunto("administradores"),
        "arranque": conjunto("arranque"),
        "tarefas": conjunto("tarefas"),
        "servicos_ativos": sorted({_txt(s.get("nome")) for s in _lista(dados, "servicos") if isinstance(s, dict) and s.get("estado") == "Running"}),
        "rdp": ["ligado"] if rdp.get("ligado") else [],
    }


NIVEL_NOVO = {"administradores": "critico", "contas": "critico", "remoto": "critico", "rdp": "critico",
              "portas": "aviso", "regras_publicas": "aviso", "arranque": "aviso", "tarefas": "aviso", "servicos_ativos": "aviso"}
NOMES = {"portas": "Nova porta aberta a rede", "regras_publicas": "Nova regra da firewall para redes publicas",
         "remoto": "Novo programa de controlo remoto", "contas": "Nova conta de utilizador ativa",
         "administradores": "Nova conta com privilegios de administrador", "arranque": "Novo programa no arranque do Windows",
         "tarefas": "Nova tarefa agendada", "servicos_ativos": "Novo servico de acesso remoto ativo", "rdp": "Ambiente de Trabalho Remoto foi LIGADO"}


def diferencas(base, atual):
    """Compara duas assinaturas. Devolve alertas para itens novos (removidos sao informativos)."""
    alertas = []
    for chave, nivel in NIVEL_NOVO.items():
        antes, depois = set(base.get(chave, [])), set(atual.get(chave, []))
        for item in sorted(depois - antes):
            alertas.append({"nivel": nivel, "tipo": "alteracao-" + chave, "titulo": NOMES[chave], "detalhe": item})
        for item in sorted(antes - depois):
            alertas.append({"nivel": "info", "tipo": "removido-" + chave, "titulo": "Removido: " + NOMES[chave].lower(), "detalhe": item})
    return alertas
