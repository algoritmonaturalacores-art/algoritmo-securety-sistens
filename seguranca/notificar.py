"""Notificacoes: aviso no ecra do Windows e, opcionalmente, no telemovel via ntfy (desligado por omissao)."""
import re
import secrets
import unicodedata
import urllib.error
import urllib.request

from .ps import PSError, executar

TOAST = r"""
$null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
$null = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
$t = [System.Security.SecurityElement]::Escape($env:AN_TITULO)
$m = [System.Security.SecurityElement]::Escape($env:AN_MENSAGEM)
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml("<toast scenario='reminder'><visual><binding template='ToastGeneric'><text>$t</text><text>$m</text><text>Algoritmo Natural - Securety Sistens</text></binding></visual><actions><action content='OK' arguments='ok' activationType='system'/></actions></toast>")
$app = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show([Windows.UI.Notifications.ToastNotification]::new($xml))
"""

ORDEM = {"info": 0, "aviso": 1, "critico": 2}
PRIORIDADE_NTFY = {"info": "3", "aviso": "4", "critico": "5"}
TOPICO = re.compile(r"[A-Za-z0-9_-]{20,64}")
SERVIDOR = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?")


class SemRedirecionar(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("redirecionamento recusado")


def limpar(texto, limite):
    return "".join(c for c in str(texto) if c.isprintable() and not 0x202A <= ord(c) <= 0x202E)[:limite]


def ascii_simples(texto):
    return unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode("ascii")


def novo_topico():
    """Nome secreto e dificil de adivinhar: quem o souber pode ler as notificacoes."""
    return "an-seg-" + secrets.token_urlsafe(24).replace("-", "x").replace("_", "y")


def notificar_pc(titulo, mensagem):
    try:
        executar(TOAST, timeout=20, json_saida=False,
                 parametros={"AN_TITULO": limpar(titulo, 120), "AN_MENSAGEM": limpar(mensagem, 250)})
        return True
    except PSError:
        return False


def notificar_telemovel(config, titulo, mensagem, nivel="aviso", abridor=None):
    topico, servidor = config.get("ntfy_topico"), (config.get("ntfy_servidor") or "https://ntfy.sh").rstrip("/")
    if not topico:
        return False
    if not TOPICO.fullmatch(str(topico)) or not SERVIDOR.fullmatch(servidor):
        return False
    pedido = urllib.request.Request(f"{servidor}/{topico}", data=limpar(mensagem, 400).encode("utf-8"), method="POST",
                                    headers={"Title": ascii_simples(limpar(titulo, 120)), "Priority": PRIORIDADE_NTFY.get(nivel, "3"),
                                             "Tags": "warning" if nivel != "critico" else "rotating_light",
                                             "User-Agent": "AlgoritmoSecuretySistens/0.2"})
    cliente = abridor or urllib.request.build_opener(SemRedirecionar())
    try:
        with cliente.open(pedido, timeout=10) as resposta:
            return 200 <= getattr(resposta, "status", 200) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def enviar(config, alerta, abridor=None, pc=notificar_pc):
    """Envia se o nivel do alerta atingir o minimo configurado. Nunca inclui palavras-passe ou chaves."""
    minimo = ORDEM.get(config.get("nivel_notificacao", "aviso"), 1)
    nivel = alerta.get("nivel", "info")
    if ORDEM.get(nivel, 0) < minimo:
        return {"pc": False, "telemovel": False}
    prefixo = {"critico": "CRITICO: ", "aviso": "Aviso: "}.get(nivel, "")
    titulo = prefixo + alerta.get("titulo", "Alerta")
    mensagem = alerta.get("detalhe", "") or "Abre o Securety Sistens para ver os detalhes."
    return {"pc": pc(titulo, mensagem) if config.get("notificar_pc", True) else False,
            "telemovel": notificar_telemovel(config, titulo, mensagem, nivel, abridor)}
