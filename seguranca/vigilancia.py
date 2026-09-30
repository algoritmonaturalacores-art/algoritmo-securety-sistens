"""Vigilancia continua: le eventos novos, compara com a linha de base, regista e notifica."""
import time
from datetime import datetime, timedelta, timezone

from . import eventos, exposicao, notificar
from .registo import Registo, RegistoError

INTERVALO_EXPOSICAO = 600
MAX_ALERTAS_POR_CICLO = 50


def _agora():
    return datetime.now(timezone.utc)


def ciclo(registo, config, forcar_exposicao=False, ler_eventos=eventos.ler, recolher=exposicao.recolher, enviar=notificar.enviar):
    """Um ciclo. Devolve a lista de alertas novos registados."""
    estado = registo.estado()
    novos = []
    ok, onde = registo.verificar_cadeia()
    if not ok and not estado.get("adulteracao_avisada"):
        novos.append({"nivel": "critico", "tipo": "registo-adulterado", "titulo": "O registo de alertas foi alterado ou apagado",
                      "detalhe": f"A cadeia de verificacao quebrou no registo {onde}. Alguem pode estar a esconder vestigios."})
        estado["adulteracao_avisada"] = True
    try:
        desde = datetime.fromisoformat(estado["ultimo_evento"])
    except (KeyError, ValueError):
        desde = _agora() - timedelta(hours=1)
    fim = _agora()
    lidos = ler_eventos(desde)
    vistos = set(estado.get("registos_vistos", []))
    frescos = [e for e in lidos["eventos"] if f"{e.get('log')}#{e.get('registo')}" not in vistos]
    novos.extend(eventos.analisar(frescos))
    inacessiveis = sorted({i.get("log") for i in lidos["inacessiveis"] if "Unauthorized" in str(i.get("erro"))})
    if inacessiveis and not estado.get("aviso_admin"):
        novos.append({"nivel": "aviso", "tipo": "sem-admin", "titulo": "Vigilancia sem acesso ao registo de Seguranca",
                      "detalhe": "Tentativas de entrada so sao detetadas com a vigilancia protegida (administrador)."})
        estado["aviso_admin"] = True
    # Se a leitura falhou por completo (ex.: PowerShell demorou demais), a janela de tempo nao avanca:
    # o proximo ciclo volta a ler estes minutos em vez de os perder.
    falhou_tudo = any(i.get("log") == "todos" for i in lidos["inacessiveis"])
    if not falhou_tudo:
        estado["ultimo_evento"] = (fim - timedelta(seconds=5)).isoformat()
        estado["registos_vistos"] = [f"{e.get('log')}#{e.get('registo')}" for e in lidos["eventos"]][-2000:]
    ultima = estado.get("ultima_exposicao", 0)
    if forcar_exposicao or time.time() - ultima >= INTERVALO_EXPOSICAO:
        dados = recolher()
        if "erro_geral" not in dados:
            atual = exposicao.assinatura(dados)
            base = registo.linha_base().get("assinatura")
            if base is None:
                registo.aceitar_linha_base(atual)
            else:
                # Compara com a ultima fotografia (nao so com a linha de base): cada alteracao alerta uma vez,
                # em vez de repetir a cada 10 minutos ate ser aceite.
                anterior = estado.get("ultima_assinatura") or base
                novos.extend(exposicao.diferencas(anterior, atual))
                estado["ultima_assinatura"] = atual
        estado["ultima_exposicao"] = time.time()
    registo.atualizar_estado(estado)
    # Todos os alertas ficam registados; so as notificacoes sao limitadas, para nao inundar o ecra.
    registados = []
    for posicao, alerta in enumerate(sorted(novos, key=lambda a: -notificar.ORDEM.get(a.get("nivel"), 0))):
        registados.append(registo.adicionar(alerta))
        if alerta.get("nivel") != "info" and posicao < MAX_ALERTAS_POR_CICLO:
            enviar(config, alerta)
    if len(novos) > MAX_ALERTAS_POR_CICLO:
        enviar(config, {"nivel": "critico", "titulo": f"{len(novos)} alertas num so ciclo",
                        "detalhe": "Atividade invulgar. Abre o Securety Sistens para ver todos."})
    return registados


def vigiar(registo=None, parar=None, saida=print):
    registo = registo or Registo()
    config = registo.config()
    intervalo = max(30, int(config.get("intervalo_segundos", 60)))
    saida(f"Vigilancia ativa (cada {intervalo} s). Estado em {registo.pasta}. Ctrl+C para parar.")
    primeira = True
    while not (parar and parar()):
        try:
            for a in ciclo(registo, config, forcar_exposicao=primeira):
                saida(f"[{a['nivel'].upper()}] {a['titulo']} - {a['detalhe'][:150]}")
        except RegistoError as erro:
            saida(str(erro))
        primeira = False
        time.sleep(intervalo)
