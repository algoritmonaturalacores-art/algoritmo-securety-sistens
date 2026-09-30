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
                novos.extend(exposicao.diferencas(base, atual))
                estado["ultima_assinatura"] = atual
        estado["ultima_exposicao"] = time.time()
    registo.guardar_estado({**registo.estado(), **estado})
    registados = []
    for alerta in sorted(novos, key=lambda a: -notificar.ORDEM.get(a.get("nivel"), 0))[:MAX_ALERTAS_POR_CICLO]:
        registados.append(registo.adicionar(alerta))
        if alerta.get("nivel") != "info":
            enviar(config, alerta)
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
