"""Algoritmo Securety Sistens - Nuno Camara | Algoritmo Natural.
Menu de consola para Windows. Python 3.10+; sem pacotes externos."""
import argparse
import getpass
import json
import sys
import time
import warnings
from datetime import datetime, timedelta, timezone
from pathlib import Path

from seguranca import VERSION, endurecer, eventos, exposicao, notificar, tarefa, vigilancia
from seguranca.agentes import AGENTS, messages_for
from seguranca.api import APIError, MODEL, ask, safe_text
from seguranca.diagnostico import collect, explain
from seguranca.ps import e_admin
from seguranca.registo import Registo, RegistoError, validar_palavra_passe

ROOT = Path(__file__).resolve().parent
ASSINATURA = "Nuno Camara | Algoritmo Natural - Sustentabilidade Digital"
TENTATIVAS_POR_SESSAO = 5
CHECKS = [
    ("Eventos recentes", "https://myaccount.google.com/notifications"),
    ("Dispositivos ligados", "https://myaccount.google.com/device-activity"),
    ("Recuperacao e verificacao em dois passos", "https://myaccount.google.com/security"),
    ("Aplicacoes com acesso", "https://myaccount.google.com/connections"),
    ("Ajuda para conta comprometida", "https://support.google.com/accounts/answer/6294825"),
]
ICONE = {"critico": "[!!!]", "aviso": "[ ! ]", "info": "[ i ]"}


def ler_segredo(pergunta):
    # Falha fechada: nunca mostrar o segredo quando nao existe terminal seguro.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(pergunta)


def confirmar(pergunta):
    return input(pergunta + " Escreve SIM para confirmar: ").strip() == "SIM"


# ---------------- acesso ----------------
def configurar_acesso(registo):
    print("\nPrimeira utilizacao: define a palavra-passe deste programa.")
    print("Protege os alertas, a marcacao e as alteracoes ao Windows contra quem use o teu PC.")
    while True:
        palavra = ler_segredo("Nova palavra-passe (10+ caracteres): ")
        erro = validar_palavra_passe(palavra)
        if erro:
            print(erro)
            continue
        if ler_segredo("Repete a palavra-passe: ") != palavra:
            print("Nao coincidem.")
            continue
        registo.definir_palavra_passe(palavra)
        print("Palavra-passe definida. Guarda-a num gestor de palavras-passe.")
        return True


def entrar(registo):
    try:
        if not registo.acesso_configurado():
            return configurar_acesso(registo)
    except RegistoError as erro:
        print(erro)
        return False
    for tentativa in range(1, TENTATIVAS_POR_SESSAO + 1):
        palavra = ler_segredo("Palavra-passe do Securety Sistens: ")
        try:
            ok, mensagem = registo.verificar_palavra_passe(palavra)
        except RegistoError:
            ok, mensagem = False, "Nao foi possivel verificar (sem permissao de escrita)."
        if ok:
            return True
        print(mensagem)
        try:
            registo.adicionar({"nivel": "aviso", "tipo": "login-programa", "titulo": "Palavra-passe errada no Securety Sistens",
                               "detalhe": f"Tentativa {tentativa} neste computador."})
        except RegistoError:
            pass
        if "Bloqueado" in mensagem:
            return False
        time.sleep(2 * tentativa)
    return False


# ---------------- funcoes do menu ----------------
def google_checklist():
    print("\nRevisao manual: o programa nao entra na conta Google.")
    for label, url in CHECKS:
        print(f"- {label}: {url}")
    print("Abre os enderecos num dispositivo de confianca. Nao partilhes passwords ou codigos.")


def mostrar_exposicao():
    print("A analisar o computador (ate 2 minutos)...")
    dados = exposicao.recolher()
    achados = exposicao.analisar(dados)
    print(f"\nPONTUACAO DE EXPOSICAO: {exposicao.pontuacao(achados)}/100  (100 = nada encontrado)")
    if not dados.get("admin"):
        print("Nota: sem administrador algumas verificacoes nao sao possiveis.")
    for a in achados:
        print(f"\n{ICONE[a['nivel']]} {a['titulo']}")
        if a["detalhe"]:
            print("      " + a["detalhe"])
        print("      O que fazer: " + a["recomendacao"] + (f"  (menu Endurecer: {a['acao']})" if a["acao"] else ""))
    return dados, achados


def mostrar_tentativas(registo):
    dias = input("Quantos dias para tras? (Enter = 7): ").strip()
    dias = int(dias) if dias.isdigit() and 0 < int(dias) <= 90 else 7
    print("A ler os registos do Windows...")
    lidos = eventos.ler(datetime.now(timezone.utc) - timedelta(days=dias), maximo=500)
    alertas = [a for a in eventos.analisar(lidos["eventos"]) if a["nivel"] != "info"]
    print(f"\n{len(alertas)} ocorrencia(s) relevante(s) nos ultimos {dias} dias.")
    for a in sorted(alertas, key=lambda x: x.get("hora_evento") or ""):
        rep = f" (x{a['repeticoes']})" if a.get("repeticoes", 1) > 1 else ""
        print(f"{ICONE[a['nivel']]} {(a.get('hora_evento') or '')[:16].replace('T', ' ')} {a['titulo']}{rep}\n      {a['detalhe'][:200]}")
    for linha in eventos.explicar_inacessiveis(lidos["inacessiveis"]):
        print("Nao lido " + linha)
    if alertas and input("\nGuardar estas ocorrencias no registo de alertas? (s/N): ").strip().lower() == "s":
        for a in alertas:
            registo.adicionar(a)
        print("Guardadas.")


def gerir_alertas(registo):
    ok, onde = registo.verificar_cadeia()
    print("\nIntegridade do registo: " + ("intacta" if ok else f"ALTERADA a partir do registo {onde} - possivel adulteracao!"))
    alertas = registo.listar()
    novos = [a for a in alertas if a["estado"] == "novo"]
    print(f"{len(alertas)} alertas guardados, {len(novos)} por rever.")
    for a in (novos or alertas)[-30:]:
        print(f"#{a['id']:>4} {ICONE.get(a['nivel'], '')} [{a['estado']}] {a['registado'][:16].replace('T', ' ')} {a['titulo']}\n       {a['detalhe'][:160]}")
    print("\nMarcar: 'v 3 4' = visto | 'c 3' = conhecido (fui eu) | 's 3' = suspeito | 'v todos' | Enter = voltar")
    comando = input("> ").strip().split()
    if len(comando) < 2 or comando[0] not in ("v", "c", "s"):
        return
    estado = {"v": "visto", "c": "conhecido", "s": "suspeito"}[comando[0]]
    ids = [a["id"] for a in novos] if comando[1] == "todos" else [int(x) for x in comando[1:] if x.isdigit()]
    print(f"{registo.marcar(ids, estado)} alerta(s) marcados como {estado}.")
    if estado == "conhecido" and confirmar("Aceitar o estado atual do PC como normal (nova linha de base)?"):
        registo.aceitar_linha_base(exposicao.assinatura(exposicao.recolher()))
        print("Linha de base atualizada.")


def menu_endurecer():
    if not e_admin():
        print("\nPara alterar o Windows abre o programa como administrador.")
        print("Mesmo assim, eis o que seria proposto:")
    dados, achados = mostrar_exposicao()
    propostas = ["auditoria", "bloqueio", "firewall", "defender"]
    for a in achados:
        if a["acao"] and a["acao"] not in propostas and a["acao"] != "regras-publicas":
            propostas.append(a["acao"])
    print("\nALTERACOES PROPOSTAS (cada uma pede confirmacao):")
    for codigo in propostas:
        titulo, descricao, _ = endurecer.ACOES[codigo]
        print(f"\n* {titulo}\n  {descricao}")
        if e_admin() and confirmar("  Aplicar?"):
            try:
                endurecer.aplicar(codigo, True)
                print("  Aplicado.")
            except endurecer.EndurecerError as erro:
                print("  Falhou: " + str(erro))
    regras = dados.get("regras_publicas") if isinstance(dados.get("regras_publicas"), list) else []
    for regra in regras:
        print(f"\n* Retirar redes publicas da regra: {regra.get('nome')}")
        if e_admin() and confirmar("  Aplicar?"):
            try:
                endurecer.retirar_perfil_publico(regra.get("id"), True)
                print("  Aplicado.")
            except endurecer.EndurecerError as erro:
                print("  Falhou: " + str(erro))


def menu_notificacoes(registo):
    config = registo.config()
    print(f"\nAviso no ecra do PC: {'ligado' if config['notificar_pc'] else 'desligado'}")
    print(f"Telemovel (ntfy): {'ligado' if config['ntfy_topico'] else 'desligado'}")
    print(f"Nivel minimo: {config['nivel_notificacao']}")
    print("\n1. Testar notificacao\n2. Ligar telemovel\n3. Desligar telemovel\n4. Mudar nivel minimo\nEnter = voltar")
    escolha = input("> ").strip()
    if escolha == "1":
        r = notificar.enviar(dict(config, nivel_notificacao="info"),
                             {"nivel": "aviso", "titulo": "Teste de notificacao", "detalhe": "Se estas a ver isto, as notificacoes funcionam."})
        print(f"PC: {'enviado' if r['pc'] else 'falhou/desligado'} | Telemovel: {'enviado' if r['telemovel'] else 'falhou/desligado'}")
    elif escolha == "2":
        topico = notificar.novo_topico()
        print("\n1) Instala a app 'ntfy' no telemovel (Google Play / F-Droid / App Store).")
        print("2) Na app, carrega em + e subscreve este topico (e secreto, nao o partilhes):")
        print("\n   " + topico + "\n")
        print("Os alertas vao pelo servidor publico ntfy.sh: so titulo e resumo, nunca palavras-passe.")
        if confirmar("Ativar?"):
            config["ntfy_topico"] = topico
            registo.guardar_config(config)
            notificar.enviar(dict(config, nivel_notificacao="info"),
                             {"nivel": "aviso", "titulo": "Telemovel ligado", "detalhe": "Vais receber aqui os alertas do teu PC."})
    elif escolha == "3":
        config["ntfy_topico"] = None
        registo.guardar_config(config)
    elif escolha == "4":
        nivel = input("aviso ou critico? ").strip()
        if nivel in ("aviso", "critico"):
            config["nivel_notificacao"] = nivel
            registo.guardar_config(config)


def menu_tarefa():
    e = tarefa.estado()
    print(f"\nVigilancia automatica: {'instalada (' + str(e.get('estado')) + ')' if e.get('existe') else 'nao instalada'}")
    print("Corre em segundo plano ao iniciar sessao, com privilegios, a partir de uma pasta protegida.")
    for problema in tarefa.verificar_requisitos():
        print("Requisito: " + problema)
    escolha = input("1. Instalar/atualizar  2. Remover  Enter = voltar\n> ").strip()
    try:
        if escolha == "1" and confirmar("Instalar a vigilancia automatica?"):
            destino, estado = tarefa.instalar(ROOT)
            print(f"Instalada em {destino}. Alertas guardados em {estado}.")
        elif escolha == "2" and confirmar("Remover a vigilancia automatica?"):
            tarefa.remover()
            print("Removida. Os alertas guardados foram mantidos.")
    except tarefa.TarefaError as erro:
        print("Nao foi possivel: " + str(erro))


def run_agent(diagnostic):
    ids = list(AGENTS)
    for index, agent_id in enumerate(ids, 1):
        print(f"{index}. {AGENTS[agent_id][0]}")
    selected = input("Agente (Enter cancela): ").strip()
    if not selected.isdigit() or not 1 <= int(selected) <= len(ids):
        return
    agent_id = ids[int(selected) - 1]
    messages = messages_for(agent_id, diagnostic)
    print(f"\nFornecedor: Groq | Modelo: {MODEL}")
    print("Usa uma conta Groq no plano Free, sem upgrade pago. A aplicacao nao consegue verificar a faturacao.")
    print("Limites e acesso: https://console.groq.com/docs/rate-limits")
    print("Chave: https://console.groq.com/keys | Privacidade: https://console.groq.com/docs/your-data")
    print("Uma chamada; sem repeticao automatica. A chave fica apenas na memoria desta chamada.")
    print("\nConteudo EXATO a enviar (a chave e enviada apenas como credencial HTTPS):")
    for item in messages:
        print("\n" + item["role"] + ":\n" + item["content"])
    if input("\nConfirmaste o plano Free e queres enviar este conteudo? Escreve ENVIAR: ").strip() != "ENVIAR":
        print("Cancelado. Nenhum pedido enviado.")
        return
    key = None
    try:
        key = ler_segredo("Chave Groq (nao aparece nem e guardada): ").strip()
        print("A consultar o agente...")
        answer = ask(key, messages)
        print("\nRESPOSTA IA - orientacao nao verificada; nenhuma acao executada.\n")
        print(safe_text(answer))
    except getpass.GetPassWarning:
        print("Nao foi possivel ocultar a chave. Usa INICIAR.cmd numa consola Windows.")
    except APIError as error:
        print(str(error))
    finally:
        key = None


def menu(registo):
    diagnostic = None
    while True:
        print(f"\nALGORITMO SECURETY SISTENS {VERSION}   {'[administrador]' if e_admin() else '[utilizador normal]'}")
        print(ASSINATURA)
        print("Detecao de intrusoes e endurecimento do Windows. Complementa o antivirus; nao o substitui.")
        print("\n1. Quem consegue entrar neste PC? (analise de exposicao)"
              "\n2. Tentativas de entrada e alteracoes suspeitas (registos do Windows)"
              "\n3. Alertas guardados e marcacao"
              "\n4. Vigiar agora (fica a correr; Ctrl+C para parar)"
              "\n5. Endurecer o Windows (administrador)"
              "\n6. Notificacoes no PC e no telemovel"
              "\n7. Vigilancia automatica ao iniciar sessao"
              "\n8. Estado rapido do Defender e firewall"
              "\n9. Rever conta Google"
              "\n10. Consultar agente IA (Groq Free, opcional)"
              "\n0. Sair")
        choice = input("Escolha: ").strip()
        try:
            if choice == "0":
                return
            elif choice == "1":
                mostrar_exposicao()
            elif choice == "2":
                mostrar_tentativas(registo)
            elif choice == "3":
                gerir_alertas(registo)
            elif choice == "4":
                try:
                    vigilancia.vigiar(registo)
                except KeyboardInterrupt:
                    print("\nVigilancia parada.")
            elif choice == "5":
                menu_endurecer()
            elif choice == "6":
                menu_notificacoes(registo)
            elif choice == "7":
                menu_tarefa()
            elif choice == "8":
                print("A consultar o Windows; pode demorar ate 25 segundos...")
                diagnostic = collect()
                print(explain(diagnostic))
            elif choice == "9":
                google_checklist()
            elif choice == "10":
                run_agent(diagnostic)
            else:
                print("Escolha uma opcao apresentada.")
        except RegistoError as erro:
            print(str(erro))


def main():
    parser = argparse.ArgumentParser(description="Algoritmo Securety Sistens - " + ASSINATURA)
    parser.add_argument("--diagnostico", action="store_true", help="Estado Defender/firewall em JSON, sem guardar")
    parser.add_argument("--exposicao", action="store_true", help="Analise de exposicao em JSON, sem guardar")
    parser.add_argument("--vigiar", action="store_true", help="Vigilancia continua (usado pela tarefa agendada)")
    parser.add_argument("--verificar", action="store_true", help="Verifica ficheiros essenciais sem rede")
    args = parser.parse_args()
    if args.verificar:
        for name in ("INICIAR.cmd", "INSTALAR.cmd", "instalar.py", "LE-ME-PRIMEIRO.txt", "LICENSE"):
            if not (ROOT / name).is_file():
                raise SystemExit("Ficheiro em falta: " + name)
        print(f"Estrutura {VERSION} OK. {len(AGENTS)} agentes definidos. Nenhuma chamada API efetuada.")
    elif args.diagnostico:
        print(json.dumps(collect(), ensure_ascii=False, indent=2))
    elif args.exposicao:
        dados = exposicao.recolher()
        achados = exposicao.analisar(dados)
        print(json.dumps({"pontuacao": exposicao.pontuacao(achados), "achados": achados}, ensure_ascii=False, indent=2))
    elif args.vigiar:
        vigilancia.vigiar(Registo())
    else:
        registo = Registo()
        if not entrar(registo):
            print("Acesso recusado.")
            sys.exit(2)
        menu(registo)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nPrograma terminado.")
    except getpass.GetPassWarning:
        print("Nao foi possivel ocultar a palavra-passe. Usa INICIAR.cmd numa consola Windows.")
        sys.exit(1)
    except OSError:
        print("Nao foi possivel aceder a um recurso local. Verifica permissoes e ficheiros.")
        sys.exit(1)
