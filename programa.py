"""Menu de consola para Windows. Python 3.10+; sem pacotes externos."""
import argparse
import getpass
import json
import sys
import warnings
from pathlib import Path

from seguranca import VERSION
from seguranca.agentes import AGENTS, messages_for
from seguranca.api import APIError, MODEL, ask, safe_text
from seguranca.diagnostico import collect, explain

ROOT = Path(__file__).resolve().parent
CHECKS = [
    ("Eventos recentes", "https://myaccount.google.com/notifications"),
    ("Dispositivos ligados", "https://myaccount.google.com/device-activity"),
    ("Recuperacao e verificacao em dois passos", "https://myaccount.google.com/security"),
    ("Aplicacoes com acesso", "https://myaccount.google.com/connections"),
    ("Ajuda para conta comprometida", "https://support.google.com/accounts/answer/6294825"),
]


def google_checklist():
    print("\nRevisao manual: o programa nao entra na conta Google.")
    for label, url in CHECKS:
        print(f"- {label}: {url}")
    print("Abre os enderecos num dispositivo de confianca. Nao partilhes passwords ou codigos.")


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
        # Fail closed rather than echoing the key when no secure terminal exists.
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            key = getpass.getpass("Chave Groq (nao aparece nem e guardada): ").strip()
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


def menu():
    diagnostic = None
    while True:
        print(f"\nALGORITMO SECURETY SISTENS {VERSION}")
        print("Nuno Camara Freelancer - Algoritmo Natural Sustentabilidade Digital")
        print("Assistente experimental. Nao e antivirus, VPN ou EDR.")
        print("\n1. Diagnostico local de leitura\n2. Rever conta Google\n3. Consultar agente IA (Groq Free)\n4. Ver investigacao e limites\n0. Sair")
        choice = input("Escolha: ").strip()
        if choice == "0":
            return
        if choice == "1":
            print("A consultar o Windows; pode demorar ate 25 segundos...")
            diagnostic = collect()
            print(explain(diagnostic))
        elif choice == "2":
            google_checklist()
        elif choice == "3":
            run_agent(diagnostic)
        elif choice == "4":
            print("Documentacao na pasta do programa:")
            print(ROOT / "INVESTIGACAO.md")
            print(ROOT / "LE-ME-PRIMEIRO.txt")
            print("Integracoes com os motores de terceiros ainda nao implementadas. Sem vigilancia continua.")
        else:
            print("Escolha uma opcao apresentada.")


def main():
    parser = argparse.ArgumentParser(description="Algoritmo Securety Sistens - assistente local")
    parser.add_argument("--diagnostico", action="store_true", help="Consulta de leitura; imprime JSON sem guardar")
    parser.add_argument("--verificar", action="store_true", help="Verifica ficheiros essenciais sem rede")
    args = parser.parse_args()
    if args.verificar:
        for name in ("INICIAR.cmd", "INSTALAR.cmd", "instalar.py", "LE-ME-PRIMEIRO.txt", "INVESTIGACAO.md"):
            if not (ROOT / name).is_file():
                raise SystemExit("Ficheiro em falta: " + name)
        print(f"Estrutura {VERSION} OK. {len(AGENTS)} agentes definidos. Nenhuma chamada API efetuada.")
    elif args.diagnostico:
        print(json.dumps(collect(), ensure_ascii=False, indent=2))
    else:
        menu()


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nPrograma terminado.")
    except OSError:
        print("Nao foi possivel aceder a um recurso local. Verifica permissoes e ficheiros.")
        sys.exit(1)
