"""Armazenamento local: alertas encadeados (detecao de adulteracao), linha de base, configuracao e acesso."""
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path

NOME = "AlgoritmoSecuretySistens"
INICIO_CADEIA = "0" * 64
ITERACOES = 600_000
MAX_FALHAS = 5
BLOQUEIO_SEGUNDOS = 300


class RegistoError(Exception):
    pass


def pasta_estado():
    """ProgramData (so administradores escrevem) quando a vigilancia protegida esta instalada; senao a pasta do utilizador."""
    protegida = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "AlgoritmoNatural" / NOME
    if protegida.is_dir():
        return protegida
    return Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / NOME


class Registo:
    def __init__(self, pasta=None):
        self.pasta = Path(pasta) if pasta else pasta_estado()
        self.alertas = self.pasta / "alertas.jsonl"
        self.base = self.pasta / "linha_base.json"
        self.config_f = self.pasta / "config.json"
        self.acesso_f = self.pasta / "acesso.json"
        self.estado_f = self.pasta / "estado.json"

    # ---------- utilidades ----------
    def _garantir(self):
        try:
            self.pasta.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise RegistoError(f"Sem permissao para escrever em {self.pasta}. Abre como administrador.") from None

    def _ler_json(self, caminho, omissao):
        try:
            valor = json.loads(caminho.read_text(encoding="utf-8"))
            return valor if isinstance(valor, type(omissao)) else omissao
        except (OSError, ValueError):
            return omissao

    def _escrever_json(self, caminho, valor):
        self._garantir()
        temporario = caminho.with_suffix(".tmp")
        try:
            temporario.write_text(json.dumps(valor, ensure_ascii=False, indent=1), encoding="utf-8")
            os.replace(temporario, caminho)
        except OSError:
            raise RegistoError(f"Sem permissao para escrever em {self.pasta}. Abre como administrador.") from None

    # ---------- configuracao ----------
    def config(self):
        omissao = {"intervalo_segundos": 60, "nivel_notificacao": "aviso", "notificar_pc": True,
                   "ntfy_topico": None, "ntfy_servidor": "https://ntfy.sh"}
        omissao.update(self._ler_json(self.config_f, {}))
        return omissao

    def guardar_config(self, config):
        self._escrever_json(self.config_f, config)

    def estado(self):
        return self._ler_json(self.estado_f, {})

    def guardar_estado(self, estado):
        self._escrever_json(self.estado_f, estado)

    # ---------- alertas encadeados ----------
    def _linhas(self):
        try:
            return [json.loads(l) for l in self.alertas.read_text(encoding="utf-8").splitlines() if l.strip()]
        except FileNotFoundError:
            return []
        except (OSError, ValueError):
            raise RegistoError("Ficheiro de alertas ilegivel ou adulterado.") from None

    def _linhas_para_escrever(self):
        """Ficheiro ilegivel nao pode parar a vigilancia: fica de lado como prova e a cadeia recomeca."""
        try:
            return self._linhas()
        except RegistoError:
            try:
                os.replace(self.alertas, self.pasta / f"alertas.corrompido.{int(time.time())}.jsonl")
            except OSError:
                raise RegistoError("Ficheiro de alertas ilegivel e sem permissao para o por de lado.") from None
            return []

    @staticmethod
    def _hash(anterior, registo):
        corpo = {k: v for k, v in registo.items() if k != "hash"}
        return hashlib.sha256((anterior + json.dumps(corpo, sort_keys=True, ensure_ascii=False)).encode("utf-8")).hexdigest()

    def adicionar(self, alerta):
        linhas = self._linhas_para_escrever()
        anterior = linhas[-1]["hash"] if linhas else INICIO_CADEIA
        registo = {"id": len(linhas) + 1, "registado": datetime.now(timezone.utc).isoformat(),
                   "nivel": alerta.get("nivel", "info"), "tipo": alerta.get("tipo", ""), "titulo": alerta.get("titulo", ""),
                   "detalhe": alerta.get("detalhe", ""), "hora_evento": alerta.get("hora_evento"),
                   "repeticoes": alerta.get("repeticoes", 1), "tipo_registo": "alerta"}
        registo["hash"] = self._hash(anterior, registo)
        self._garantir()
        with open(self.alertas, "a", encoding="utf-8") as f:
            f.write(json.dumps(registo, ensure_ascii=False) + "\n")
        self.selar()
        return registo

    def marcar(self, ids, estado="visto", nota=""):
        """Marcar nao reescreve alertas antigos: acrescenta um registo de marcacao a cadeia."""
        if estado not in ("visto", "conhecido", "suspeito"):
            raise RegistoError("Estado de marcacao invalido.")
        linhas = self._linhas_para_escrever()
        existentes = {l["id"] for l in linhas if l.get("tipo_registo") == "alerta"}
        ids = [i for i in ids if i in existentes]
        if not ids:
            return 0
        anterior = linhas[-1]["hash"]
        registo = {"id": len(linhas) + 1, "registado": datetime.now(timezone.utc).isoformat(), "tipo_registo": "marcacao",
                   "alvos": sorted(ids), "estado": estado, "nota": "".join(c for c in nota if c.isprintable())[:200]}
        registo["hash"] = self._hash(anterior, registo)
        with open(self.alertas, "a", encoding="utf-8") as f:
            f.write(json.dumps(registo, ensure_ascii=False) + "\n")
        self.selar()
        return len(ids)

    def listar(self):
        """Alertas com o estado de marcacao mais recente aplicado."""
        linhas = self._linhas()
        alertas = {l["id"]: dict(l, estado="novo") for l in linhas if l.get("tipo_registo") == "alerta"}
        for l in linhas:
            if l.get("tipo_registo") == "marcacao":
                for alvo in l.get("alvos", []):
                    if alvo in alertas:
                        alertas[alvo]["estado"] = l.get("estado")
        return list(alertas.values())

    def verificar_cadeia(self):
        """Devolve (True, n) se intacta; (False, id) no primeiro registo alterado, removido ou reordenado."""
        anterior = INICIO_CADEIA
        try:
            linhas = self._linhas()
        except RegistoError:
            return False, 0
        for posicao, linha in enumerate(linhas, 1):
            if linha.get("id") != posicao or linha.get("hash") != self._hash(anterior, linha):
                return False, posicao
            anterior = linha["hash"]
        estado = self.estado()
        guardado = estado.get("ultimo_hash")
        if guardado and guardado != anterior:
            return False, estado.get("total_linhas", 0)
        return True, len(linhas)

    def selar(self):
        """Guarda o ultimo hash fora da cadeia para detetar linhas removidas no fim."""
        linhas = self._linhas()
        estado = self.estado()
        estado["ultimo_hash"] = linhas[-1]["hash"] if linhas else INICIO_CADEIA
        estado["total_linhas"] = len(linhas)
        self.guardar_estado(estado)

    # ---------- linha de base ----------
    def linha_base(self):
        return self._ler_json(self.base, {})

    def aceitar_linha_base(self, assinatura):
        self._escrever_json(self.base, {"aceite": datetime.now(timezone.utc).isoformat(), "assinatura": assinatura})

    # ---------- acesso por palavra-passe ----------
    def acesso_configurado(self):
        return bool(self._ler_json(self.acesso_f, {}).get("hash"))

    def definir_palavra_passe(self, palavra):
        erro = validar_palavra_passe(palavra)
        if erro:
            raise RegistoError(erro)
        sal = secrets.token_bytes(16)
        derivada = hashlib.pbkdf2_hmac("sha256", palavra.encode("utf-8"), sal, ITERACOES)
        self._escrever_json(self.acesso_f, {"algoritmo": "pbkdf2-sha256", "iteracoes": ITERACOES,
                                            "sal": sal.hex(), "hash": derivada.hex(), "falhas": 0, "bloqueado_ate": 0})

    def verificar_palavra_passe(self, palavra):
        """Devolve (ok, mensagem). Bloqueia 5 minutos apos 5 falhas seguidas."""
        dados = self._ler_json(self.acesso_f, {})
        if not dados.get("hash"):
            return False, "Acesso ainda nao configurado."
        agora = time.time()
        if dados.get("bloqueado_ate", 0) > agora:
            return False, f"Bloqueado por tentativas falhadas. Tenta daqui a {int(dados['bloqueado_ate'] - agora) + 1} segundos."
        try:
            derivada = hashlib.pbkdf2_hmac("sha256", palavra.encode("utf-8"), bytes.fromhex(dados["sal"]), int(dados["iteracoes"]))
        except (KeyError, ValueError, TypeError):
            return False, "Ficheiro de acesso danificado."
        if hmac.compare_digest(derivada.hex(), dados["hash"]):
            dados["falhas"], dados["bloqueado_ate"] = 0, 0
            self._escrever_json(self.acesso_f, dados)
            return True, "ok"
        dados["falhas"] = int(dados.get("falhas", 0)) + 1
        mensagem = f"Palavra-passe errada ({dados['falhas']}/{MAX_FALHAS})."
        if dados["falhas"] >= MAX_FALHAS:
            dados["falhas"], dados["bloqueado_ate"] = 0, agora + BLOQUEIO_SEGUNDOS
            mensagem = "Demasiadas tentativas. Bloqueado durante 5 minutos."
        self._escrever_json(self.acesso_f, dados)
        return False, mensagem


def validar_palavra_passe(palavra):
    if len(palavra) < 10:
        return "Usa pelo menos 10 caracteres."
    tipos = sum([any(c.islower() for c in palavra), any(c.isupper() for c in palavra),
                 any(c.isdigit() for c in palavra), any(not c.isalnum() for c in palavra)])
    if tipos < 3 and len(palavra) < 16:
        return "Mistura maiusculas, minusculas, numeros ou simbolos (ou usa uma frase com 16+ caracteres)."
    return None
