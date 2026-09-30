"""Porteiro do Claude: quando o Claude Code ou o Claude Desktop arranca, o processo e congelado ate alguem
introduzir a palavra-passe E o codigo de 6 digitos (Ente Auth). Errado ou cancelado: o Claude e fechado,
fica um alerta e chega notificacao. Corre dentro da vigilancia protegida (elevada), que um programa
sem administrador nao consegue parar nem ler o segredo."""
import ctypes
import os
import time
from ctypes import wintypes

from . import notificar

ALVOS = ("claude.exe",)
TENTATIVAS_POR_JANELA = 3
ESPERA_JANELA = 120
INTERVALO = 0.5
VALIDADE_OMISSAO = 240  # minutos sem voltar a pedir o codigo depois de uma entrada correta


# ---------------- processos do Windows (ctypes, sem pacotes externos) ----------------
class _Entrada(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


CONSULTA = 0x1000          # PROCESS_QUERY_LIMITED_INFORMATION
SUSPENDER = 0x0800         # PROCESS_SUSPEND_RESUME
TERMINAR = 0x0001          # PROCESS_TERMINATE


def _kernel32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.OpenProcess.restype = wintypes.HANDLE
    return k


def _abrir(pid, acesso):
    return _kernel32().OpenProcess(acesso, False, pid)


def _info(pid):
    """(caminho completo, hora de criacao) - a hora distingue um PID reutilizado."""
    k = _kernel32()
    h = k.OpenProcess(CONSULTA, False, pid)
    if not h:
        return "", 0
    try:
        buf = ctypes.create_unicode_buffer(1024)
        tamanho = wintypes.DWORD(len(buf))
        caminho = buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(tamanho)) else ""
        c, s, u, kt = (wintypes.FILETIME() for _ in range(4))
        criado = (c.dwHighDateTime << 32 | c.dwLowDateTime) if k.GetProcessTimes(h, ctypes.byref(c), ctypes.byref(s),
                                                                                ctypes.byref(kt), ctypes.byref(u)) else 0
        return caminho, criado
    finally:
        k.CloseHandle(h)


def listar_claude():
    k = _kernel32()
    snap = k.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not snap or snap == wintypes.HANDLE(-1).value:
        return []
    procs = []
    try:
        e = _Entrada()
        e.dwSize = ctypes.sizeof(_Entrada)
        ok = k.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            if e.szExeFile.lower() in ALVOS:
                caminho, criado = _info(e.th32ProcessID)
                procs.append({"pid": e.th32ProcessID, "ppid": e.th32ParentProcessID, "nome": e.szExeFile,
                              "caminho": caminho, "criado": criado})
            ok = k.Process32NextW(snap, ctypes.byref(e))
    finally:
        k.CloseHandle(snap)
    return procs


def _ntdll(funcao, pid):
    h = _abrir(pid, SUSPENDER)
    if not h:
        return False
    try:
        return getattr(ctypes.WinDLL("ntdll"), funcao)(wintypes.HANDLE(h)) == 0
    finally:
        _kernel32().CloseHandle(h)


def suspender(pid):
    return _ntdll("NtSuspendProcess", pid)


def retomar(pid):
    return _ntdll("NtResumeProcess", pid)


def terminar(pid):
    k = _kernel32()
    h = k.OpenProcess(TERMINAR, False, pid)
    if not h:
        return False
    try:
        return bool(k.TerminateProcess(h, 1))
    finally:
        k.CloseHandle(h)


def aplicacao(caminho):
    c = (caminho or "").lower()
    return "Claude Desktop" if "\\windowsapps\\" in c or "anthropicclaude" in c else "Claude Code"


# ---------------- janela de pedido ----------------
def janela(app, erro=""):
    """Devolve (palavra, codigo) ou None se cancelado / 2 minutos sem resposta."""
    import tkinter as tk
    resultado = {}
    raiz = tk.Tk()
    raiz.title("Securety Sistens - verificacao em dois passos")
    raiz.attributes("-topmost", True)
    raiz.resizable(False, False)
    tk.Label(raiz, text=f"Alguem esta a abrir o {app}.", font=("Segoe UI", 12, "bold")).pack(padx=24, pady=(18, 4))
    tk.Label(raiz, text="Esta congelado ate confirmares que es tu.", font=("Segoe UI", 10)).pack(padx=24)
    tk.Label(raiz, text="Palavra-passe do Securety Sistens:", font=("Segoe UI", 10)).pack(anchor="w", padx=24, pady=(14, 2))
    palavra = tk.Entry(raiz, show="•", width=34, font=("Segoe UI", 11))
    palavra.pack(padx=24)
    tk.Label(raiz, text="Codigo de 6 digitos da app Ente Auth:", font=("Segoe UI", 10)).pack(anchor="w", padx=24, pady=(10, 2))
    codigo = tk.Entry(raiz, width=34, font=("Consolas", 14))
    codigo.pack(padx=24)
    tk.Label(raiz, text=erro, fg="#b00020", font=("Segoe UI", 10)).pack(padx=24, pady=(8, 0))

    def aceitar(_evento=None):
        resultado["valor"] = (palavra.get(), codigo.get().strip())
        raiz.quit()

    botoes = tk.Frame(raiz)
    botoes.pack(pady=14)
    tk.Button(botoes, text="Abrir o Claude", width=16, command=aceitar).pack(side="left", padx=6)
    tk.Button(botoes, text="Cancelar (fecha)", width=16, command=raiz.quit).pack(side="left", padx=6)
    tk.Label(raiz, text="Nuno Camara | Algoritmo Natural", fg="#666", font=("Segoe UI", 8)).pack(pady=(0, 10))
    raiz.bind("<Return>", aceitar)
    raiz.bind("<Escape>", lambda _e: raiz.quit())
    raiz.protocol("WM_DELETE_WINDOW", raiz.quit)
    raiz.after(ESPERA_JANELA * 1000, raiz.quit)
    raiz.after(150, lambda: (raiz.lift(), raiz.focus_force(), palavra.focus_set()))
    try:
        raiz.mainloop()
    finally:
        raiz.destroy()
    return resultado.get("valor")


# ---------------- logica ----------------
class Porteiro:
    def __init__(self, registo, listar=listar_claude, suspender=suspender, retomar=retomar, terminar=terminar,
                 pedir=janela, enviar=notificar.enviar, relogio=time.time):
        self.registo, self.listar, self.pedir, self.enviar, self.relogio = registo, listar, pedir, enviar, relogio
        self._suspender, self._retomar, self._terminar = suspender, retomar, terminar
        self.valido_ate = 0.0
        # O que ja estava aberto quando a vigilancia arrancou continua (nao fecha a sessao atual por surpresa).
        self.permitidos = {(p["pid"], p["criado"]) for p in self.listar()}
        self.recusados = set()  # se o Windows nao deixar fechar, fica congelado e nao volta a pedir

    def validade(self):
        try:
            return max(0, int(self.registo.config().get("claude_validade_minutos", VALIDADE_OMISSAO))) * 60
        except (TypeError, ValueError):
            return VALIDADE_OMISSAO * 60

    def passo(self):
        procs = sorted(self.listar(), key=lambda p: p["criado"])
        atuais = {p["pid"]: (p["pid"], p["criado"]) for p in procs}
        self.permitidos &= set(atuais.values())
        self.recusados &= set(atuais.values())
        pendentes = []
        for p in procs:
            chave = atuais[p["pid"]]
            if chave in self.permitidos or chave in self.recusados:
                continue
            # Processos filhos de um Claude ja autorizado (o Desktop abre varios) passam.
            if atuais.get(p["ppid"]) in self.permitidos or self.relogio() < self.valido_ate:
                self.permitidos.add(chave)
                continue
            pendentes.append(p)
        if not pendentes:
            return None
        for p in pendentes:
            self._suspender(p["pid"])
        return self._decidir(pendentes)

    def _decidir(self, pendentes):
        app = aplicacao(pendentes[0]["caminho"])
        erro = ""
        for _ in range(TENTATIVAS_POR_JANELA):
            resposta = self.pedir(app, erro)
            if resposta is None:
                return self._recusar(pendentes, app, "Cancelado ou sem resposta em 2 minutos.", "aviso")
            ok, mensagem = self.registo.verificar_dois_fatores(*resposta)
            if ok:
                self.valido_ate = self.relogio() + self.validade()
                for p in pendentes:
                    self.permitidos.add((p["pid"], p["criado"]))
                    self._retomar(p["pid"])
                if mensagem != "ok":
                    self._alerta("aviso", f"{app} aberto com codigo de recuperacao", mensagem)
                return "aceite"
            if "Bloqueado" in mensagem or "Demasiadas" in mensagem:
                return self._recusar(pendentes, app, mensagem, "critico")
            erro = mensagem
        return self._recusar(pendentes, app, f"{TENTATIVAS_POR_JANELA} tentativas erradas seguidas.", "critico")

    def _recusar(self, pendentes, app, motivo, nivel):
        for p in pendentes:
            self.recusados.add((p["pid"], p["criado"]))
            self._terminar(p["pid"])
        self._alerta(nivel, f"Tentativa de abrir o {app} bloqueada", motivo)
        return "recusado"

    def _alerta(self, nivel, titulo, detalhe):
        alerta = {"nivel": nivel, "tipo": "porteiro-claude", "titulo": titulo, "detalhe": detalhe}
        try:
            self.registo.adicionar(alerta)
        except Exception:  # o registo nunca pode impedir o bloqueio
            pass
        try:
            self.enviar(self.registo.config(), alerta)
        except Exception:
            pass

    def correr(self, parar=None):
        while not (parar and parar()):
            try:
                self.passo()
            except Exception as erro:  # nunca deixar a vigilancia morrer por um erro inesperado
                self._alerta("aviso", "Erro no porteiro do Claude", type(erro).__name__)
                time.sleep(5)
            time.sleep(INTERVALO)


def ativo(registo):
    return os.name == "nt" and registo.dois_fatores_configurado()
