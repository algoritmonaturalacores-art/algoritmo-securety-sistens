"""Porteiro do Claude: quando o Claude Code ou o Claude Desktop arranca, fica congelado ate alguem introduzir
o codigo de 6 digitos do Google Authenticator. Errado ou cancelado: fecha, regista alerta e notifica.
Corre dentro da vigilancia protegida (elevada): sem administrador nao se consegue parar nem ler a chave."""
import ctypes
import time
from ctypes import wintypes

from . import notificar

TENTATIVAS_POR_JANELA = 3
VALIDADE_OMISSAO = 240  # minutos sem voltar a pedir depois de um codigo certo
INTERVALO = 0.5


# ---------------- processos do Windows (ctypes, sem pacotes externos) ----------------
class _Entrada(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


CONSULTA, SUSPENDER, TERMINAR = 0x1000, 0x0800, 0x0001  # direitos pedidos ao abrir um processo
INVALIDO = ctypes.c_void_p(-1).value


def _k32():
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.OpenProcess.restype = wintypes.HANDLE
    k.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    k.CloseHandle.argtypes = (wintypes.HANDLE,)
    return k


def _com_processo(pid, direitos, funcao):
    k = _k32()
    h = k.OpenProcess(direitos, False, pid)
    if not h:
        return None
    try:
        return funcao(k, h)
    finally:
        k.CloseHandle(h)


def _caminho_e_hora(k, h):
    buf = ctypes.create_unicode_buffer(1024)
    tamanho = wintypes.DWORD(len(buf))
    caminho = buf.value if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(tamanho)) else ""
    tempos = [wintypes.FILETIME() for _ in range(4)]
    ok = k.GetProcessTimes(h, *(ctypes.byref(t) for t in tempos))
    return caminho, (tempos[0].dwHighDateTime << 32 | tempos[0].dwLowDateTime) if ok else 0


def listar_processos(nomes):
    nomes = {n.lower() for n in nomes}
    k = _k32()
    foto = k.CreateToolhelp32Snapshot(0x2, 0)  # TH32CS_SNAPPROCESS
    if not foto or foto == INVALIDO:
        return []
    procs = []
    try:
        e = _Entrada()
        e.dwSize = ctypes.sizeof(_Entrada)
        ok = k.Process32FirstW(foto, ctypes.byref(e))
        while ok:
            if e.szExeFile.lower() in nomes:
                caminho, criado = _com_processo(e.th32ProcessID, CONSULTA, _caminho_e_hora) or ("", 0)
                procs.append({"pid": e.th32ProcessID, "ppid": e.th32ParentProcessID, "nome": e.szExeFile,
                              "caminho": caminho, "criado": criado})
            ok = k.Process32NextW(foto, ctypes.byref(e))
    finally:
        k.CloseHandle(foto)
    return procs


def listar_claude():
    return listar_processos(("claude.exe",))


def _nt(funcao):
    nt = ctypes.WinDLL("ntdll")
    getattr(nt, funcao).argtypes = (wintypes.HANDLE,)
    return lambda k, h: getattr(nt, funcao)(h) == 0


def suspender(pid):
    return bool(_com_processo(pid, SUSPENDER, _nt("NtSuspendProcess")))


def retomar(pid):
    return bool(_com_processo(pid, SUSPENDER, _nt("NtResumeProcess")))


def terminar(pid):
    return bool(_com_processo(pid, TERMINAR, lambda k, h: k.TerminateProcess(h, 1)))


# ---------------- janela que pede o codigo ----------------
class JanelaCodigo:
    def __init__(self, app, erro, espera=120):
        import tkinter as tk
        self.resultado = None
        self.raiz = r = tk.Tk()
        r.title("Securety Sistens - verificacao do Claude")
        r.attributes("-topmost", True)
        r.resizable(False, False)
        tk.Label(r, text=f"Alguem esta a abrir o {app}.", font=("Segoe UI", 12, "bold")).pack(padx=24, pady=(18, 4))
        tk.Label(r, text="Esta congelado ate confirmares que es tu.", font=("Segoe UI", 10)).pack(padx=24)
        tk.Label(r, text="Codigo de 6 digitos do Google Authenticator:", font=("Segoe UI", 10)).pack(anchor="w", padx=24, pady=(14, 2))
        self.codigo = tk.Entry(r, width=16, font=("Consolas", 18), justify="center")
        self.codigo.pack(padx=24)
        tk.Label(r, text=erro, fg="#b00020", font=("Segoe UI", 10)).pack(padx=24, pady=(8, 0))
        botoes = tk.Frame(r)
        botoes.pack(pady=14)
        tk.Button(botoes, text="Abrir o Claude", width=16, command=self.aceitar).pack(side="left", padx=6)
        tk.Button(botoes, text="Cancelar (fecha)", width=16, command=self.cancelar).pack(side="left", padx=6)
        tk.Label(r, text="Nuno Camara | Algoritmo Natural", fg="#666", font=("Segoe UI", 8)).pack(pady=(0, 10))
        r.bind("<Return>", lambda _e: self.aceitar())
        r.bind("<Escape>", lambda _e: self.cancelar())
        r.protocol("WM_DELETE_WINDOW", self.cancelar)
        r.after(int(espera * 1000), self.cancelar)
        r.after(150, lambda: (r.lift(), r.focus_force(), self.codigo.focus_set()))

    def aceitar(self):
        self.resultado = "".join(self.codigo.get().split())
        self.raiz.quit()

    def cancelar(self):
        self.resultado = None
        self.raiz.quit()

    def mostrar(self):
        try:
            self.raiz.mainloop()
        finally:
            self.raiz.destroy()
        return self.resultado


def pedir_codigo(app, erro):
    """Devolve o codigo introduzido, ou None se cancelado ou 2 minutos sem resposta."""
    return JanelaCodigo(app, erro).mostrar()


def aplicacao(caminho):
    return "Claude Desktop" if "\\windowsapps\\" in (caminho or "").lower() else "Claude Code"


class Porteiro:
    def __init__(self, registo, listar=listar_claude, suspender=suspender, retomar=retomar, terminar=terminar,
                 pedir=pedir_codigo, enviar=notificar.enviar, relogio=time.time, dormir=time.sleep):
        self.registo, self.listar, self.pedir, self.enviar = registo, listar, pedir, enviar
        self.suspender, self.retomar, self.terminar = suspender, retomar, terminar
        self.relogio, self.dormir = relogio, dormir
        self.valido_ate = 0.0
        # O que ja estava aberto quando a vigilancia arrancou continua: nunca fecha trabalho em curso de surpresa.
        self.permitidos = {self._chave(p) for p in self.listar()}
        self.recusados = set()  # se o Windows nao deixar fechar, fica congelado e nao volta a pedir

    @staticmethod
    def _chave(p):
        return p["pid"], p["criado"]  # a hora de criacao distingue um PID reutilizado

    def _validade(self):
        try:
            return max(0, int(self.registo.config().get("claude_validade_minutos", VALIDADE_OMISSAO))) * 60
        except (TypeError, ValueError):
            return VALIDADE_OMISSAO * 60

    def passo(self):
        procs = sorted(self.listar(), key=lambda p: p["criado"])
        atuais = {p["pid"]: self._chave(p) for p in procs}
        self.permitidos &= set(atuais.values())
        self.recusados &= set(atuais.values())
        pendentes = []
        for p in procs:
            chave = atuais[p["pid"]]
            if chave in self.permitidos or chave in self.recusados:
                continue
            if atuais.get(p["ppid"]) in self.permitidos or self.relogio() < self.valido_ate:
                self.permitidos.add(chave)  # filho de um Claude autorizado, ou dentro da validade
            else:
                pendentes.append(p)
        if pendentes:
            for p in pendentes:
                self.suspender(p["pid"])
            self._decidir(pendentes)

    def _decidir(self, pendentes):
        app = aplicacao(pendentes[0]["caminho"])
        erro = ""
        for _ in range(TENTATIVAS_POR_JANELA):
            resposta = self.pedir(app, erro)
            if resposta is None:
                return self._recusar(pendentes, app, "Cancelado ou sem resposta em 2 minutos.", "aviso")
            ok, mensagem = self.registo.verificar_codigo(resposta)
            if ok:
                self.valido_ate = self.relogio() + self._validade()
                for p in pendentes:
                    self.permitidos.add(self._chave(p))
                    self.retomar(p["pid"])
                if mensagem != "ok":
                    self._alerta("aviso", f"{app} aberto com codigo de recuperacao", mensagem)
                return
            if "Bloqueado" in mensagem or "Demasiadas" in mensagem:
                return self._recusar(pendentes, app, mensagem, "critico")
            erro = mensagem
        self._recusar(pendentes, app, f"{TENTATIVAS_POR_JANELA} tentativas erradas seguidas.", "critico")

    def _recusar(self, pendentes, app, motivo, nivel):
        for p in pendentes:
            self.recusados.add(self._chave(p))
            self.terminar(p["pid"])
        self._alerta(nivel, f"Tentativa de abrir o {app} bloqueada", motivo)

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
            except Exception as erro:  # um erro momentaneo nunca pode desligar o porteiro
                self._alerta("aviso", "Erro no porteiro do Claude", type(erro).__name__)
                self.dormir(5)
            self.dormir(INTERVALO)
