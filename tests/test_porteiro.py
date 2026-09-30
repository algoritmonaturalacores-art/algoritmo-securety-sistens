import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seguranca import porteiro, totp  # noqa: E402
from seguranca.registo import Registo  # noqa: E402

SEGREDO = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
DESKTOP = r"C:\Program Files\WindowsApps\Claude_2.1_x64__pzs8sxrjxfjjc\app\claude.exe"
CODE = r"C:\Users\x\.local\bin\claude.exe"


def proc(pid, criado, ppid=1, caminho=CODE):
    return {"pid": pid, "ppid": ppid, "nome": "claude.exe", "caminho": caminho, "criado": criado}


def codigo_certo():
    return totp.codigo(SEGREDO)


@unittest.skipUnless(sys.platform == "win32", "usa DPAPI do Windows")
class TestPorteiro(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.reg = Registo(self.tmp.name)
        self.reg.definir_dois_fatores(SEGREDO, totp.codigos_recuperacao()[1])
        self.procs = [proc(10, 1)]
        self.suspensos, self.retomados, self.fechados, self.pedidos, self.notificados = [], [], [], [], []
        self.respostas = []
        self.agora = 1000.0
        self.pode_fechar = True

    def tearDown(self):
        self.tmp.cleanup()

    def pedir(self, app, erro):
        self.pedidos.append((app, erro))
        resposta = self.respostas.pop(0) if self.respostas else None
        return resposta() if callable(resposta) else resposta

    def fechar(self, pid):
        self.fechados.append(pid)
        if self.pode_fechar:
            self.procs = [p for p in self.procs if p["pid"] != pid]
        return self.pode_fechar

    def porteiro(self):
        return porteiro.Porteiro(self.reg, listar=lambda: list(self.procs), suspender=self.suspensos.append,
                                 retomar=self.retomados.append, terminar=self.fechar, pedir=self.pedir,
                                 enviar=lambda config, alerta: self.notificados.append(alerta), relogio=lambda: self.agora)

    def alertas(self):
        return self.reg.listar()

    # --------------------------------------------------------------
    def test_claude_ja_aberto_quando_o_porteiro_arranca_nao_e_tocado(self):
        p = self.porteiro()
        p.passo()
        self.assertEqual((self.suspensos, self.pedidos, self.fechados), ([], [], []))

    def test_claude_novo_fica_congelado_e_abre_com_palavra_e_codigo(self):
        p = self.porteiro()
        self.procs.append(proc(20, 2, caminho=DESKTOP))
        self.respostas = [codigo_certo]
        p.passo()
        self.assertEqual(self.suspensos, [20])
        self.assertEqual(self.retomados, [20])
        self.assertEqual(self.fechados, [])
        self.assertEqual(self.pedidos[0][0], "Claude Desktop")

    def test_nome_do_claude_code(self):
        p = self.porteiro()
        self.procs.append(proc(20, 2, caminho=CODE))
        p.passo()
        self.assertEqual(self.pedidos[0][0], "Claude Code")

    def test_cancelar_fecha_regista_aviso_e_notifica(self):
        p = self.porteiro()
        self.procs.append(proc(20, 2))
        self.respostas = [None]
        p.passo()
        self.assertEqual(self.fechados, [20])
        self.assertEqual(self.retomados, [])
        self.assertEqual(self.alertas()[-1]["nivel"], "aviso")
        self.assertEqual(self.notificados[-1]["nivel"], "aviso")

    def test_tres_erros_seguidos_fecham_com_alerta_critico(self):
        p = self.porteiro()
        self.procs.append(proc(20, 2))
        self.respostas = ["000000", "111111", "222222"] if codigo_certo() not in ("000000", "111111", "222222") else ["333333"] * 3
        p.passo()
        self.assertEqual(len(self.pedidos), 3)
        self.assertEqual(self.pedidos[0][1], "")
        self.assertIn("errado", self.pedidos[1][1])
        self.assertEqual(self.fechados, [20])
        self.assertEqual(self.alertas()[-1]["nivel"], "critico")

    def test_bloqueado_fecha_logo_sem_insistir(self):
        for _ in range(5):
            self.reg.verificar_codigo("x")
        p = self.porteiro()
        self.procs.append(proc(20, 2))
        self.respostas = [codigo_certo] * 3
        p.passo()
        self.assertEqual(len(self.pedidos), 1)
        self.assertEqual(self.fechados, [20])
        self.assertEqual(self.alertas()[-1]["nivel"], "critico")

    def test_filhos_de_um_claude_autorizado_passam_sem_pedir(self):
        p = self.porteiro()
        self.procs.append(proc(11, 5, ppid=10))
        p.passo()
        self.assertEqual(self.pedidos, [])

    def test_dentro_da_validade_nao_volta_a_pedir_e_depois_pede(self):
        self.reg.guardar_config({**self.reg.config(), "claude_validade_minutos": 10})
        p = self.porteiro()
        self.procs.append(proc(20, 2))
        self.respostas = [codigo_certo]
        p.passo()
        self.agora += 5 * 60
        self.procs.append(proc(30, 3, ppid=99))
        p.passo()
        self.assertEqual(len(self.pedidos), 1)
        self.agora += 6 * 60
        self.procs.append(proc(40, 4, ppid=99))
        p.passo()
        self.assertEqual(len(self.pedidos), 2)
        self.assertEqual(self.fechados, [40])

    def test_validade_zero_pede_sempre(self):
        self.reg.guardar_config({**self.reg.config(), "claude_validade_minutos": 0})
        p = self.porteiro()
        self.procs.append(proc(20, 2))
        self.respostas = [codigo_certo]
        p.passo()
        self.procs.append(proc(30, 3, ppid=99))
        p.passo()
        self.assertEqual(len(self.pedidos), 2)

    def test_pid_reutilizado_por_outro_processo_nao_herda_autorizacao(self):
        p = self.porteiro()
        self.procs = [proc(10, 99)]  # o PID 10 agora e outro processo
        p.passo()
        self.assertEqual(len(self.pedidos), 1)

    def test_se_o_windows_nao_deixar_fechar_nao_pede_em_ciclo(self):
        self.pode_fechar = False
        p = self.porteiro()
        self.procs.append(proc(20, 2))
        p.passo()
        p.passo()
        self.assertEqual(len(self.pedidos), 1)

    def test_erro_inesperado_nao_para_o_porteiro(self):
        chamadas = []

        def listar():
            chamadas.append(1)
            if len(chamadas) == 2:
                raise RuntimeError("falha momentanea")
            return list(self.procs)

        p = porteiro.Porteiro(self.reg, listar=listar, suspender=self.suspensos.append, retomar=self.retomados.append,
                              terminar=self.fechar, pedir=self.pedir, enviar=lambda c, a: None,
                              relogio=lambda: self.agora, dormir=lambda s: None)
        p.correr(parar=lambda: len(chamadas) >= 4)
        self.assertGreaterEqual(len(chamadas), 4)



@unittest.skipUnless(sys.platform == "win32", "processos do Windows")
class TestProcessosWindows(unittest.TestCase):
    """Funcoes reais do Windows, testadas num 'ping' inofensivo."""

    def setUp(self):
        import subprocess
        self.proc = subprocess.Popen(["ping", "-n", "3", "127.0.0.1"], stdout=subprocess.DEVNULL)

    def tearDown(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()

    def test_listar_encontra_o_processo_com_caminho_pai_e_hora(self):
        import os
        achados = [p for p in porteiro.listar_processos(("ping.exe",)) if p["pid"] == self.proc.pid]
        self.assertEqual(len(achados), 1)
        p = achados[0]
        self.assertTrue(p["caminho"].lower().endswith("ping.exe"))
        self.assertEqual(p["ppid"], os.getpid())
        self.assertGreater(p["criado"], 0)

    def test_listar_claude_so_devolve_claude(self):
        self.assertTrue(all(p["nome"].lower() == "claude.exe" for p in porteiro.listar_claude()))

    def test_congelado_nao_avanca_e_retomado_termina(self):
        import time
        self.assertTrue(porteiro.suspender(self.proc.pid))
        time.sleep(3.5)  # o ping demora ~2 s; congelado, nao pode ter terminado
        self.assertIsNone(self.proc.poll())
        self.assertTrue(porteiro.retomar(self.proc.pid))
        self.assertEqual(self.proc.wait(timeout=10), 0)

    def test_terminar_fecha(self):
        self.assertTrue(porteiro.terminar(self.proc.pid))
        self.assertEqual(self.proc.wait(timeout=5), 1)

    def test_pid_inexistente_devolve_falso_sem_rebentar(self):
        self.assertFalse(porteiro.suspender(4_000_000))
        self.assertFalse(porteiro.terminar(4_000_000))

    def test_porteiro_usa_as_funcoes_reais_por_omissao(self):
        import inspect
        d = inspect.signature(porteiro.Porteiro).parameters
        self.assertIs(d["listar"].default, porteiro.listar_claude)
        self.assertIs(d["terminar"].default, porteiro.terminar)



@unittest.skipUnless(sys.platform == "win32", "janela do Windows")
class TestJanela(unittest.TestCase):
    def textos(self, j):
        return " ".join(w.cget("text") for w in j.raiz.winfo_children() if w.winfo_class() == "Label")

    def test_aceitar_devolve_o_codigo_sem_espacos(self):
        j = porteiro.JanelaCodigo("Claude Code", "")
        j.codigo.insert(0, " 123 456 ")
        j.raiz.after(50, j.aceitar)
        self.assertEqual(j.mostrar(), "123456")

    def test_cancelar_devolve_none(self):
        j = porteiro.JanelaCodigo("Claude Code", "")
        j.raiz.after(50, j.cancelar)
        self.assertIsNone(j.mostrar())

    def test_sem_resposta_fecha_sozinha(self):
        self.assertIsNone(porteiro.JanelaCodigo("Claude Code", "", espera=0.3).mostrar())

    def test_mostra_aplicacao_erro_e_google_authenticator_sem_palavra_passe(self):
        j = porteiro.JanelaCodigo("Claude Desktop", "Codigo errado (1/5).")
        texto = self.textos(j)
        j.raiz.after(50, j.cancelar)
        j.mostrar()
        self.assertIn("Claude Desktop", texto)
        self.assertIn("Codigo errado (1/5).", texto)
        self.assertIn("Google Authenticator", texto)
        self.assertNotIn("alavra-passe", texto)

    def test_porteiro_usa_a_janela_por_omissao(self):
        import inspect
        self.assertIs(inspect.signature(porteiro.Porteiro).parameters["pedir"].default, porteiro.pedir_codigo)


if __name__ == "__main__":
    unittest.main()
