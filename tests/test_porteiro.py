import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seguranca import porteiro, totp  # noqa: E402
from seguranca.registo import Registo  # noqa: E402

PALAVRA = "Frase-Longa-Segura-2026"
SEGREDO_RFC = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890" (RFC 6238)
simples = lambda s: s  # noqa: E731


class TestTotp(unittest.TestCase):
    def test_vetores_rfc6238(self):
        self.assertEqual(totp.codigo(SEGREDO_RFC, 59), "287082")
        self.assertEqual(totp.codigo(SEGREDO_RFC, 1111111109), "081804")
        self.assertEqual(totp.codigo(SEGREDO_RFC, 2000000000), "279037")

    def test_janela_e_reutilizacao(self):
        t = 1111111109
        passo = totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, t - 30), instante=t)
        self.assertIsNotNone(passo)
        self.assertIsNone(totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, t - 30), passo, instante=t))
        self.assertIsNone(totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, t - 120), instante=t))
        self.assertIsNone(totp.verificar(SEGREDO_RFC, "12345", instante=t))

    def test_segredo_novo_e_uri(self):
        s = totp.novo_segredo()
        self.assertEqual(len(s), 32)
        self.assertEqual(len(totp.codigo(s)), 6)
        self.assertTrue(totp.uri(s, "Claude no PC").startswith("otpauth://totp/"))

    @unittest.skipUnless(os.name == "nt", "DPAPI so no Windows")
    def test_dpapi(self):
        self.assertEqual(totp.desproteger(totp.proteger("ABC")), "ABC")
        self.assertNotIn("ABC", totp.proteger("ABC"))


class TestDoisFatores(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = Registo(self.tmp.name)
        self.r.definir_palavra_passe(PALAVRA)
        self.codigos, hashes = totp.codigos_recuperacao()
        self.r.definir_dois_fatores(SEGREDO_RFC, hashes, proteger=simples)
        self.t = 1111111109

    def tearDown(self):
        self.tmp.cleanup()

    def verificar(self, palavra, codigo):
        return self.r.verificar_dois_fatores(palavra, codigo, instante=self.t, desproteger=simples)

    def test_precisa_dos_dois(self):
        certo = totp.codigo(SEGREDO_RFC, self.t)
        self.assertFalse(self.verificar("errada-errada-1A", certo)[0])
        self.assertFalse(self.verificar(PALAVRA, "000000")[0])
        self.assertTrue(self.verificar(PALAVRA, certo)[0])
        self.assertFalse(self.verificar(PALAVRA, certo)[0], "o mesmo codigo nao pode ser usado duas vezes")

    def test_bloqueio_apos_5_falhas(self):
        for _ in range(5):
            self.verificar(PALAVRA, "000000")
        ok, msg = self.verificar(PALAVRA, totp.codigo(SEGREDO_RFC, self.t))
        self.assertFalse(ok)
        self.assertIn("Bloqueado", msg)

    def test_recuperacao_uso_unico(self):
        ok, msg = self.verificar(PALAVRA, self.codigos[0].lower())
        self.assertTrue(ok)
        self.assertIn("Restam 7", msg)
        self.assertFalse(self.verificar(PALAVRA, self.codigos[0])[0])


class FalsoRegisto:
    def __init__(self, respostas_ok):
        self.respostas_ok, self.alertas = respostas_ok, []

    def config(self):
        return {"claude_validade_minutos": 10}

    def verificar_dois_fatores(self, palavra, codigo):
        return (True, "ok") if (palavra, codigo) in self.respostas_ok else (False, "Palavra-passe ou codigo errado (1/5).")

    def adicionar(self, alerta):
        self.alertas.append(alerta)


class TestPorteiro(unittest.TestCase):
    def montar(self, respostas, ok=(("p", "123456"),)):
        self.procs = [{"pid": 10, "ppid": 1, "nome": "claude.exe", "caminho": r"C:\Users\x\.local\bin\claude.exe", "criado": 1}]
        self.suspensos, self.retomados, self.fechados, self.pedidos = [], [], [], []
        self.agora = 1000.0
        respostas = list(respostas)

        def pedir(app, erro):
            self.pedidos.append((app, erro))
            return respostas.pop(0) if respostas else None

        self.reg = FalsoRegisto(set(ok))
        p = porteiro.Porteiro(self.reg, listar=lambda: list(self.procs), suspender=self.suspensos.append,
                              retomar=self.retomados.append, terminar=self.fechados.append, pedir=pedir,
                              enviar=lambda c, a: None, relogio=lambda: self.agora)
        return p

    def test_ja_aberto_ao_arrancar_continua(self):
        p = self.montar([])
        self.assertIsNone(p.passo())
        self.assertEqual(self.suspensos, [])

    def test_novo_claude_congela_e_abre_com_codigo(self):
        p = self.montar([("p", "123456")])
        self.procs.append({"pid": 20, "ppid": 5, "nome": "claude.exe", "caminho": "C:\\Program Files\\WindowsApps\\Claude_x\\Claude.exe", "criado": 2})
        self.assertEqual(p.passo(), "aceite")
        self.assertEqual(self.suspensos, [20])
        self.assertEqual(self.retomados, [20])
        self.assertEqual(self.pedidos[0][0], "Claude Desktop")
        # Filhos do Desktop e novas aberturas dentro da validade passam sem pedir
        self.procs.append({"pid": 21, "ppid": 20, "nome": "claude.exe", "caminho": "", "criado": 3})
        self.assertIsNone(p.passo())
        self.assertEqual(len(self.pedidos), 1)

    def test_validade_expira(self):
        p = self.montar([("p", "123456"), None])
        self.procs.append({"pid": 20, "ppid": 5, "nome": "claude.exe", "caminho": "", "criado": 2})
        p.passo()
        self.agora += 11 * 60
        self.procs.append({"pid": 30, "ppid": 5, "nome": "claude.exe", "caminho": "", "criado": 4})
        self.assertEqual(p.passo(), "recusado")
        self.assertEqual(self.fechados, [30])

    def test_errado_tres_vezes_fecha_e_alerta(self):
        p = self.montar([("p", "000000")] * 3)
        self.procs.append({"pid": 20, "ppid": 5, "nome": "claude.exe", "caminho": "", "criado": 2})
        self.assertEqual(p.passo(), "recusado")
        self.assertEqual(self.fechados, [20])
        self.assertEqual(self.reg.alertas[-1]["nivel"], "critico")
        self.assertIn("errado", self.pedidos[-1][1])
        # Nao volta a pedir pelo mesmo processo se o Windows nao o deixar fechar
        self.assertIsNone(p.passo())
        self.assertEqual(len(self.pedidos), 3)

    def test_cancelar_fecha(self):
        p = self.montar([None])
        self.procs.append({"pid": 20, "ppid": 5, "nome": "claude.exe", "caminho": "", "criado": 2})
        self.assertEqual(p.passo(), "recusado")
        self.assertEqual(self.reg.alertas[-1]["nivel"], "aviso")

    def test_pid_reutilizado_nao_herda_autorizacao(self):
        p = self.montar([None])
        self.procs[0] = dict(self.procs[0], criado=99)  # mesmo PID 10, processo diferente
        self.assertEqual(p.passo(), "recusado")


if __name__ == "__main__":
    unittest.main()
