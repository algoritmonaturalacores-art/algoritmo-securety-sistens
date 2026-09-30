import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seguranca import registo as registo_mod, totp  # noqa: E402
from seguranca.registo import Registo  # noqa: E402

PALAVRA = "Frase-Longa-Segura-2026"
SEGREDO = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
T = 1111111109


@unittest.skipUnless(sys.platform == "win32", "usa DPAPI do Windows")
class TestCodigoClaude(unittest.TestCase):
    """O Claude abre so com o codigo de 6 digitos do Google Authenticator (sem palavra-passe)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = Registo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def ligar(self):
        self.codigos, hashes = totp.codigos_recuperacao()
        self.r.definir_dois_fatores(SEGREDO, hashes)

    def entrar(self, codigo, t=T):
        return self.r.verificar_codigo(codigo, instante=t)

    def errado(self, t=T):
        return str((int(totp.codigo(SEGREDO, t)) + 1) % 10 ** 6).zfill(6)

    def test_sem_configurar_recusa(self):
        self.assertFalse(self.r.dois_fatores_configurado())
        ok, msg = self.entrar(totp.codigo(SEGREDO, T))
        self.assertFalse(ok)
        self.assertIn("configurad", msg)

    def test_funciona_sem_palavra_passe_do_programa(self):
        self.ligar()
        self.assertFalse(self.r.acesso_configurado())
        self.assertEqual(self.entrar(totp.codigo(SEGREDO, T)), (True, "ok"))

    def test_chave_nao_fica_legivel_no_ficheiro(self):
        self.ligar()
        self.assertNotIn(SEGREDO, self.r.dois_fatores_f.read_text(encoding="utf-8"))

    def test_codigo_errado_recusa(self):
        self.ligar()
        self.assertFalse(self.entrar(self.errado())[0])

    def test_codigo_nao_serve_duas_vezes_mesmo_depois_de_reabrir(self):
        self.ligar()
        c = totp.codigo(SEGREDO, T)
        self.assertTrue(self.entrar(c)[0])
        self.assertFalse(Registo(self.tmp.name).verificar_codigo(c, instante=T)[0])

    def test_5_codigos_errados_bloqueiam_mesmo_com_codigo_certo_depois(self):
        self.ligar()
        for _ in range(5):
            self.entrar(self.errado())
        ok, msg = self.entrar(totp.codigo(SEGREDO, T))
        self.assertFalse(ok)
        self.assertIn("Bloqueado", msg)

    def bloquear_e_esperar(self, vezes):
        """Provoca 'vezes' bloqueios seguidos, avancando o relogio para la de cada um."""
        import unittest.mock as mock
        agora = [1_000_000.0]
        with mock.patch("seguranca.registo.time.time", lambda: agora[0]):
            duracoes = []
            for _ in range(vezes):
                for _ in range(5):
                    self.entrar(self.errado())
                fim = json.loads(self.r.dois_fatores_f.read_text(encoding="utf-8"))["bloqueado_ate"]
                duracoes.append(round((fim - agora[0]) / 60))
                agora[0] = fim + 1
        return duracoes

    def test_bloqueios_seguidos_duram_cada_vez_mais_ate_1_hora(self):
        self.ligar()
        self.assertEqual(self.bloquear_e_esperar(6), [5, 10, 20, 40, 60, 60])

    def test_codigo_certo_repoe_o_bloqueio_para_5_minutos(self):
        self.ligar()
        self.bloquear_e_esperar(2)
        import unittest.mock as mock
        with mock.patch("seguranca.registo.time.time", lambda: 10_000_000.0):
            self.assertTrue(self.entrar(totp.codigo(SEGREDO, 10_000_000.0), t=10_000_000.0)[0])
        self.assertEqual(self.bloquear_e_esperar(1), [5])

    def test_bloqueio_do_codigo_nao_bloqueia_o_menu(self):
        self.r.definir_palavra_passe(PALAVRA)
        self.ligar()
        for _ in range(5):
            self.entrar(self.errado())
        self.assertTrue(self.r.verificar_palavra_passe(PALAVRA)[0])

    def test_codigo_de_recuperacao_serve_uma_vez(self):
        self.ligar()
        ok, msg = self.entrar(self.codigos[0].lower())
        self.assertTrue(ok)
        self.assertIn("7", msg)
        self.assertFalse(self.entrar(self.codigos[0])[0])

    def test_recuperacao_vazia_nao_entra(self):
        self.ligar()
        self.assertFalse(self.entrar("")[0])
        self.assertFalse(self.entrar("----")[0])

    def test_ficheiro_adulterado_recusa_sem_rebentar(self):
        self.ligar()
        dados = json.loads(self.r.dois_fatores_f.read_text(encoding="utf-8"))
        dados["segredo"] = "AAAA"
        self.r.dois_fatores_f.write_text(json.dumps(dados), encoding="utf-8")
        ok, msg = self.entrar(totp.codigo(SEGREDO, T))
        self.assertFalse(ok)
        self.assertIn("danificad", msg)


class TestPalavraPasseMenu(unittest.TestCase):
    def test_bloqueios_do_menu_tambem_crescem_e_repoem_com_a_certa(self):
        import unittest.mock as mock
        with tempfile.TemporaryDirectory() as tmp:
            r = Registo(tmp)
            r.definir_palavra_passe(PALAVRA)
            agora = [1_000_000.0]
            with mock.patch("seguranca.registo.time.time", lambda: agora[0]):
                def bloquear():
                    for _ in range(5):
                        r.verificar_palavra_passe("Errada-Errada-1")
                    fim = json.loads(r.acesso_f.read_text(encoding="utf-8"))["bloqueado_ate"]
                    minutos = round((fim - agora[0]) / 60)
                    agora[0] = fim + 1
                    return minutos
                self.assertEqual([bloquear(), bloquear()], [5, 10])
                self.assertTrue(r.verificar_palavra_passe(PALAVRA)[0])
                self.assertEqual(bloquear(), 5)


class TestPastaProtegida(unittest.TestCase):
    def test_so_restringe_dentro_do_programdata(self):
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        self.assertTrue(registo_mod.em_pasta_protegida(Path(pd) / "AlgoritmoNatural" / "x" / "dois_fatores.json"))
        self.assertFalse(registo_mod.em_pasta_protegida(Path(tempfile.gettempdir()) / "dois_fatores.json"))


if __name__ == "__main__":
    unittest.main()
