import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from seguranca import totp  # noqa: E402

SEGREDO_RFC = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890" em Base32 (RFC 6238, anexo B)


class TestCodigo(unittest.TestCase):
    def test_codigo_igual_ao_vetor_oficial_rfc6238(self):
        self.assertEqual(totp.codigo(SEGREDO_RFC, 59), "287082")
        self.assertEqual(totp.codigo(SEGREDO_RFC, 1111111109), "081804")
        self.assertEqual(totp.codigo(SEGREDO_RFC, 2000000000), "279037")


T = 1111111109


class TestVerificar(unittest.TestCase):
    def test_aceita_codigo_atual(self):
        self.assertIsNotNone(totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, T), instante=T))

    def test_aceita_codigo_de_ha_30_segundos(self):
        self.assertIsNotNone(totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, T - 30), instante=T))

    def test_recusa_codigo_de_ha_2_minutos(self):
        self.assertIsNone(totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, T - 120), instante=T))

    def test_recusa_codigo_errado_e_formato_invalido(self):
        certo = totp.codigo(SEGREDO_RFC, T)
        errado = str((int(certo) + 1) % 10 ** 6).zfill(6)
        self.assertIsNone(totp.verificar(SEGREDO_RFC, errado, instante=T))
        self.assertIsNone(totp.verificar(SEGREDO_RFC, certo[:5], instante=T))
        self.assertIsNone(totp.verificar(SEGREDO_RFC, "", instante=T))

    def test_recusa_reutilizar_codigo_ja_aceite(self):
        c = totp.codigo(SEGREDO_RFC, T)
        passo = totp.verificar(SEGREDO_RFC, c, instante=T)
        self.assertIsNone(totp.verificar(SEGREDO_RFC, c, instante=T, ultimo_passo=passo))

    def test_recusa_codigo_anterior_ao_ultimo_aceite(self):
        passo = totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, T), instante=T)
        anterior = totp.codigo(SEGREDO_RFC, T - 30)
        self.assertIsNone(totp.verificar(SEGREDO_RFC, anterior, instante=T, ultimo_passo=passo))

    def test_aceita_codigo_seguinte_ao_ultimo_aceite(self):
        passo = totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, T), instante=T)
        self.assertIsNotNone(totp.verificar(SEGREDO_RFC, totp.codigo(SEGREDO_RFC, T + 30), instante=T + 30, ultimo_passo=passo))

    def test_recusa_digitos_nao_ascii_sem_rebentar(self):
        self.assertIsNone(totp.verificar(SEGREDO_RFC, "١٢٣٤٥٦", instante=T))

    def test_aceita_espacos_no_codigo(self):
        c = totp.codigo(SEGREDO_RFC, T)
        self.assertIsNotNone(totp.verificar(SEGREDO_RFC, f" {c[:3]} {c[3:]} ", instante=T))


class TestChaveERecuperacao(unittest.TestCase):
    def test_segredo_novo_tem_160_bits_e_e_diferente_cada_vez(self):
        a, b = totp.novo_segredo(), totp.novo_segredo()
        self.assertEqual(len(a), 32)  # 20 bytes em Base32
        self.assertNotEqual(a, b)
        self.assertEqual(len(totp.codigo(a)), 6)

    def test_formatar_em_grupos_de_4_e_continua_valido(self):
        f = totp.formatar(SEGREDO_RFC)
        self.assertEqual(f.split()[0], "GEZD")
        self.assertEqual(totp.codigo(f, T), totp.codigo(SEGREDO_RFC, T))

    def test_codigos_recuperacao_8_diferentes_e_so_hash_guardado(self):
        codigos, hashes = totp.codigos_recuperacao()
        self.assertEqual(len(set(codigos)), 8)
        self.assertTrue(all(len(c.replace("-", "")) == 12 for c in codigos))
        self.assertFalse(any(c in h for c in codigos for h in hashes))
        self.assertEqual(totp.hash_recuperacao(codigos[0].lower().replace("-", " ")), hashes[0])


@unittest.skipUnless(sys.platform == "win32", "DPAPI so existe no Windows")
class TestCifra(unittest.TestCase):
    def test_cifra_e_decifra(self):
        self.assertEqual(totp.desproteger(totp.proteger(SEGREDO_RFC)), SEGREDO_RFC)

    def test_texto_cifrado_nao_revela_a_chave(self):
        self.assertNotIn(SEGREDO_RFC, totp.proteger(SEGREDO_RFC))

    def test_cifra_adulterada_da_erro(self):
        import base64
        dados = bytearray(base64.b64decode(totp.proteger(SEGREDO_RFC)))
        dados[-5] ^= 0xFF
        with self.assertRaises(OSError):
            totp.desproteger(base64.b64encode(bytes(dados)).decode())


if __name__ == "__main__":
    unittest.main()
