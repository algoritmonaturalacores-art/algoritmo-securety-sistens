import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from seguranca import endurecer, eventos, exposicao, notificar, tarefa, vigilancia
from seguranca.registo import Registo, RegistoError, validar_palavra_passe

AGORA = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)


def ev(log, i, dados, minutos=0, registo=1):
    return {"log": log, "id": i, "hora": (AGORA + timedelta(minutes=minutos)).isoformat(), "registo": registo, "dados": dados}


class EventosTests(unittest.TestCase):
    def test_forca_bruta_detetada(self):
        lista = [ev("Security", 4625, {"IpAddress": "203.0.113.9", "LogonType": "10", "TargetUserName": "admin"}, k, k) for k in range(6)]
        alertas = eventos.analisar(lista)
        self.assertEqual(alertas[0]["tipo"], "forca-bruta")
        self.assertEqual(alertas[0]["nivel"], "critico")
        self.assertIn("203.0.113.9", alertas[0]["detalhe"])

    def test_poucas_falhas_espacadas_nao_sao_forca_bruta(self):
        lista = [ev("Security", 4625, {"IpAddress": "-", "LogonType": "2", "TargetUserName": "nuno"}, k * 30, k) for k in range(5)]
        alertas = eventos.analisar(lista)
        self.assertEqual(alertas[0]["tipo"], "entrada-falhada")
        self.assertIn("teclado", alertas[0]["detalhe"])

    def test_entrada_rdp_externa_critica_e_local_ignorada(self):
        externa = ev("Security", 4624, {"IpAddress": "198.51.100.7", "LogonType": "10", "TargetUserName": "nuno"})
        local = ev("Security", 4624, {"IpAddress": "127.0.0.1", "LogonType": "3", "TargetUserName": "nuno"}, registo=2)
        alertas = eventos.analisar([externa, local])
        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["nivel"], "critico")

    def test_admin_adicionado_e_registo_apagado(self):
        alertas = eventos.analisar([
            ev("Security", 4732, {"TargetSid": "S-1-5-32-544", "MemberName": "hacker", "TargetUserName": "Administradores"}),
            ev("Security", 1102, {}, registo=2)])
        self.assertEqual({a["nivel"] for a in alertas}, {"critico"})

    def test_servico_em_pasta_de_utilizador_e_suspeito(self):
        suspeito = eventos.analisar([ev("System", 7045, {"ServiceName": "x", "ImagePath": r"C:\Users\n\AppData\Local\Temp\x.exe"})])
        normal = eventos.analisar([ev("System", 7045, {"ServiceName": "Chrome", "ImagePath": r'"C:\Program Files\Google\x.exe"'})])
        self.assertEqual(suspeito[0]["nivel"], "critico")
        self.assertEqual(normal[0]["nivel"], "info")

    def test_exclusao_no_antivirus_e_critica_e_ruido_ignorado(self):
        alertas = eventos.analisar([
            ev("Microsoft-Windows-Windows Defender/Operational", 5007, {"New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\x = 0x0"}),
            ev("Microsoft-Windows-Windows Defender/Operational", 5007, {"New Value": r"HKLM\...\Diagnostics\InitializingComponentProgress = LoadingEngine"}, registo=2)])
        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["tipo"], "defender-exclusao")

    def test_regra_firewall_so_entrada_publica(self):
        base = {"Direction": "1", "Action": "3", "RuleName": "App", "ApplicationPath": r"C:\Program Files\App\a.exe"}
        alertas = eventos.analisar([
            ev("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2097, dict(base, Profiles="4")),
            ev("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 2097, dict(base, Direction="2", Profiles="7"), registo=2)])
        self.assertEqual(len(alertas), 1)
        self.assertEqual(alertas[0]["nivel"], "aviso")

    def test_dados_estranhos_nao_rebentam(self):
        self.assertEqual(eventos.analisar([{"log": None, "id": "x", "dados": "lixo"}]), [])

    def test_repetidos_agrupados(self):
        e1 = ev("System", 104, {})
        alertas = eventos.analisar([e1, dict(e1, registo=9)])
        self.assertEqual(alertas[0]["repeticoes"], 2)


class ExposicaoTests(unittest.TestCase):
    DADOS = {"rdp": {"ligado": True, "assistencia": False, "nla": False}, "servicos": [], "remoto_processos": ["AnyDesk"],
             "remoto_instalados": [], "portas": [{"porta": 7070, "processo": "AnyDesk"}, {"porta": 445, "processo": "System"}],
             "firewall": [{"perfil": "Public", "ligado": False, "entrada": "NotConfigured"}], "regras_publicas": [],
             "contas": [{"nome": "Convidado", "ativa": True, "exige_password": False, "rid": 501}],
             "administradores": [], "smb": {"smb1": True, "partilhas": []},
             "politicas": {"uac": True, "uac_pedido": 5, "bloqueia_password_vazia": True},
             "defender": {"tempo_real": True, "anti_adulteracao": True, "desatualizado": False, "pua": 1, "protecao_rede": 1}}

    def test_regras_principais(self):
        codigos = {a["codigo"] for a in exposicao.analisar(self.DADOS)}
        for esperado in ("rdp-ligado", "remoto-ativo", "portas-AnyDesk", "firewall-Public", "convidado", "smb1"):
            self.assertIn(esperado, codigos)
        self.assertNotIn("portas-System", codigos)

    def test_sem_dados_nao_e_seguro(self):
        achados = exposicao.analisar({})
        self.assertTrue(any(a["codigo"] == "defender-desconhecido" for a in achados))
        self.assertTrue(any(a["codigo"] == "firewall-desconhecida" for a in achados))
        self.assertLess(exposicao.pontuacao(exposicao.analisar({"erro_geral": "x"})), 100)

    def test_diferencas(self):
        base = exposicao.assinatura({"administradores": ["PC\\nuno"], "portas": []})
        atual = exposicao.assinatura({"administradores": ["PC\\nuno", "PC\\intruso"], "portas": [{"porta": 4444, "processo": "nc"}]})
        alertas = exposicao.diferencas(base, atual)
        self.assertIn(("critico", "PC\\intruso"), {(a["nivel"], a["detalhe"]) for a in alertas})
        self.assertIn("4444/nc", {a["detalhe"] for a in alertas})


class RegistoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.r = Registo(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_cadeia_deteta_alteracao_e_remocao(self):
        for k in range(3):
            self.r.adicionar({"nivel": "aviso", "titulo": f"a{k}", "detalhe": ""})
        self.assertEqual(self.r.verificar_cadeia(), (True, 3))
        linhas = self.r.alertas.read_text(encoding="utf-8").splitlines()
        self.r.alertas.write_text("\n".join([linhas[0], linhas[1].replace("a1", "xx"), linhas[2]]) + "\n", encoding="utf-8")
        self.assertFalse(self.r.verificar_cadeia()[0])
        self.r.alertas.write_text("\n".join(linhas[:2]) + "\n", encoding="utf-8")
        self.assertFalse(self.r.verificar_cadeia()[0])

    def test_marcacao_nao_reescreve(self):
        a = self.r.adicionar({"nivel": "aviso", "titulo": "t", "detalhe": ""})
        self.assertEqual(self.r.marcar([a["id"], 999], "conhecido"), 1)
        self.assertEqual(self.r.listar()[0]["estado"], "conhecido")
        self.assertTrue(self.r.verificar_cadeia()[0])
        with self.assertRaises(RegistoError):
            self.r.marcar([a["id"]], "apagado")

    def test_palavra_passe_e_bloqueio(self):
        self.assertIsNotNone(validar_palavra_passe("curta"))
        self.r.definir_palavra_passe("Acores-2026!seguro")
        self.assertNotIn("Acores-2026", self.r.acesso_f.read_text())
        self.assertTrue(self.r.verificar_palavra_passe("Acores-2026!seguro")[0])
        for _ in range(5):
            ok, msg = self.r.verificar_palavra_passe("errada")
            self.assertFalse(ok)
        self.assertIn("Bloqueado", msg)
        self.assertFalse(self.r.verificar_palavra_passe("Acores-2026!seguro")[0])


class NotificarTests(unittest.TestCase):
    class Abridor:
        def __init__(self):
            self.pedidos = []

        def open(self, pedido, timeout):
            self.pedidos.append(pedido)
            resposta = io.BytesIO(b"{}")
            resposta.status = 200
            return resposta

    def test_telemovel_desligado_por_omissao(self):
        abridor = self.Abridor()
        r = notificar.enviar({"nivel_notificacao": "aviso"}, {"nivel": "critico", "titulo": "t", "detalhe": "d"}, abridor, pc=lambda t, m: True)
        self.assertFalse(r["telemovel"])
        self.assertEqual(abridor.pedidos, [])

    def test_topico_invalido_ou_servidor_http_recusado(self):
        abridor = self.Abridor()
        for config in ({"ntfy_topico": "curto"}, {"ntfy_topico": "a" * 30, "ntfy_servidor": "http://inseguro.pt"},
                       {"ntfy_topico": "../../x" + "a" * 30}):
            self.assertFalse(notificar.notificar_telemovel(config, "t", "m", abridor=abridor))
        self.assertEqual(abridor.pedidos, [])

    def test_envio_e_nivel_minimo(self):
        abridor = self.Abridor()
        config = {"ntfy_topico": notificar.novo_topico(), "nivel_notificacao": "critico"}
        notificar.enviar(config, {"nivel": "aviso", "titulo": "t", "detalhe": "d"}, abridor, pc=lambda t, m: True)
        self.assertEqual(abridor.pedidos, [])
        notificar.enviar(config, {"nivel": "critico", "titulo": "Ataque à conta", "detalhe": "x\u202e"}, abridor, pc=lambda t, m: True)
        pedido = abridor.pedidos[0]
        self.assertTrue(pedido.full_url.startswith("https://ntfy.sh/an-seg-"))
        self.assertEqual(pedido.get_header("Priority"), "5")
        self.assertNotIn("\u202e", pedido.data.decode())
        pedido.get_header("Title").encode("ascii")


class VigilanciaTests(unittest.TestCase):
    def test_ciclo_regista_notifica_e_nao_repete(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Registo(tmp)
            falhas = [ev("Security", 4625, {"IpAddress": "203.0.113.5", "LogonType": "3", "TargetUserName": "x"}, k, k) for k in range(6)]
            enviados = []
            ler = lambda desde: {"eventos": falhas, "inacessiveis": []}
            recolher = lambda: {"administradores": ["PC\\nuno"]}
            primeiro = vigilancia.ciclo(r, {}, True, ler, recolher, lambda c, a: enviados.append(a))
            self.assertEqual(primeiro[0]["tipo"], "forca-bruta")
            self.assertEqual(len(enviados), 1)
            self.assertEqual(vigilancia.ciclo(r, {}, False, ler, recolher, lambda c, a: enviados.append(a)), [])
            recolher2 = lambda: {"administradores": ["PC\\nuno", "PC\\novo"]}
            terceiro = vigilancia.ciclo(r, {}, True, ler, recolher2, lambda c, a: enviados.append(a))
            self.assertEqual(terceiro[0]["titulo"], "Nova conta com privilegios de administrador")

    def test_sem_admin_avisa_uma_vez(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = Registo(tmp)
            ler = lambda desde: {"eventos": [], "inacessiveis": [{"log": "Security", "erro": "UnauthorizedAccessException"}]}
            um = vigilancia.ciclo(r, {}, False, ler, lambda: {}, lambda c, a: None)
            dois = vigilancia.ciclo(r, {}, False, ler, lambda: {}, lambda c, a: None)
            self.assertEqual([a["tipo"] for a in um], ["sem-admin"])
            self.assertEqual(dois, [])


class ProtecaoTests(unittest.TestCase):
    def test_endurecer_exige_confirmacao_e_lista_fechada(self):
        with self.assertRaises(endurecer.EndurecerError):
            endurecer.aplicar("rdp", "sim")
        with self.assertRaises(endurecer.EndurecerError):
            endurecer.aplicar("formatar-disco", True)
        with self.assertRaises(endurecer.EndurecerError):
            endurecer.retirar_perfil_publico("x'; Remove-Item C:\\ -Recurse #", True)

    def test_python_em_pasta_de_utilizador_recusado(self):
        self.assertTrue(tarefa.pasta_do_utilizador(r"C:\Users\qualquer\AppData\Local\Programs\Python\python.exe"))
        self.assertFalse(tarefa.pasta_do_utilizador(r"C:\Program Files\Python312\python.exe"))
        with patch("seguranca.tarefa.e_admin", return_value=True), patch("sys.executable", r"C:\Users\x\AppData\python.exe"):
            with self.assertRaises(tarefa.TarefaError):
                tarefa.instalar(Path("."))

    def test_parametros_nunca_interpolados(self):
        from seguranca import ps
        for script in (notificar.TOAST, tarefa.REGISTAR, endurecer.REGRA_PUBLICA, eventos.SCRIPT):
            self.assertNotIn("{", script.replace("${", "").replace("@{", "").replace("{ ", "").replace("{$", "").replace("[System[", "")[:0])
        with self.assertRaises(ps.PSError):
            ps.executar("1", parametros={"OUTRO": "x"})
        with self.assertRaises(ps.PSError):
            ps.executar("1", parametros={"AN_X": "a\x00b"})


class CorrecoesTests(unittest.TestCase):
    def test_ficheiro_de_alertas_corrompido_nao_para_a_vigilancia(self):
        with tempfile.TemporaryDirectory() as pasta:
            registo = Registo(pasta)
            registo.adicionar({"nivel": "aviso", "titulo": "x"})
            with open(registo.alertas, "a", encoding="utf-8") as f:
                f.write("{linha partida\n")
            config = {"nivel_notificacao": "critico", "notificar_pc": False}
            novos = vigilancia.ciclo(registo, config, ler_eventos=lambda d: {"eventos": [], "inacessiveis": []},
                                     recolher=lambda: {"erro_geral": "x"}, enviar=lambda c, a: None)
            self.assertEqual(novos[0]["tipo"], "registo-adulterado")
            self.assertTrue(list(Path(pasta).glob("alertas.corrompido.*.jsonl")))
            self.assertEqual(registo.verificar_cadeia()[0], True)

    def test_vigiar_continua_apos_erro_de_registo(self):
        chamadas = []

        def ciclo_falha(*a, **k):
            chamadas.append(1)
            raise RegistoError("falha")
        with patch.object(vigilancia, "ciclo", ciclo_falha), patch.object(vigilancia.time, "sleep"):
            vigilancia.vigiar(Registo(tempfile.mkdtemp()), parar=lambda: len(chamadas) >= 3, saida=lambda t: None)
        self.assertEqual(len(chamadas), 3)

    def test_system32_no_meio_do_caminho_nao_e_seguro(self):
        self.assertEqual(eventos.nivel_caminho(r"C:\evil\system32\svc.exe"), "aviso")
        self.assertEqual(eventos.nivel_caminho(r"C:\malware\program files\a.exe"), "aviso")
        self.assertEqual(eventos.nivel_caminho(r"C:\Windows\System32\svchost.exe"), "info")
        self.assertEqual(eventos.nivel_caminho(r'"C:\Program Files\App\a.exe" -k x'), "info")
        self.assertEqual(eventos.nivel_caminho(r"system32\drivers\a.sys"), "info")

    def test_instalar_nao_importa_estado_da_pasta_do_utilizador(self):
        with tempfile.TemporaryDirectory() as raiz:
            raiz = Path(raiz)
            origem, destino, estado, perfil = raiz / "o", raiz / "d", raiz / "e", raiz / "p"
            for nome in tarefa.FICHEIROS:
                (origem / nome).parent.mkdir(parents=True, exist_ok=True)
                (origem / nome).write_text("x")
            antiga = perfil / "AlgoritmoSecuretySistens"
            antiga.mkdir(parents=True)
            for nome in ("config.json", "acesso.json", "linha_base.json"):
                (antiga / nome).write_text("{}")
            with patch.object(tarefa, "verificar_requisitos", return_value=[]), patch.object(tarefa, "DESTINO", destino), \
                    patch.object(tarefa, "ESTADO", estado), patch.object(tarefa, "executar"), \
                    patch.dict("os.environ", {"LOCALAPPDATA": str(perfil)}):
                tarefa.instalar(origem)
            self.assertEqual(list(estado.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
