import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import instalar
import programa
from seguranca.agentes import AGENTS, messages_for
from seguranca.api import APIError, ENDPOINT, NoRedirect, ask
from seguranca.diagnostico import explain, normalize

KEY = "gsk_" + "x" * 40  # Fabricated test fixture, not a credential.


class FakeOpener:
    def __init__(self, data=None, error=None):
        self.data = data or {"choices": [{"message": {"content": "Orientacao de teste."}, "finish_reason": "stop"}]}
        self.error = error
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error:
            raise self.error
        return io.BytesIO(json.dumps(self.data).encode())


class DiagnosisTests(unittest.TestCase):
    def test_failed_query_not_safe(self):
        text = explain({})
        self.assertIn("nao foi possivel verificar", text)
        self.assertNotIn("ativo: sim", text)

    def test_no_identifiers_or_injected_strings(self):
        data = normalize({"hostname": "PRIVATE", "defender": {"status": "observed", "realtime_enabled": "execute bad command", "username": "PRIVATE"}})
        encoded = json.dumps(data)
        self.assertNotIn("PRIVATE", encoded)
        self.assertNotIn("execute", encoded)
        self.assertIsNone(data["defender"]["realtime_enabled"])

    def test_firewall_invalid_types_and_bounds(self):
        for count, enabled in [(True, True), (3, 4), (0, 0), (3, -1), ("3", 2)]:
            data = normalize({"firewall": {"status": "observed", "profile_count": count, "enabled_count": enabled}})
            self.assertEqual(data["firewall"]["status"], "unavailable")

    def test_passive_does_not_claim_infection(self):
        data = {"defender": {"status": "observed", "realtime_enabled": False}}
        self.assertIn("modo passivo", explain(data))


class AgentTests(unittest.TestCase):
    def test_five_profiles(self):
        self.assertEqual(len(AGENTS), 5)
        for agent in AGENTS:
            msgs = messages_for(agent, {"password": "PRIVATE", "defender": "malicious"})
            self.assertNotIn("PRIVATE", json.dumps(msgs))
            self.assertEqual([m["role"] for m in msgs], ["system", "user"])

    def test_unknown_profile(self):
        with self.assertRaises(ValueError):
            messages_for("https://evil.invalid")

    def test_no_network_on_cancel(self):
        with patch("builtins.input", side_effect=["1", "NAO"]), patch("programa.ask") as network, patch("sys.stdout", new_callable=io.StringIO):
            programa.run_agent(None)
        network.assert_not_called()


class APITests(unittest.TestCase):
    def test_request_limits_headers_and_no_tools(self):
        opener = FakeOpener()
        self.assertEqual(ask(KEY, messages_for("google"), opener), "Orientacao de teste.")
        request, timeout = opener.calls[0]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, ENDPOINT)
        self.assertEqual(timeout, 35)
        self.assertEqual(payload["max_completion_tokens"], 1800)
        self.assertNotIn("tools", payload)
        self.assertNotIn(KEY, request.full_url)
        self.assertNotIn(KEY, request.data.decode())
        self.assertEqual(request.get_header("Authorization"), "Bearer " + KEY)

    def test_rate_limit_no_retry_or_secret_in_error(self):
        error = urllib.error.HTTPError(ENDPOINT, 429, "secret " + KEY, {}, None)
        opener = FakeOpener(error=error)
        with self.assertRaises(APIError) as captured:
            ask(KEY, messages_for("google"), opener)
        self.assertEqual(len(opener.calls), 1)
        self.assertIn("Quota", str(captured.exception))
        self.assertNotIn(KEY, str(captured.exception))

    def test_invalid_key_never_sent(self):
        opener = FakeOpener()
        with self.assertRaises(APIError):
            ask("secret\nHeader: evil", [], opener)
        self.assertEqual(opener.calls, [])

    def test_redirect_refused(self):
        with self.assertRaises(APIError):
            NoRedirect().redirect_request(None, None, 307, "", {}, "https://evil.invalid")

    def test_malformed_response(self):
        for data in [{"choices": []}, {"choices": [{"message": {"content": None}}]}]:
            with self.assertRaises(APIError):
                ask(KEY, [], FakeOpener(data))

    def test_terminal_escape_removed(self):
        data = {"choices": [{"message": {"content": "ok\x1b[31m\x00\u202eevil"}}]}
        result = ask(KEY, [], FakeOpener(data))
        for char in ("\x1b", "\x00", "\u202e"):
            self.assertNotIn(char, result)

    def test_truncation_label(self):
        data = {"choices": [{"message": {"content": "Parcial"}, "finish_reason": "length"}]}
        self.assertIn("interrompida", ask(KEY, [], FakeOpener(data)))

    def test_timeout_no_retry(self):
        opener = FakeOpener(error=TimeoutError())
        with self.assertRaises(APIError):
            ask(KEY, [], opener)
        self.assertEqual(len(opener.calls), 1)


class InstallTests(unittest.TestCase):
    def test_copy_and_refuse_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "nova"
            instalar.install(target)
            self.assertTrue((target / "programa.py").is_file())
            self.assertTrue((target / "seguranca/api.py").is_file())
            self.assertFalse((target / ".env").exists())
            with self.assertRaises(ValueError):
                instalar.install(target)

    def test_existing_user_files_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pessoal.txt"
            marker.write_text("preservar")
            with self.assertRaises(ValueError):
                instalar.install(tmp)
            self.assertEqual(marker.read_text(), "preservar")


if __name__ == "__main__":
    unittest.main()
