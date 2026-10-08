"""Groq Free: sem SDK, sem retries, sem ferramentas e sem guardar chaves."""
import json
import re
import urllib.error
import urllib.request

from . import VERSION

ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "openai/gpt-oss-20b"
MAX_RESPONSE = 262144


class APIError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise APIError("Redirecionamento recusado para proteger a chave API.")


def safe_text(value):
    if not isinstance(value, str):
        raise APIError("Resposta do modelo sem texto utilizavel.")
    return "".join(c for c in value if c in "\n\t" or (c.isprintable() and not 0x202A <= ord(c) <= 0x202E))


def ask(key, messages, opener=None):
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", key):
        raise APIError("Formato da chave invalido. Obtem uma chave na consola Groq.")
    payload = {"model": MODEL, "messages": messages, "max_completion_tokens": 1800,
               "reasoning_effort": "low", "include_reasoning": False, "stream": False}
    request = urllib.request.Request(ENDPOINT,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                 "User-Agent": "AlgoritmoSecuretySistens/" + VERSION}, method="POST")
    client = opener or urllib.request.build_opener(NoRedirect())
    try:
        with client.open(request, timeout=35) as response:
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise APIError("Resposta demasiado grande; pedido terminado.")
        result = json.loads(raw)
        choice = result["choices"][0]
        content = safe_text(choice["message"]["content"])
        if not content.strip():
            raise APIError("A API nao devolveu texto. Nao foi feita outra chamada.")
        if choice.get("finish_reason") == "length":
            content += "\n[Resposta interrompida no limite de tokens; nao foi repetida.]"
        return content
    except urllib.error.HTTPError as error:
        known = {401: "Chave rejeitada. Verifica ou substitui a chave.",
                 403: "Acesso ao modelo nao autorizado nesta conta.",
                 404: "Modelo indisponivel. Consulta a lista atual de modelos Groq.",
                 429: "Quota gratuita ou limite de pedidos atingido. Aguarda; nao ha repeticao automatica."}
        raise APIError(known.get(error.code, f"API indisponivel (HTTP {error.code}). Nao foi feita outra chamada.")) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise APIError("Falha de ligacao ou tempo esgotado. O diagnostico local continua disponivel.") from None
    except (ValueError, KeyError, IndexError, TypeError):
        raise APIError("Resposta da API num formato inesperado. Nao foi feita outra chamada.") from None
