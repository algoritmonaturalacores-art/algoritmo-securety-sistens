"""Codigos de 6 digitos (TOTP, RFC 6238) compativeis com Ente Auth, Google Authenticator e semelhantes.
So biblioteca padrao. O segredo fica cifrado com DPAPI do Windows e num ficheiro que so administradores leem."""
import base64
import ctypes
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

PASSO = 30
DIGITOS = 6


def novo_segredo():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def _chave(segredo):
    limpo = "".join(str(segredo).split()).upper()
    return base64.b32decode(limpo + "=" * (-len(limpo) % 8))


def codigo(segredo, instante=None, passo_n=None):
    n = int((time.time() if instante is None else instante) // PASSO) if passo_n is None else passo_n
    digest = hmac.new(_chave(segredo), struct.pack(">Q", n), hashlib.sha1).digest()
    pos = digest[-1] & 0x0F
    valor = struct.unpack(">I", digest[pos:pos + 4])[0] & 0x7FFFFFFF
    return str(valor % 10 ** DIGITOS).zfill(DIGITOS)


def verificar(segredo, introduzido, ultimo_passo=-1, instante=None, janela=1):
    """Devolve o passo aceite, ou None. Aceita +-30 s de diferenca no relogio e recusa reutilizar um codigo."""
    introduzido = "".join(c for c in str(introduzido) if c.isdigit())
    if len(introduzido) != DIGITOS:
        return None
    atual = int((time.time() if instante is None else instante) // PASSO)
    for n in range(atual - janela, atual + janela + 1):
        if n > ultimo_passo and hmac.compare_digest(codigo(segredo, passo_n=n), introduzido):
            return n
    return None


def formatar(segredo):
    return " ".join(segredo[i:i + 4] for i in range(0, len(segredo), 4))


def uri(segredo, conta, emissor="Algoritmo Natural"):
    rotulo = urllib.parse.quote(f"{emissor}:{conta}")
    return f"otpauth://totp/{rotulo}?secret={segredo}&issuer={urllib.parse.quote(emissor)}&digits={DIGITOS}&period={PASSO}"


def codigos_recuperacao(n=8):
    """Codigos de uso unico para quando o telemovel nao estiver disponivel. Guarda-se so o hash."""
    codigos = ["-".join(secrets.token_hex(2).upper() for _ in range(3)) for _ in range(n)]
    return codigos, [hash_recuperacao(c) for c in codigos]


def hash_recuperacao(texto):
    return hashlib.sha256("".join(c for c in texto.upper() if c.isalnum()).encode("ascii")).hexdigest()


# ---------- DPAPI (cifra ligada a esta conta do Windows) ----------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(dados, cifrar):
    entrada = ctypes.create_string_buffer(dados, len(dados))
    blob_in = _Blob(len(dados), ctypes.cast(entrada, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    crypt32 = ctypes.windll.crypt32
    funcao = crypt32.CryptProtectData if cifrar else crypt32.CryptUnprotectData
    # 0x1 = CRYPTPROTECT_UI_FORBIDDEN
    if not funcao(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):
        raise OSError("DPAPI falhou.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def proteger(texto):
    return base64.b64encode(_dpapi(texto.encode("utf-8"), True)).decode("ascii")


def desproteger(texto):
    return _dpapi(base64.b64decode(texto), False).decode("utf-8")
