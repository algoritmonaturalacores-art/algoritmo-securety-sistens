"""Codigos de 6 digitos (TOTP, RFC 6238) compativeis com Google Authenticator, Ente Auth e semelhantes. So biblioteca padrao."""
import base64
import ctypes
import hashlib
import hmac
import secrets
import struct
import time

PASSO = 30
DIGITOS = 6


def _chave(segredo):
    limpo = "".join(str(segredo).split()).upper()
    return base64.b32decode(limpo + "=" * (-len(limpo) % 8))


def _passo(instante):
    return int((time.time() if instante is None else instante) // PASSO)


def codigo(segredo, instante=None, n=None):
    n = _passo(instante) if n is None else n
    digest = hmac.new(_chave(segredo), struct.pack(">Q", n), hashlib.sha1).digest()
    pos = digest[-1] & 0x0F
    valor = struct.unpack(">I", digest[pos:pos + 4])[0] & 0x7FFFFFFF
    return str(valor % 10 ** DIGITOS).zfill(DIGITOS)


def verificar(segredo, introduzido, instante=None, janela=1, ultimo_passo=-1):
    """Devolve o passo aceite, ou None. Aceita +-30 s de diferenca entre o relogio do PC e o do telemovel
    e recusa codigos iguais ou anteriores ao ultimo aceite (ninguem reutiliza um codigo que viu)."""
    introduzido = "".join(str(introduzido).split())
    if len(introduzido) != DIGITOS or not (introduzido.isascii() and introduzido.isdigit()):
        return None
    atual = _passo(instante)
    for n in range(atual - janela, atual + janela + 1):
        if n > ultimo_passo and hmac.compare_digest(codigo(segredo, n=n), introduzido):
            return n
    return None


def novo_segredo():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def formatar(segredo):
    return " ".join(segredo[i:i + 4] for i in range(0, len(segredo), 4))


def codigos_recuperacao(n=8):
    """Codigos de uso unico para quando o telemovel nao estiver disponivel. So o hash e guardado."""
    codigos = set()
    while len(codigos) < n:
        codigos.add("-".join(secrets.token_hex(2).upper() for _ in range(3)))
    codigos = sorted(codigos)
    return codigos, [hash_recuperacao(c) for c in codigos]


def hash_recuperacao(texto):
    return hashlib.sha256("".join(c for c in str(texto).upper() if c.isascii() and c.isalnum()).encode("ascii")).hexdigest()


# ---------- DPAPI: cifra ligada a esta conta do Windows ----------
class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(dados, cifrar):
    entrada = ctypes.create_string_buffer(dados, len(dados))
    blob_in = _Blob(len(dados), ctypes.cast(entrada, ctypes.POINTER(ctypes.c_char)))
    blob_out = _Blob()
    crypt32 = ctypes.WinDLL("crypt32")
    funcao = crypt32.CryptProtectData if cifrar else crypt32.CryptUnprotectData
    if not funcao(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out)):  # 0x1: sem janelas
        raise OSError("DPAPI recusou os dados.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.WinDLL("kernel32").LocalFree(blob_out.pbData)


def proteger(texto):
    return base64.b64encode(_dpapi(texto.encode("utf-8"), True)).decode("ascii")


def desproteger(texto):
    return _dpapi(base64.b64decode(texto), False).decode("utf-8")
