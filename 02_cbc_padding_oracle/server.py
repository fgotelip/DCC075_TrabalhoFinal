"""servico vulneravel: padding oracle em cbc

# simula um endpoint que recebe um cookie/token cifrado em aes-cbc e, ao
# decriptar, informa se o padding pkcs#7 era valido ou nao (ex: por uma
# mensagem de erro diferente, ou por um status http diferente) -- essa
# diferenca de comportamento e o "oracle" que o atacante explora
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from DCC075_TrabalhoFinal.common.aes_utils import (  
    aes_cbc_decrypt_raw,
    aes_cbc_encrypt,
    pkcs7_unpad,
    random_bytes,
)

_KEY = random_bytes(16)

# mensagem "secreta" que o servico emite como cookie cifrado para o cliente
_MENSAGEM = b"usuario=convidado;acesso=basico;valido_ate=2026-12-31"


def emitir_cookie() -> bytes:
    """gera um cookie cifrado (iv || ciphertext), como um servico real faria"""
    iv = random_bytes(16)
    ciphertext = aes_cbc_encrypt(_KEY, iv, _MENSAGEM)
    return iv + ciphertext


def padding_e_valido(cookie: bytes) -> bool:
    """unico ponto de contato do atacante: recebe iv||ciphertext e devolve

    apenas se o padding bateu ou nao -- simula, por exemplo, o servico
    responder http 200 vs 400/500 dependendo do padding, sem revelar o
    conteudo decriptado
    """
    iv, ciphertext = cookie[:16], cookie[16:]
    plaintext = aes_cbc_decrypt_raw(_KEY, iv, ciphertext)
    try:
        pkcs7_unpad(plaintext)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    cookie = emitir_cookie()
    print("cookie emitido (hex):", cookie.hex())
    print("padding valido?", padding_e_valido(cookie))
