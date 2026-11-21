"""servico vulneravel: reutilizacao de nonce em ctr

# simula um servico mal configurado que cifra varias mensagens em aes-ctr
# usando sempre o MESMO par (chave, nonce) -- um erro classico (ex: nonce
# fixo "por simplicidade", ou gerado de forma que repete). em ctr, isso
# faz o mesmo keystream ser reaproveitado, quebrando a seguranca do modo
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from DCC075_TrabalhoFinal.common.aes_utils import aes_ctr_crypt, random_bytes  # noqa: E402

_KEY = random_bytes(16)
_NONCE_FIXO = random_bytes(8)  # bug: deveria ser aleatorio a cada mensagem


def cifrar_mensagem(plaintext: bytes) -> bytes:
    """cifra uma mensagem reaproveitando sempre o mesmo nonce"""
    return aes_ctr_crypt(_KEY, _NONCE_FIXO, plaintext)


if __name__ == "__main__":
    c1 = cifrar_mensagem(b"transferir R$100 para conta 111")
    c2 = cifrar_mensagem(b"transferir R$900 para conta 222")
    print("ciphertext 1 (hex):", c1.hex())
    print("ciphertext 2 (hex):", c2.hex())
