"""servico vulneravel: bit-flipping em cbc

# simula um servico que gera um "cookie de sessao" estruturado como
# campo=valor;campo=valor, cifrado em aes-cbc, e que depois confia nesse
# cookie decriptado para decidir permissoes -- um padrao comum (e perigoso)
# de usar criptografia simetrica sem autenticacao para guardar estado
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from DCC075_TrabalhoFinal.common.aes_utils import (  # noqa: E402
    aes_cbc_decrypt_raw,
    aes_cbc_encrypt,
    pkcs7_unpad,
    random_bytes,
)

_KEY = random_bytes(16)

_PREFIXO = b"usuario="
_SUFIXO = b";isadmin=0"


def criar_cookie(nome_usuario: str) -> bytes:
    """gera um cookie cifrado a partir de um nome de usuario controlado

    pelo atacante -- igual a um servico que recebe o usuario no cadastro
    e sempre marca admin=false para quem nao e administrador. o servico
    sanitiza ';' e '=' para o atacante nao poder injetar campos direto
    """
    nome_sanitizado = nome_usuario.replace(";", "").replace("=", "")
    plaintext = _PREFIXO + nome_sanitizado.encode() + _SUFIXO

    iv = random_bytes(16)
    ciphertext = aes_cbc_encrypt(_KEY, iv, plaintext)
    return iv + ciphertext


def e_admin(cookie: bytes) -> bool:
    """decripta o cookie e diz se o servico concederia acesso de admin

    (o atacante nunca ve o plaintext -- so o resultado desta checagem,
    como um servico real que so retorna "acesso concedido/negado")
    """
    iv, ciphertext = cookie[:16], cookie[16:]
    plaintext = aes_cbc_decrypt_raw(_KEY, iv, ciphertext)
    try:
        plaintext = pkcs7_unpad(plaintext)
    except Exception:
        return False
    return b";isadmin=1" in plaintext


if __name__ == "__main__":
    cookie = criar_cookie("joao")
    print("cookie (hex):", cookie.hex())
    print("e admin?", e_admin(cookie))
