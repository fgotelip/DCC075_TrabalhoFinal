"""ataque: bit-flipping em cbc (elevacao de privilegio)

# em cbc, plaintext[i] = decrypt(ciphertext[i]) XOR ciphertext[i-1]. logo,
# se o atacante flipar um bit no ciphertext do bloco i-1, o MESMO bit flipa
# no plaintext do bloco i apos a decriptacao -- sem precisar da chave.
# o preco e que o bloco i-1 vira lixo ilegivel, entao o ataque so funciona
# em campos que o servico nao valida (aqui, o campo "usuario=" anterior).
#
# o atacante controla o campo "usuario" e, com isso, consegue alinhar o
# campo sensivel (";isadmin=0") exatamente no inicio de um bloco de 16
# bytes -- e entao flipa 1 bit no bloco anterior para trocar '0' por '1'
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import criar_cookie, e_admin 

BLOCK_SIZE = 16
PREFIXO_LEN = len(b"usuario=")
ALVO = b";isadmin=0"
POSICAO_DO_DIGITO = ALVO.index(b"0")  # offset do caractere que queremos trocar


def alinhar_usuario_no_bloco() -> str:
    """escolhe um tamanho de usuario que empurre ';isadmin=0' para o

    inicio exato de um bloco de 16 bytes, usando so letras (sem ';' ou
    '='), que e tudo que o campo "usuario" permite
    """
    faltam = (-PREFIXO_LEN) % BLOCK_SIZE
    return "A" * faltam


def atacar() -> bool:
    usuario = alinhar_usuario_no_bloco()
    cookie = criar_cookie(usuario)
    print(f"[*] usuario usado para alinhamento: {len(usuario)} caracteres 'A'")

    # offset, dentro do plaintext, onde comeca o bloco alvo (que contem
    # ';isadmin=0')
    offset_bloco_alvo = PREFIXO_LEN + len(usuario)
    assert offset_bloco_alvo % BLOCK_SIZE == 0, "nao alinhou no bloco"
    indice_bloco_alvo = offset_bloco_alvo // BLOCK_SIZE

    # no cookie (iv || ciphertext), cada bloco de ciphertext tem 16 bytes;
    # o bloco anterior ao alvo e o que vamos corromper para flipar o bit
    # (se indice_bloco_alvo == 0, o bloco anterior seria o iv -- nao e o
    # caso aqui, mas o codigo suporta os dois)
    offset_bloco_anterior_no_cookie = 16 + (indice_bloco_alvo - 1) * BLOCK_SIZE
    posicao_a_flipar = offset_bloco_anterior_no_cookie + POSICAO_DO_DIGITO

    cookie_forjado = bytearray(cookie)
    # xor com 0x01 troca o ultimo bit de '0' (0x30) por '1' (0x31)
    cookie_forjado[posicao_a_flipar] ^= 0x01

    print("[*] cookie original (hex):", cookie.hex())
    print("[*] cookie forjado  (hex):", bytes(cookie_forjado).hex())

    return e_admin(bytes(cookie_forjado))


if __name__ == "__main__":
    resultado = atacar()
    print(f"[+] servico concedeu acesso de admin? {resultado}")
