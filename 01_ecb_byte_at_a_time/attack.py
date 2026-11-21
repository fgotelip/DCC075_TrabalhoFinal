"""ataque: recuperacao byte a byte de segredo cifrado em ecb

# explora o fato de que, em ecb, o mesmo bloco de 16 bytes de texto claro
# sempre gera o mesmo bloco de ciphertext (nao ha iv nem encadeamento) --
# o atacante usa isso como oracle de comparacao para descobrir o segredo
# byte a byte, sem nunca saber a chave
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import encryption_oracle  # noqa: E402

BLOCK_SIZE = 16


def descobrir_tamanho_segredo() -> int:
    # aumenta o prefixo ate o ciphertext crescer um bloco -- a diferenca de
    # tamanho revela quantos bytes de padding havia, e portanto o tamanho
    # exato do segredo
    tamanho_base = len(encryption_oracle(b""))
    for tamanho_prefixo in range(1, BLOCK_SIZE + 1):
        novo_tamanho = len(encryption_oracle(b"A" * tamanho_prefixo))
        if novo_tamanho != tamanho_base:
            return tamanho_base - tamanho_prefixo
    raise RuntimeError("nao foi possivel medir o tamanho do segredo")


def bloco_alvo(ciphertext: bytes, indice_bloco: int) -> bytes:
    inicio = indice_bloco * BLOCK_SIZE
    return ciphertext[inicio:inicio + BLOCK_SIZE]


def recuperar_segredo() -> bytes:
    tamanho_segredo = descobrir_tamanho_segredo()
    segredo_recuperado = b""

    for posicao in range(tamanho_segredo):
        indice_bloco = posicao // BLOCK_SIZE
        # tamanho de padding que alinha o proximo byte desconhecido como
        # ultimo byte de um bloco completo
        padding = (BLOCK_SIZE - 1) - (posicao % BLOCK_SIZE)
        prefixo = b"A" * padding

        # ciphertext "real": prefixo + (bytes ja conhecidos do segredo) +
        # byte desconhecido cai exatamente no final de um bloco
        alvo = bloco_alvo(encryption_oracle(prefixo), indice_bloco)

        # testa cada byte possivel (0-255) montando o mesmo bloco e
        # comparando o ciphertext resultante -- o byte que bate e o certo
        encontrado = False
        for candidato in range(256):
            tentativa = prefixo + segredo_recuperado + bytes([candidato])
            bloco_tentativa = bloco_alvo(
                encryption_oracle(tentativa), indice_bloco
            )
            if bloco_tentativa == alvo:
                segredo_recuperado += bytes([candidato])
                encontrado = True
                break

        if not encontrado:
            # normalmente acontece só no ultimo byte (padding pkcs#7 atrapalha)
            break

    return segredo_recuperado


if __name__ == "__main__":
    print("[*] descobrindo tamanho do segredo...")
    tamanho = descobrir_tamanho_segredo()
    print(f"[*] tamanho estimado: {tamanho} bytes")

    print("[*] recuperando segredo byte a byte (sem conhecer a chave)...")
    segredo = recuperar_segredo()

    print(f"[+] segredo recuperado ({len(segredo)} bytes):")
    print(segredo.decode(errors="replace"))
