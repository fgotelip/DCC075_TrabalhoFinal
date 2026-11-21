"""ataque: reutilizacao de nonce em ctr (two-time pad)

# em ctr, ciphertext = plaintext XOR keystream(chave, nonce, contador).
# se duas mensagens usam o MESMO (chave, nonce), elas usam o MESMO
# keystream. logo:
#
#   c1 XOR c2 = (p1 XOR ks) XOR (p2 XOR ks) = p1 XOR p2
#
# ou seja, o atacante consegue o xor dos dois textos claros sem conhecer
# a chave -- e isso ja e muita informacao. aqui mostramos dois niveis:
#
# 1) c1 XOR c2 vaza estrutura (tamanho de palavras, repeticoes)
# 2) se o atacante souber (ou adivinhar) o conteudo de UMA mensagem,
#    ele recupera o keystream inteiro e decripta TODAS as outras
#    mensagens que reusaram o mesmo nonce -- "two-time pad"
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from server import cifrar_mensagem  # noqa: E402


def xor_bytes(bytes_a: bytes, bytes_b: bytes) -> bytes:
    return bytes(byte_a ^ byte_b for byte_a, byte_b in zip(bytes_a, bytes_b))


def mostrar_vazamento_estrutural(c1: bytes, c2: bytes) -> None:
    print("[*] c1 XOR c2 =", xor_bytes(c1, c2).hex())
    print("    (ja revela onde os textos diferem/coincidem, mesmo sem a chave)")


def recuperar_com_known_plaintext(
    ciphertext_conhecido: bytes,
    plaintext_conhecido: bytes,
    ciphertext_alvo: bytes,
) -> bytes:
    """cenario classico de reuso de nonce: o atacante descobriu (de outra

    forma) o conteudo de UMA mensagem cifrada com o mesmo par chave/nonce.
    com isso ele recupera o keystream e decripta qualquer outra mensagem
    que reusou o mesmo nonce, sem jamais obter a chave
    """
    tamanho = min(len(ciphertext_conhecido), len(plaintext_conhecido))
    keystream = xor_bytes(
        ciphertext_conhecido[:tamanho], plaintext_conhecido[:tamanho]
    )
    tamanho_alvo = min(len(keystream), len(ciphertext_alvo))
    return xor_bytes(keystream[:tamanho_alvo], ciphertext_alvo[:tamanho_alvo])


if __name__ == "__main__":
    # servico (bugado) cifra duas mensagens reusando o mesmo nonce
    p1 = b"transferir R$100 para conta 111"
    p2 = b"transferir R$900 para conta 222"
    c1 = cifrar_mensagem(p1)
    c2 = cifrar_mensagem(p2)

    print("[*] duas mensagens interceptadas, cifradas com o mesmo nonce")
    mostrar_vazamento_estrutural(c1, c2)

    print()
    print("[*] simulando que o atacante descobriu o conteudo da 1a mensagem")
    print("    (ex: vazou em outro lugar, ou e um formato previsivel)")
    recuperado = recuperar_com_known_plaintext(c1, p1, c2)

    print(f"[+] 2a mensagem recuperada sem conhecer a chave:")
    print(recuperado.decode(errors="replace"))
    assert recuperado == p2, "ataque falhou"
