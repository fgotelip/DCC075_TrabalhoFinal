"""servico vulneravel: oracle de encriptacao ecb

# simula um servico que concatena entrada do atacante com um segredo fixo e
# devolve o ciphertext em aes-ecb
"""

from DCC075_TrabalhoFinal.common.aes_utils import aes_ecb_encrypt, random_bytes

# chave fixa, gerada uma vez quando o servico "sobe" -- o atacante nunca a ve
_KEY = random_bytes(16)

# segredo que o servico protege (ex: um token/flag) -- o atacante nao o ve
# diretamente, so atraves do oracle
_SECRET = (
    b"flag{ecb_e_deterministico_bloco_a_bloco_e_isso_vaza_segredo}"
)


def encryption_oracle(attacker_controlled: bytes) -> bytes:
    """unico ponto de contato do atacante com o servico

    recebe bytes controlados pelo atacante, concatena com o segredo e
    devolve o ciphertext aes-ecb -- exatamente o que um endpoint real
    vulneravel faria (ex: /api/token?prefixo=...)
    """
    plaintext = attacker_controlled + _SECRET
    return aes_ecb_encrypt(_KEY, plaintext)


if __name__ == "__main__":
    # demonstra o uso normal do servico (sem ataque)
    ct = encryption_oracle(b"")
    print("tamanho do segredo (padded):", len(ct), "bytes")
    print("ciphertext (hex):", ct.hex())
