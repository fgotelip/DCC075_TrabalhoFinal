"""comparacao: aes-gcm (cifragem autenticada) contra os mesmos 3 ataques

# aes-gcm e um modo AEAD (authenticated encryption with associated data):
# alem de cifrar, ele gera uma "tag" de autenticacao sobre o ciphertext.
# ao decriptar, a tag e verificada ANTES de qualquer plaintext ser
# devolvido -- qualquer bit alterado no ciphertext (seja por padding
# oracle, bit-flipping ou reuso indevido) faz a verificacao falhar, e a
# biblioteca levanta uma excecao em vez de devolver dado adulterado
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def demo_padding_oracle_nao_existe():
    print("--- tentativa de padding oracle attack em gcm ---")
    print("gcm nao usa pkcs#7 (nao e um modo cbc), entao nao ha conceito")
    print("de 'padding invalido' para um atacante sondar. a unica resposta")
    print("possivel na decriptacao e: tag valida (devolve plaintext) ou")
    print("tag invalida (excecao) -- nao ha oracle de padding a explorar.\n")


def demo_bitflip_e_detectado():
    print("--- tentativa de bit-flipping em gcm ---")
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce = b"\x00" * 12

    plaintext = b"usuario=joao;isadmin=0"
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # mesmo ataque: flipa 1 bit no ciphertext tentando trocar '0' por '1'
    ciphertext_forjado = bytearray(ciphertext)
    ciphertext_forjado[len(plaintext) - 1] ^= 0x01  # o byte do '0' final

    try:
        aesgcm.decrypt(nonce, bytes(ciphertext_forjado), associated_data=None)
        print("[!] inesperado: gcm aceitou o ciphertext adulterado")
    except InvalidTag:
        print("[+] gcm REJEITOU o ciphertext adulterado (InvalidTag)")
        print("    -- o bit-flipping nao passa despercebido como em cbc\n")


def demo_reuso_de_nonce_ainda_e_perigoso():
    print("--- reuso de nonce em gcm (continua sendo grave!) ---")
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    nonce_fixo = b"\x00" * 12  # bug: nonce reaproveitado, igual ao ctr

    p1 = b"transferir R$100 para conta 111"
    p2 = b"transferir R$900 para conta 222"
    c1 = aesgcm.encrypt(nonce_fixo, p1, associated_data=None)
    c2 = aesgcm.encrypt(nonce_fixo, p2, associated_data=None)

    # gcm = ctr (para confidencialidade) + autenticacao. reusar nonce
    # ainda vaza o xor dos plaintexts (igual ao ctr puro) e, pior, pode
    # permitir forjar tags em alguns cenarios -- gcm NAO perdoa reuso de
    # nonce, so protege contra adulteracao de UM ciphertext isolado
    #
    # AESGCM.encrypt devolve ciphertext || tag (16 bytes de tag no final);
    # a tag muda a cada chamada mesmo com nonce repetido, entao comparamos
    # so a parte do ciphertext (sem a tag), que e a que carrega o xor dos
    # plaintexts
    corpo1, corpo2 = c1[:-16], c2[:-16]
    tamanho = min(len(corpo1), len(corpo2))
    xor_plaintexts = bytes(
        byte_corpo1 ^ byte_corpo2
        for byte_corpo1, byte_corpo2 in zip(corpo1[:tamanho], corpo2[:tamanho])
    )
    xor_esperado = bytes(
        byte_p1 ^ byte_p2 for byte_p1, byte_p2 in zip(p1, p2)
    )

    print("[!] mesmo em gcm, reusar nonce vaza p1 XOR p2:")
    print("    c1 XOR c2 == p1 XOR p2 ?", xor_plaintexts == xor_esperado)
    print("    conclusao: gcm resolve integridade/autenticidade, mas o")
    print("    nonce AINDA precisa ser unico por mensagem -- boas praticas")
    print("    (ex: nonce aleatorio de 96 bits, ou contador que nunca repete)")
    print("    continuam obrigatorias.\n")


if __name__ == "__main__":
    demo_padding_oracle_nao_existe()
    demo_bitflip_e_detectado()
    demo_reuso_de_nonce_ainda_e_perigoso()
