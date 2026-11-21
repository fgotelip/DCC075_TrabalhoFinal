"""funcoes auxiliares de aes usadas pelos exemplos vulneraveis e pelos ataques

# nao usa pycryptodome, usa a biblioteca 'cryptography' (pyca), que tambem
# e citada como opcao equivalente ao openssl/pycryptodome
"""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # tamanho do bloco do aes em bytes


def pkcs7_pad(texto_claro: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    # preenche texto_claro ate ser multiplo de block_size, no esquema pkcs#7
    tamanho_padding = block_size - (len(texto_claro) % block_size)
    return texto_claro + bytes([tamanho_padding]) * tamanho_padding


class PaddingError(Exception):
    # erro generico levantado quando o padding pkcs#7 e invalido
    pass


def pkcs7_unpad(dados_com_padding: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(dados_com_padding) == 0 or len(dados_com_padding) % block_size != 0:
        raise PaddingError("tamanho invalido")
    tamanho_padding = dados_com_padding[-1]
    if tamanho_padding < 1 or tamanho_padding > block_size:
        raise PaddingError("byte de padding invalido")
    if dados_com_padding[-tamanho_padding:] != bytes([tamanho_padding]) * tamanho_padding:
        raise PaddingError("bytes de padding nao conferem")
    return dados_com_padding[:-tamanho_padding]


def aes_ecb_encrypt(chave: bytes, texto_claro: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(chave), modes.ECB())
    encriptador = cipher.encryptor()
    return encriptador.update(pkcs7_pad(texto_claro)) + encriptador.finalize()


def aes_cbc_encrypt(chave: bytes, iv: bytes, texto_claro: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    encriptador = cipher.encryptor()
    return encriptador.update(pkcs7_pad(texto_claro)) + encriptador.finalize()


def aes_cbc_decrypt_raw(chave: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    # decripta sem checar/remover padding (usado internamente pelo oracle)
    cipher = Cipher(algorithms.AES(chave), modes.CBC(iv))
    decriptador = cipher.decryptor()
    return decriptador.update(ciphertext) + decriptador.finalize()


def aes_ctr_keystream_block(chave: bytes, bloco_nonce_contador: bytes) -> bytes:
    # gera um bloco de keystream ctr a partir de um nonce+contador de 16 bytes
    cipher = Cipher(algorithms.AES(chave), modes.ECB())
    encriptador = cipher.encryptor()
    return encriptador.update(bloco_nonce_contador) + encriptador.finalize()


def aes_ctr_crypt(chave: bytes, nonce: bytes, texto: bytes) -> bytes:
    # ctr simples: nonce de 8 bytes + contador de 8 bytes big-endian
    # (implementado na mao para deixar claro como o nonce/contador formam o
    # bloco que vira keystream -- a mesma logica do modes.CTR da lib)
    resultado = bytearray()
    contador = 0
    for inicio_bloco in range(0, len(texto), BLOCK_SIZE):
        bloco_texto = texto[inicio_bloco:inicio_bloco + BLOCK_SIZE]
        bloco_nonce_contador = nonce + contador.to_bytes(8, "big")
        keystream = aes_ctr_keystream_block(chave, bloco_nonce_contador)
        resultado.extend(
            byte_texto ^ byte_keystream
            for byte_texto, byte_keystream in zip(bloco_texto, keystream)
        )
        contador += 1
    return bytes(resultado)


def random_bytes(quantidade_bytes: int) -> bytes:
    return os.urandom(quantidade_bytes)