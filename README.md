# Ataques a modos de operação de cifras de bloco

Trabalho final de Segurança da Computação (DCC075, UFJF) — Tema 2: implementação
de um serviço vulnerável e exploração prática de ataques a modos de operação de
cifras de bloco, com comparação contra cifragem autenticada (AES-GCM).

## Como executar

Pré-requisitos: Python 3.9+ e a biblioteca `cryptography`.

```bash
pip install -r requirements.txt
```

> Usamos a biblioteca [`cryptography`](https://cryptography.io/) (pyca) em vez
> do PyCryptodome.

Cada pasta tem um `server.py` (o serviço vulnerável) e um `attack.py` (o
ataque). Para rodar qualquer um dos exemplos:

```bash
cd 01_ecb_byte_at_a_time
python3 attack.py
```

O `attack.py` importa o `server.py` só para simular a comunicação
cliente↔servidor (chamando funções como se fossem uma API) — o atacante
**nunca** acessa a chave (`_KEY`) ou outras variáveis internas do servidor,
só as funções que representariam endpoints públicos. Essa é a regra de ouro
seguida em todos os exemplos: o código de ataque só usa o que um atacante
real conseguiria observar (ciphertexts, respostas sim/não do serviço).

## Estrutura

| Pasta | Modo | Ataque | O que demonstra |
|---|---|---|---|
| `01_ecb_byte_at_a_time` | ECB | Recuperação byte a byte | ECB é determinístico por bloco → vaza um segredo anexado à entrada do atacante, sem quebrar a chave |
| `02_cbc_padding_oracle` | CBC | Padding oracle (Vaudenay) | Um serviço que só informa "padding válido?" é suficiente para decriptar qualquer ciphertext, sem a chave |
| `03_cbc_bitflipping` | CBC | Bit-flipping | Sem autenticação, dá pra alterar bits do plaintext decriptado (ex: `isadmin=0` → `isadmin=1`) manipulando o ciphertext |
| `04_ctr_nonce_reuse` | CTR | Two-time pad (reuso de nonce) | Reusar (chave, nonce) no CTR reaproveita o keystream → XOR dos ciphertexts vaza XOR dos plaintexts |
| `05_gcm_comparison` | GCM | — (demonstração) | Os mesmos 3 ataques contra AES-GCM: os dois primeiros falham (tag de autenticação), o reuso de nonce continua perigoso |

`common/aes_utils.py` tem as funções de AES/CBC/ECB/CTR e padding PKCS#7
reutilizadas pelos serviços. GCM é implementado à parte, com `AESGCM` da
própria `cryptography`, por já incluir autenticação pronta.

## Executando todos os experimentos (`run_all.py`)

Para rodar todos os ataques e a demonstração do AES-GCM em sequência e obter
a saída completa de uma vez, execute o script [`run_all.py`](run_all.py) na
raiz do projeto:

```bash
python3 run_all.py
```

Ele executa em ordem os scripts `01_ecb_byte_at_a_time/attack.py`,
`02_cbc_padding_oracle/attack.py`, `03_cbc_bitflipping/attack.py`,
`04_ctr_nonce_reuse/attack.py` e `05_gcm_comparison/demo.py` (cada um no seu
próprio diretório), interrompendo a execução caso algum deles retorne erro.

> **Nota sobre variação entre execuções:** nos scripts `02_cbc_padding_oracle`
> e `03_cbc_bitflipping`, os valores em hexadecimal exibidos para os cookies
> (`cookie interceptado`, `cookie original` e `cookie forjado`) mudam a cada
> execução porque os serviços geram chaves e IVs aleatórios ao iniciar. Os
> textos recuperados, o `c1 XOR c2` do CTR e as confirmações dos ataques
> (`True` / `InvalidTag`) permanecem os mesmos.

## Resumo dos resultados

- **ECB**: o segredo de 60 bytes é recuperado 100% corretamente, byte a byte,
  só observando como o ciphertext muda conforme o atacante varia o prefixo.
- **CBC / padding oracle**: o plaintext completo de um "cookie" é recuperado
  sem a chave, usando só a informação de padding válido/inválido — em média
  ~128 tentativas por byte (256 no pior caso), ~16×128 por bloco de 16 bytes.
- **CBC / bit-flipping**: um usuário sem privilégio consegue virar admin
  alterando 1 bit do ciphertext, sem decriptar nada — só porque o serviço
  confia no conteúdo decriptado sem checar integridade.
- **CTR / reuso de nonce**: com uma mensagem conhecida (ou previsível), o
  atacante recupera o keystream e decripta qualquer outra mensagem cifrada
  com o mesmo (chave, nonce) — "two-time pad", o mesmo problema do OTP reusado.
- **GCM**: os ataques de padding oracle e bit-flipping deixam de fazer
  sentido/são detectados (`InvalidTag`), pois a tag de autenticação é
  verificada antes de qualquer plaintext ser liberado. Reuso de nonce
  **continua** grave mesmo em GCM — autenticação não resolve o problema do
  nonce, então a unicidade do nonce continua sendo um requisito obrigatório.

## Boas práticas (discussão para o relatório)

- Preferir sempre um modo **autenticado** (AEAD): AES-GCM, ChaCha20-Poly1305
  etc. Eles cobrem confidencialidade **e** integridade/autenticidade num só
  passo, fechando as classes de ataque exploradas em `02` e `03`.
- Nunca usar **ECB** para dados estruturados/repetitivos — a ausência de IV
  faz blocos iguais de plaintext gerarem blocos iguais de ciphertext.
- Em modos baseados em stream (CTR, e também o keystream interno do GCM), o
  **nonce nunca pode se repetir** para a mesma chave. Preferir nonce aleatório
  de tamanho adequado (96 bits em GCM) ou um contador que nunca repete, nunca
  derivado de forma previsível ou reaproveitado "por engano".
- Se mesmo assim for necessário usar um modo não autenticado como CBC, é
  obrigatório combinar com um **MAC** (Encrypt-then-MAC) para impedir
  padding oracle e bit-flipping — nunca confiar em "decriptou sem erro"
  como prova de integridade.
- Erros/respostas do serviço não devem vazar **nenhuma** informação sobre a
  etapa de decriptação (padding válido/inválido, tempo de resposta
  diferente, mensagens de erro distintas) — isso é o que vira o oracle que
  o atacante explora. O ideal é responder sempre de forma genérica e em
  tempo constante.
- Usar bibliotecas de criptografia consolidadas (`cryptography`, OpenSSL,
  PyCryptodome) e os modos/parametrizações recomendados por elas, em vez de
  implementar primitivas por conta própria.

## Sobre as informações sensíveis neste repositório

Todo o código aqui roda localmente (não há IPs/URLs de alvos reais) — os
serviços "vulneráveis" são simulações in-process para fins didáticos, então
não há necessidade de remover nada por sensibilidade.