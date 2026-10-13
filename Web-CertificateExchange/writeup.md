# Certificate Exchange by Kulkan Security — Writeup

- **Evento:** Main CTF Ekoparty BA 2026 (Hack in Cariri) · sponsor challenge (Kulkan Security)
- **Categoria:** WEB · **Pontos:** 200 · **Bugs:** 2
- **Alvos:** https://<HOST>/ · serviço mTLS em `:1337`
- **Flag:** `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`

## TL;DR

Puzzle de **tokenizers intercalados** (GPT-2 + T5) revela o path do "primeiro pacote": um client
cert assinado pela CA interna. O serviço `:1337` é **mTLS de verdade** (valida o client cert
contra a Kulkan Root CA). Com o cert level-1 autentica-se no `/exchange`, que devolve o próximo
cert **XOR-mascarado** — quebrado por **known-plaintext** (o PEM começa com
`-----BEGIN CERTIFICATE-----`). Trocando level-1 → level-2 → flag.

## Etapa 0 — O puzzle dos tokenizers

A home mostra uma lista de token IDs: *"Two of our CertExchange models computed your next
instruction together... we misplaced both tokenizers, and their output got intertwined"*.

Dicas (imagens em `/static/`): roleta com **EVEN** destacado + print de nmap com **`-T5`**
destacado → separar os IDs por **paridade** e decodificar com **dois tokenizers**: índices
**pares = GPT-2**, **ímpares = T5**. Juntando palavra-a-palavra (even-first) forma uma frase:

```
Hello Human, this inference was produced by a collaborative effort of two LLMs.
You can get the first exchange package from: /vault/ffasfsaf/firstexchange.pem
```

Decode (sem baixar modelo pesado — só `tiktoken` + `sentencepiece` com o `spiece.model` do t5-base):

```python
import tiktoken, sentencepiece as spm
ids=[15496,3892,428,6,373,16,416,11788,25408,2546,286,3,27140,9,10128,1941,13,192,
     460,148,262,129,5163,166,422,2642,25,3,31246,87,292,208,9501,10335,1878,87,14,3,
     11085,3,1069,3,3803,3,13,3,79,3,368,3]
g=tiktoken.get_encoding("gpt2"); sp=spm.SentencePieceProcessor(model_file='spiece.model')
print(g.decode(ids[0::2]))   # GPT-2 nos pares
print(sp.decode(ids[1::2]))  # T5 nos ímpares
```

## Etapa 1 — Primeiro pacote (client cert level-1)

O path está no serviço mTLS (`:1337`); no host 443 tudo é catch-all:

```bash
curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem -o pkg1.pem
```

`pkg1.pem` traz **cert + RSA private key**:
- subject `CN=level-1.exchange.kulkan.local`, issuer `CN=Kulkan Root CA`
- ExtendedKeyUsage: *TLS Web Client Authentication*

**Por que mTLS de verdade:** apresentar um cert self-signed resulta em
`TLS alert, unknown CA (560)` — o servidor valida o client cert contra a Kulkan Root CA. Sem cert
→ app responde `403 "no means of authentication"`. Só o cert assinado pela CA passa.

## Etapa 2 — Exchange (trueque) + XOR known-plaintext

Autenticado com o cert level-1, o `POST /exchange` entrega o próximo credential **XOR-mascarado**
(base64), com a dica "key in our Meditations Playlist". Não precisa adivinhar a playlist: o
plaintext é um PEM que começa com `-----BEGIN CERTIFICATE-----`, então a chave sai por
**known-plaintext**.

```python
import base64
kp=b"-----BEGIN CERTIFICATE-----\n"
data=base64.b64decode(blob)
key=bytes(data[i]^kp[i] for i in range(len(kp)))   # -> b'OMG_I_LUV_EKO_ARG_XOR_KEY' (24 bytes, repetida)
pt=bytes(data[i]^key[i%len(key)] for i in range(len(data)))  # cert level-2
```

Chave XOR recuperada: **`OMG_I_LUV_EKO_ARG_XOR_KEY`**.

## Etapa 3 — Subir o nível até a flag

Troca level-1 → level-2 → flag (loop reautenticando com cada cert novo via `curl --cert`):

```
[L1] Credential accepted... -> next cert CN=level-2.exchange.kulkan.local
[L2] Mutual trust established. Your agent certificate checks out. The exchange is complete.
     HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b
```

## Lições

- mTLS com validação de CA correta no TLS, mas a "exchange" distribui o próximo cert mascarado
  só com XOR de chave fixa → **known-plaintext** destrói (PEM tem prefixo conhecido).
- "Esconder" a chave numa playlist é obscuridade: o formato do plaintext já entrega tudo.
- Reconhecer tokenizer IDs (GPT-2 ~50k vocab, ids como 15496="Hello"; T5/SentencePiece) é o
  pulo do gato do puzzle inicial.

## Artefatos

`pkg1.pem` (cert level-1), `pkg2.pem` (level-2) — gerados durante o solve (sandbox, não commitados).
