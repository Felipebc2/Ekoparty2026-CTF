<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Certificate+Exchange+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

# Certificate Exchange — WEB · 200 pts · 🟢 EASY

- **Status:** ✅ RESOLVIDO
- **Flag:** `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** `https://<HOST>/` · serviço mTLS em `<PORT>` (`:1337`)
- **Enunciado:** *"Two of our CertExchange models computed your next instruction together... we misplaced both tokenizers, and their output got intertwined"* (sponsor challenge, Kulkan Security; 2 bugs)

---

## 0. TL;DR

1. Puzzle de tokenizers intercalados (GPT-2 + T5) revela o path do "primeiro pacote": um client cert assinado pela CA interna.
2. O serviço `:1337` é mTLS de verdade (valida o client cert contra a Kulkan Root CA). Com o cert level-1 autentica-se no `/exchange`, que devolve o próximo cert XOR-mascarado — quebrado por known-plaintext (o PEM começa com `-----BEGIN CERTIFICATE-----`).
3. Trocando level-1 -> level-2 -> flag.

### Cadeia que fechou
1. Decodificar os token IDs da home (pares = GPT-2, ímpares = T5) -> path `/vault/ffasfsaf/firstexchange.pem`.
2. `curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem` -> `pkg1.pem` (cert + key level-1).
3. `POST /exchange` autenticado com `pkg1.pem` -> blob XOR-mascarado -> known-plaintext com `-----BEGIN CERTIFICATE-----` -> chave `OMG_I_LUV_EKO_ARG_XOR_KEY` -> cert level-2.
4. Reautenticar com level-2 -> `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`.

---

## 1. Artefatos

- `pkg1.pem` (cert level-1), `pkg2.pem` (level-2) — gerados durante o solve (sandbox, não commitados neste repositório).

## 2. Entrega / validação

Autenticação mútua via mTLS contra `<HOST>:1337`, reautenticando com cada cert novo (`curl --cert`), subindo de nível até a resposta final conter a flag:

```
[L1] Credential accepted... -> next cert CN=level-2.exchange.kulkan.local
[L2] Mutual trust established. Your agent certificate checks out. The exchange is complete.
     HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b
```

## 3. Análise

### 3.1 O puzzle dos tokenizers

A home mostra uma lista de token IDs: *"Two of our CertExchange models computed your next instruction together... we misplaced both tokenizers, and their output got intertwined"*.

Dicas (imagens em `/static/`): roleta com **EVEN** destacado + print de nmap com **`-T5`** destacado -> separar os IDs por paridade e decodificar com dois tokenizers: índices pares = GPT-2, ímpares = T5. Juntando palavra-a-palavra (even-first) forma uma frase:

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

### 3.2 Primeiro pacote (client cert level-1)

O path está no serviço mTLS (`:1337`); no host 443 tudo é catch-all:

```bash
curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem -o pkg1.pem
```

`pkg1.pem` traz cert + chave privada RSA:

- subject `CN=level-1.exchange.kulkan.local`, issuer `CN=Kulkan Root CA`
- ExtendedKeyUsage: *TLS Web Client Authentication*

Por que é mTLS de verdade: apresentar um cert self-signed resulta em `TLS alert, unknown CA (560)` — o servidor valida o client cert contra a Kulkan Root CA. Sem cert -> app responde `403 "no means of authentication"`. Só o cert assinado pela CA passa.

### 3.3 Exchange (troca) + XOR known-plaintext

Autenticado com o cert level-1, o `POST /exchange` entrega o próximo credential XOR-mascarado (base64), com a dica "key in our Meditations Playlist". Não precisa adivinhar a playlist: o plaintext é um PEM que começa com `-----BEGIN CERTIFICATE-----`, então a chave sai por known-plaintext.

```python
import base64
kp=b"-----BEGIN CERTIFICATE-----\n"
data=base64.b64decode(blob)
key=bytes(data[i]^kp[i] for i in range(len(kp)))   # -> b'OMG_I_LUV_EKO_ARG_XOR_KEY' (24 bytes, repetida)
pt=bytes(data[i]^key[i%len(key)] for i in range(len(data)))  # cert level-2
```

Chave XOR recuperada: `OMG_I_LUV_EKO_ARG_XOR_KEY`.

## 4. O que não funcionou

Nenhum beco sem saída relevante registrado — o solve seguiu direto pelas 3 etapas sem hipótese descartada.

## 5. Conclusão / próximos passos

Resolvido. Pontos de atenção para desafios parecidos: mTLS com validação de CA correta no handshake TLS, mas a "exchange" distribui o próximo cert mascarado só com XOR de chave fixa -> known-plaintext destrói, porque o PEM tem prefixo conhecido. "Esconder" a chave numa playlist é só obscuridade: o formato do plaintext já entrega tudo. Reconhecer tokenizer IDs (GPT-2 ~50k vocab, ids como `15496`="Hello"; T5/SentencePiece) foi o pulo do gato do puzzle inicial.

---

## Apêndice — ferramentas

- Decodificação dos token IDs: `tiktoken` (GPT-2) + `sentencepiece` (T5, `spiece.model`) — ver trecho em §3.1.
- Solve do XOR known-plaintext e troca de certs: `curl --cert`/`-k` + script Python ad-hoc (ver §3.3), sem artefato de script dedicado versionado neste diretório.
