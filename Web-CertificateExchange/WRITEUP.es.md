<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Certificate+Exchange+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Certificate Exchange — WEB · 200 pts · 🟢 EASY

- **Status:** ✅ RESUELTO
- **Flag:** `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `https://<HOST>/` · servicio mTLS en `<PORT>` (`:1337`)
- **Enunciado:** *"Two of our CertExchange models computed your next instruction together... we misplaced both tokenizers, and their output got intertwined"* (sponsor challenge, Kulkan Security; 2 bugs)

---

## 0. TL;DR

1. Puzzle de tokenizers intercalados (GPT-2 + T5) revela el path del "primer paquete": un client cert firmado por la CA interna.
2. El servicio `:1337` es mTLS de verdad (valida el client cert contra la Kulkan Root CA). Con el cert level-1 te autenticás en el `/exchange`, que devuelve el siguiente cert XOR-enmascarado — roto por known-plaintext (el PEM empieza con `-----BEGIN CERTIFICATE-----`).
3. Cambiando level-1 -> level-2 -> flag.

### Cadena que cerró
1. Decodificar los token IDs de la home (pares = GPT-2, impares = T5) -> path `/vault/ffasfsaf/firstexchange.pem`.
2. `curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem` -> `pkg1.pem` (cert + key level-1).
3. `POST /exchange` autenticado con `pkg1.pem` -> blob XOR-enmascarado -> known-plaintext con `-----BEGIN CERTIFICATE-----` -> clave `OMG_I_LUV_EKO_ARG_XOR_KEY` -> cert level-2.
4. Reautenticar con level-2 -> `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`.

---

## 1. Artefactos

- `pkg1.pem` (cert level-1), `pkg2.pem` (level-2) — generados durante el solve (sandbox, no commiteados en este repositorio).

## 2. Entrega / validación

Autenticación mutua vía mTLS contra `<HOST>:1337`, reautenticando con cada cert nuevo (`curl --cert`), subiendo de nivel hasta que la respuesta final contenga la flag:

```
[L1] Credential accepted... -> next cert CN=level-2.exchange.kulkan.local
[L2] Mutual trust established. Your agent certificate checks out. The exchange is complete.
     HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b
```

## 3. Análisis

### 3.1 El puzzle de los tokenizers

La home muestra una lista de token IDs: *"Two of our CertExchange models computed your next instruction together... we misplaced both tokenizers, and their output got intertwined"*.

Pistas (imágenes en `/static/`): ruleta con **EVEN** destacado + print de nmap con **`-T5`** destacado -> separar los IDs por paridad y decodificar con dos tokenizers: índices pares = GPT-2, impares = T5. Juntando palabra a palabra (even-first) forma una frase:

```
Hello Human, this inference was produced by a collaborative effort of two LLMs.
You can get the first exchange package from: /vault/ffasfsaf/firstexchange.pem
```

Decode (sin bajar modelo pesado — solo `tiktoken` + `sentencepiece` con el `spiece.model` del t5-base):

```python
import tiktoken, sentencepiece as spm
ids=[15496,3892,428,6,373,16,416,11788,25408,2546,286,3,27140,9,10128,1941,13,192,
     460,148,262,129,5163,166,422,2642,25,3,31246,87,292,208,9501,10335,1878,87,14,3,
     11085,3,1069,3,3803,3,13,3,79,3,368,3]
g=tiktoken.get_encoding("gpt2"); sp=spm.SentencePieceProcessor(model_file='spiece.model')
print(g.decode(ids[0::2]))   # GPT-2 en los pares
print(sp.decode(ids[1::2]))  # T5 en los impares
```

### 3.2 Primer paquete (client cert level-1)

El path está en el servicio mTLS (`:1337`); en el host 443 todo es catch-all:

```bash
curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem -o pkg1.pem
```

`pkg1.pem` trae cert + clave privada RSA:

- subject `CN=level-1.exchange.kulkan.local`, issuer `CN=Kulkan Root CA`
- ExtendedKeyUsage: *TLS Web Client Authentication*

Por qué es mTLS de verdad: presentar un cert self-signed resulta en `TLS alert, unknown CA (560)` — el servidor valida el client cert contra la Kulkan Root CA. Sin cert -> la app responde `403 "no means of authentication"`. Solo el cert firmado por la CA pasa.

### 3.3 Exchange (intercambio) + XOR known-plaintext

Autenticado con el cert level-1, el `POST /exchange` entrega el siguiente credential XOR-enmascarado (base64), con la pista "key in our Meditations Playlist". No hace falta adivinar la playlist: el plaintext es un PEM que empieza con `-----BEGIN CERTIFICATE-----`, así que la clave sale por known-plaintext.

```python
import base64
kp=b"-----BEGIN CERTIFICATE-----\n"
data=base64.b64decode(blob)
key=bytes(data[i]^kp[i] for i in range(len(kp)))   # -> b'OMG_I_LUV_EKO_ARG_XOR_KEY' (24 bytes, repetida)
pt=bytes(data[i]^key[i%len(key)] for i in range(len(data)))  # cert level-2
```

Clave XOR recuperada: `OMG_I_LUV_EKO_ARG_XOR_KEY`.

## 4. Lo que no funcionó

Ningún callejón sin salida relevante registrado — el solve siguió directo por las 3 etapas sin hipótesis descartada.

## 5. Conclusión / próximos pasos

Resuelto. Puntos de atención para desafíos parecidos: mTLS con validación de CA correcta en el handshake TLS, pero el "exchange" distribuye el siguiente cert enmascarado solo con XOR de clave fija -> known-plaintext lo destruye, porque el PEM tiene prefijo conocido. "Esconder" la clave en una playlist es solo oscuridad: el formato del plaintext ya entrega todo. Reconocer tokenizer IDs (GPT-2 ~50k vocab, ids como `15496`="Hello"; T5/SentencePiece) fue la jugada clave del puzzle inicial.

---

## Apéndice — herramientas

- Decodificación de los token IDs: `tiktoken` (GPT-2) + `sentencepiece` (T5, `spiece.model`) — ver el fragmento en §3.1.
- Solve del XOR known-plaintext e intercambio de certs: `curl --cert`/`-k` + script Python ad-hoc (ver §3.3), sin artefacto de script dedicado versionado en este directorio.
