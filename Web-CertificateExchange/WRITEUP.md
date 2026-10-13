<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Certificate+Exchange+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Certificate Exchange — WEB · 200 pts · 🟢 EASY

- **Status:** ✅ SOLVED
- **Flag:** `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `https://<HOST>/` · mTLS service on `<PORT>` (`:1337`)
- **Prompt:** *"Two of our CertExchange models computed your next instruction together... we misplaced both tokenizers, and their output got intertwined"* (sponsor challenge, Kulkan Security; 2 bugs)

---

## 0. TL;DR

1. An intertwined-tokenizers puzzle (GPT-2 + T5) reveals the path of the "first package": a client cert signed by the internal CA.
2. The `:1337` service is real mTLS (validates the client cert against the Kulkan Root CA). With the level-1 cert you authenticate to `/exchange`, which returns the next cert XOR-masked — broken by known-plaintext (the PEM starts with `-----BEGIN CERTIFICATE-----`).
3. Trading level-1 -> level-2 -> flag.

### Chain that landed
1. Decode the home's token IDs (even = GPT-2, odd = T5) -> path `/vault/ffasfsaf/firstexchange.pem`.
2. `curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem` -> `pkg1.pem` (level-1 cert + key).
3. `POST /exchange` authenticated with `pkg1.pem` -> XOR-masked blob -> known-plaintext with `-----BEGIN CERTIFICATE-----` -> key `OMG_I_LUV_EKO_ARG_XOR_KEY` -> level-2 cert.
4. Re-authenticate with level-2 -> `HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b`.

---

## 1. Artifacts

- `pkg1.pem` (level-1 cert), `pkg2.pem` (level-2) — generated during the solve (sandbox, not committed in this repository).

## 2. Delivery / validation

Mutual authentication via mTLS against `<HOST>:1337`, re-authenticating with each new cert (`curl --cert`), leveling up until the final response contains the flag:

```
[L1] Credential accepted... -> next cert CN=level-2.exchange.kulkan.local
[L2] Mutual trust established. Your agent certificate checks out. The exchange is complete.
     HIK_CERTIFICATE_EXCHANGE_495a562d42abe088ea485caa42df3c0b
```

## 3. Analysis

### 3.1 The tokenizers puzzle

The home shows a list of token IDs: *"Two of our CertExchange models computed your next instruction together... we misplaced both tokenizers, and their output got intertwined"*.

Hints (images in `/static/`): a roulette with **EVEN** highlighted + an nmap screenshot with **`-T5`** highlighted -> split the IDs by parity and decode with two tokenizers: even indices = GPT-2, odd = T5. Joining word-by-word (even-first) forms a sentence:

```
Hello Human, this inference was produced by a collaborative effort of two LLMs.
You can get the first exchange package from: /vault/ffasfsaf/firstexchange.pem
```

Decode (without downloading a heavy model — just `tiktoken` + `sentencepiece` with t5-base's `spiece.model`):

```python
import tiktoken, sentencepiece as spm
ids=[15496,3892,428,6,373,16,416,11788,25408,2546,286,3,27140,9,10128,1941,13,192,
     460,148,262,129,5163,166,422,2642,25,3,31246,87,292,208,9501,10335,1878,87,14,3,
     11085,3,1069,3,3803,3,13,3,79,3,368,3]
g=tiktoken.get_encoding("gpt2"); sp=spm.SentencePieceProcessor(model_file='spiece.model')
print(g.decode(ids[0::2]))   # GPT-2 on the even ones
print(sp.decode(ids[1::2]))  # T5 on the odd ones
```

### 3.2 First package (level-1 client cert)

The path is on the mTLS service (`:1337`); on host 443 everything is catch-all:

```bash
curl -sk https://<HOST>:1337/vault/ffasfsaf/firstexchange.pem -o pkg1.pem
```

`pkg1.pem` carries a cert + RSA private key:

- subject `CN=level-1.exchange.kulkan.local`, issuer `CN=Kulkan Root CA`
- ExtendedKeyUsage: *TLS Web Client Authentication*

Why it's real mTLS: presenting a self-signed cert results in `TLS alert, unknown CA (560)` — the server validates the client cert against the Kulkan Root CA. No cert -> the app responds `403 "no means of authentication"`. Only the CA-signed cert passes.

### 3.3 Exchange + XOR known-plaintext

Authenticated with the level-1 cert, `POST /exchange` hands over the next credential XOR-masked (base64), with the hint "key in our Meditations Playlist". No need to guess the playlist: the plaintext is a PEM that starts with `-----BEGIN CERTIFICATE-----`, so the key comes out by known-plaintext.

```python
import base64
kp=b"-----BEGIN CERTIFICATE-----\n"
data=base64.b64decode(blob)
key=bytes(data[i]^kp[i] for i in range(len(kp)))   # -> b'OMG_I_LUV_EKO_ARG_XOR_KEY' (24 bytes, repeated)
pt=bytes(data[i]^key[i%len(key)] for i in range(len(data)))  # level-2 cert
```

Recovered XOR key: `OMG_I_LUV_EKO_ARG_XOR_KEY`.

## 4. What didn't work

No relevant dead end recorded — the solve went straight through the 3 stages with no discarded hypothesis.

## 5. Conclusion / next steps

Solved. Points of attention for similar challenges: mTLS with correct CA validation in the TLS handshake, but the "exchange" distributes the next masked cert only with a fixed-key XOR -> known-plaintext destroys it, because the PEM has a known prefix. "Hiding" the key in a playlist is just obscurity: the plaintext format already gives everything away. Recognizing tokenizer IDs (GPT-2 ~50k vocab, ids like `15496`="Hello"; T5/SentencePiece) was the key move in the initial puzzle.

---

## Appendix — tools

- Decoding the token IDs: `tiktoken` (GPT-2) + `sentencepiece` (T5, `spiece.model`) — see the snippet in §3.1.
- XOR known-plaintext solve and cert trading: `curl --cert`/`-k` + ad-hoc Python script (see §3.3), with no dedicated script artifact versioned in this directory.
