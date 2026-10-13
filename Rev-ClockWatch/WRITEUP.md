<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Clock+Watch+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

# Clock Watch — REVERSE (reverse09) · 600 pts · 🔴 HARD

- **Status:** ✅ RESOLVIDO — confirmada pelo oráculo vivo `POST /flag -> {"ok": true}`.
- **Flag:** `HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** oráculo HTTP — `GET /ticket`, `POST /flag`
- **Enunciado:** —

---

## 0. TL;DR

1. `artifacts/sample.bin` é um ELF64 x86-64 stripped, self-unpacking loader ("CPK") que desempacota e executa um ELF filho via `memfd_create`+`fexecve`.
2. O filho reconstruído faz o check real: compara `SHA256(input)` com `SHA256(SECRET)`, com anti-análise que troca o ponteiro/tamanho lido quando detecta debugger/execução lenta ("changes its mind").
3. O SECRET vem de uma árvore Merkle keyed (TLV) embutida no filho; calculando a raiz e o keystream do leaf certo (`index=14` por ordem reversa de parse) dá o SECRET, cujo SHA256 é o proof aceito pelo oráculo HTTP.

### Cadeia que fechou
1. Loader (`sample.bin`) -> stage2 (XOR keystream com feedback, seed `ebx=0x78719254` recuperado por brute-force 32-bit) -> stage3 (LZ4 decompress + verifica FNV-1a `0x12b94ef2`) -> stage4 (`memfd_create`+`fexecve`) -> ELF filho (`scratchpad/child.elf`, 24296 bytes).
2. Child: `sample.bin --check <64 hex>` compara `SHA256(input)==SHA256(SECRET)`.
3. SECRET extraído estaticamente da árvore HIKB/ICHN embutida (`raw_payload XOR keystream`, ver 3.3).
4. `proof = sha256(SECRET.hex())` -> `ticket = GET /ticket` -> `token = sha256(f"{ticket}:{proof}")` -> `POST /flag {ticket, token}` -> `{"ok": true, "flag": "HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac"}`.

---

## 1. Artefatos

- `artifacts/sample.bin` — ELF64 x86-64, stripped, self-unpacking loader ("CPK"). NÃO foi executado (análise 100% estática; oráculo vivo só para validar a flag).

## 2. Entrega / validação

- Proof HTTP: `ticket = GET /ticket` (TTL 45s), `token = sha256(f"{ticket}:{proof}")`, `proof = sha256(SECRET.hex())`. `POST /flag {ticket, token}` -> `{"ok": true, "flag": "..."}`.

## 3. Análise

### 3.1 Loader externo (sample.bin)

`main` lê `/proc/self/exe`, roda 5 estágios sobre um contexto:

- trailer de 40 bytes no fim do arquivo (offset `0x8137`): magic `"CPKX"` (= `"RAZI"` XOR `0x11`), ver `9/1`, 3 qwords = `{MSG_off=0x48b0, MSG_len=0x3887, out_len=0x5ee8}`, `seed=0x7bfb63ac`, `FNV=0x12b94ef2`.
- stage2: XOR keystream + passo de difusão sobre `file[0x48b0:0x8137]`. Keystream = PRNG com FEEDBACK (não splitmix): estado inicial = `ebx^0x8ff34781`; por byte: `s-=0x61c88647; s=((s^s>>16)*0x21f0aaad); s=((s^s>>15)*0x735a2d97); out ^= ((s^s>>15) ^ c)&0xff; c+=0x2b`. (O estado transformado realimenta — bug fácil de errar.) Seed real recuperado por brute-force 32-bit (C) com constraint = ident ELF `"7f454c46020101"`: `ebx=0x78719254`.
- stage3: LZ4 block decompress -> `0x5ee8` bytes; verifica FNV-1a `== 0x12b94ef2`. = ELF filho.
- stage4: `memfd_create` + `fexecve` do filho.

Filho reconstruído: `scratchpad/child.elf` (24296 bytes, FNV confere).

### 3.2 Child ELF (o "real check")

`sample.bin --check <64 hex>` decodifica 32 bytes e os compara com o SECRET via SHA-256 (fcn `0x401cb0` = SHA-256; compara `SHA256(input)==SHA256(secret) -> input==secret`).

Anti-análise ("changes its mind"): `TracerPid` (`/proc/self/status`) + gate `rdtsc` (`>0x4c4b400` ciclos). Sob debugger/lento a função que extrai o secret é chamada com ponteiro+tamanho diferentes -> parseia região errada -> secret falso. O caminho rápido/sem trace é o real.

SECRET vem de uma estrutura HIKB/ICHN (árvore Merkle keyed) embutida no child (offset `0x5a3e`):

- 15 entradas TLV `[u16 a][u16 b][u8 type][u16 len][payload]`. Uma `type=2` (raiz extraída), `type-1`/`0` decoys.
- fcn `0x402510` avalia a árvore. Entrada `type-2` (file pos 0) é LEAF (`a=b=0xffff`).
- fcn `0x402400` = PRF = `SHA256(label ‖ index_le32 ‖ child1 ‖ child2)`.
- LEAF: `keystream = SHA256("ICHN-leaf" ‖ index_le32)`, sem filhos.
- O index é o slot de armazenamento (parse em ordem REVERSA): `type-2` (1ª no arquivo) -> slot 14.

### 3.3 Cálculo do SECRET

```
raw_payload (type-2) = 49bb643965e29c024d7f44b77e202bc1c1ba3c1813f7d9d3b32477026412be56
keystream = SHA256("ICHN-leaf" + bytes[14,0,0,0])
SECRET = raw_payload XOR keystream
       = 61506bd3579b890a9397e67d59965ab5117c36a41dcddeb83126db3191ad36a7
```

### 3.4 Oráculo

```
proof  = sha256(SECRET.hex())           = 4e88b5a5...
ticket = GET /ticket  (TTL 45s)
token  = sha256(f"{ticket}:{proof}")
POST /flag {ticket, token} -> {"ok": true, "flag": "HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac"}
```

## 4. O que não funcionou

Não há registro de hipóteses descartadas no material original — a análise estática chegou direto ao SECRET.

## 5. Conclusão / próximos passos

Cadeia fechada por análise 100% estática (loader + child ELF + árvore Merkle keyed), sem executar o binário; apenas o oráculo HTTP foi usado para validar a flag. Script único ticket->token->flag disponível no histórico de comandos (inline); SECRET hardcodado para reproduzir.

---

## Apêndice — ferramentas

- `scratchpad/child.elf` — ELF filho reconstruído a partir do desempacotamento estático do loader (24296 bytes, FNV `0x12b94ef2` confirmado).
