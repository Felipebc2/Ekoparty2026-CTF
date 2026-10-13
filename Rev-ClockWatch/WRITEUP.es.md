<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Clock+Watch+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Clock Watch — REVERSE (reverse09) · 600 pts · 🔴 HARD

- **Status:** ✅ RESUELTO — confirmada por el oráculo vivo `POST /flag -> {"ok": true}`.
- **Flag:** `HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** oráculo HTTP — `GET /ticket`, `POST /flag`
- **Enunciado:** —

---

## 0. TL;DR

1. `artifacts/sample.bin` es un ELF64 x86-64 stripped, un self-unpacking loader ("CPK") que desempaqueta y ejecuta un ELF hijo vía `memfd_create`+`fexecve`.
2. El hijo reconstruido hace el check real: compara `SHA256(input)` con `SHA256(SECRET)`, con anti-análisis que cambia el puntero/tamaño leído cuando detecta un debugger/ejecución lenta ("changes its mind").
3. El SECRET viene de un árbol Merkle keyed (TLV) embebido en el hijo; calculando la raíz y el keystream del leaf correcto (`index=14` por orden inverso de parse) da el SECRET, cuyo SHA256 es el proof aceptado por el oráculo HTTP.

### Cadena que cerró
1. Loader (`sample.bin`) -> stage2 (XOR keystream con feedback, seed `ebx=0x78719254` recuperado por brute-force 32-bit) -> stage3 (LZ4 decompress + verifica FNV-1a `0x12b94ef2`) -> stage4 (`memfd_create`+`fexecve`) -> ELF hijo (`scratchpad/child.elf`, 24296 bytes).
2. Child: `sample.bin --check <64 hex>` compara `SHA256(input)==SHA256(SECRET)`.
3. SECRET extraído estáticamente del árbol HIKB/ICHN embebido (`raw_payload XOR keystream`, ver 3.3).
4. `proof = sha256(SECRET.hex())` -> `ticket = GET /ticket` -> `token = sha256(f"{ticket}:{proof}")` -> `POST /flag {ticket, token}` -> `{"ok": true, "flag": "HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac"}`.

---

## 1. Artefactos

- `artifacts/sample.bin` — ELF64 x86-64, stripped, self-unpacking loader ("CPK"). NO fue ejecutado (análisis 100% estático; el oráculo vivo solo para validar la flag).

## 2. Entrega / validación

- Proof HTTP: `ticket = GET /ticket` (TTL 45s), `token = sha256(f"{ticket}:{proof}")`, `proof = sha256(SECRET.hex())`. `POST /flag {ticket, token}` -> `{"ok": true, "flag": "..."}`.

## 3. Análisis

### 3.1 Loader externo (sample.bin)

`main` lee `/proc/self/exe`, corre 5 estadios sobre un contexto:

- trailer de 40 bytes al final del archivo (offset `0x8137`): magic `"CPKX"` (= `"RAZI"` XOR `0x11`), ver `9/1`, 3 qwords = `{MSG_off=0x48b0, MSG_len=0x3887, out_len=0x5ee8}`, `seed=0x7bfb63ac`, `FNV=0x12b94ef2`.
- stage2: XOR keystream + paso de difusión sobre `file[0x48b0:0x8137]`. Keystream = PRNG con FEEDBACK (no splitmix): estado inicial = `ebx^0x8ff34781`; por byte: `s-=0x61c88647; s=((s^s>>16)*0x21f0aaad); s=((s^s>>15)*0x735a2d97); out ^= ((s^s>>15) ^ c)&0xff; c+=0x2b`. (El estado transformado realimenta — bug fácil de errar.) Seed real recuperado por brute-force 32-bit (C) con constraint = ident ELF `"7f454c46020101"`: `ebx=0x78719254`.
- stage3: LZ4 block decompress -> `0x5ee8` bytes; verifica FNV-1a `== 0x12b94ef2`. = ELF hijo.
- stage4: `memfd_create` + `fexecve` del hijo.

Hijo reconstruido: `scratchpad/child.elf` (24296 bytes, FNV comprueba).

### 3.2 Child ELF (el "real check")

`sample.bin --check <64 hex>` decodifica 32 bytes y los compara con el SECRET vía SHA-256 (fcn `0x401cb0` = SHA-256; compara `SHA256(input)==SHA256(secret) -> input==secret`).

Anti-análisis ("changes its mind"): `TracerPid` (`/proc/self/status`) + gate `rdtsc` (`>0x4c4b400` ciclos). Bajo debugger/lento la función que extrae el secret es llamada con puntero+tamaño diferentes -> parsea la región equivocada -> secret falso. El camino rápido/sin trace es el real.

El SECRET viene de una estructura HIKB/ICHN (árbol Merkle keyed) embebida en el child (offset `0x5a3e`):

- 15 entradas TLV `[u16 a][u16 b][u8 type][u16 len][payload]`. Una `type=2` (raíz extraída), `type-1`/`0` decoys.
- fcn `0x402510` evalúa el árbol. La entrada `type-2` (file pos 0) es LEAF (`a=b=0xffff`).
- fcn `0x402400` = PRF = `SHA256(label ‖ index_le32 ‖ child1 ‖ child2)`.
- LEAF: `keystream = SHA256("ICHN-leaf" ‖ index_le32)`, sin hijos.
- El index es el slot de almacenamiento (parse en orden INVERSO): `type-2` (1a en el archivo) -> slot 14.

### 3.3 Cálculo del SECRET

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

## 4. Lo que no funcionó

No hay registro de hipótesis descartadas en el material original — el análisis estático llegó directo al SECRET.

## 5. Conclusión / próximos pasos

Cadena cerrada por análisis 100% estático (loader + child ELF + árbol Merkle keyed), sin ejecutar el binario; solo el oráculo HTTP fue usado para validar la flag. Script único ticket->token->flag disponible en el historial de comandos (inline); SECRET hardcodeado para reproducir.

---

## Apéndice — herramientas

- `scratchpad/child.elf` — ELF hijo reconstruido a partir del desempaquetado estático del loader (24296 bytes, FNV `0x12b94ef2` confirmado).
