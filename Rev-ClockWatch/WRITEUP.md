<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Clock+Watch+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Clock Watch — REVERSE (reverse09) · 600 pts · 🔴 HARD

- **Status:** ✅ SOLVED — confirmed by the live oracle `POST /flag -> {"ok": true}`.
- **Flag:** `HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac`
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** HTTP oracle — `GET /ticket`, `POST /flag`
- **Prompt:** —

---

## 0. TL;DR

1. `artifacts/sample.bin` is a stripped ELF64 x86-64, a self-unpacking loader ("CPK") that unpacks and executes a child ELF via `memfd_create`+`fexecve`.
2. The reconstructed child does the real check: it compares `SHA256(input)` with `SHA256(SECRET)`, with anti-analysis that swaps the read pointer/size when it detects a debugger/slow execution ("changes its mind").
3. The SECRET comes from a keyed Merkle tree (TLV) embedded in the child; computing the root and the keystream of the right leaf (`index=14` by reverse parse order) yields the SECRET, whose SHA256 is the proof accepted by the HTTP oracle.

### Chain that closed
1. Loader (`sample.bin`) -> stage2 (XOR keystream with feedback, seed `ebx=0x78719254` recovered by 32-bit brute-force) -> stage3 (LZ4 decompress + FNV-1a check `0x12b94ef2`) -> stage4 (`memfd_create`+`fexecve`) -> child ELF (`scratchpad/child.elf`, 24296 bytes).
2. Child: `sample.bin --check <64 hex>` compares `SHA256(input)==SHA256(SECRET)`.
3. SECRET extracted statically from the embedded HIKB/ICHN tree (`raw_payload XOR keystream`, see 3.3).
4. `proof = sha256(SECRET.hex())` -> `ticket = GET /ticket` -> `token = sha256(f"{ticket}:{proof}")` -> `POST /flag {ticket, token}` -> `{"ok": true, "flag": "HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac"}`.

---

## 1. Artifacts

- `artifacts/sample.bin` — ELF64 x86-64, stripped, self-unpacking loader ("CPK"). It was NOT executed (100% static analysis; the live oracle only to validate the flag).

## 2. Delivery / validation

- HTTP proof: `ticket = GET /ticket` (TTL 45s), `token = sha256(f"{ticket}:{proof}")`, `proof = sha256(SECRET.hex())`. `POST /flag {ticket, token}` -> `{"ok": true, "flag": "..."}`.

## 3. Analysis

### 3.1 External loader (sample.bin)

`main` reads `/proc/self/exe`, runs 5 stages over a context:

- 40-byte trailer at the end of the file (offset `0x8137`): magic `"CPKX"` (= `"RAZI"` XOR `0x11`), ver `9/1`, 3 qwords = `{MSG_off=0x48b0, MSG_len=0x3887, out_len=0x5ee8}`, `seed=0x7bfb63ac`, `FNV=0x12b94ef2`.
- stage2: XOR keystream + diffusion step over `file[0x48b0:0x8137]`. Keystream = PRNG with FEEDBACK (not splitmix): initial state = `ebx^0x8ff34781`; per byte: `s-=0x61c88647; s=((s^s>>16)*0x21f0aaad); s=((s^s>>15)*0x735a2d97); out ^= ((s^s>>15) ^ c)&0xff; c+=0x2b`. (The transformed state feeds back — an easy bug to get wrong.) Real seed recovered by 32-bit brute-force (C) with constraint = ELF ident `"7f454c46020101"`: `ebx=0x78719254`.
- stage3: LZ4 block decompress -> `0x5ee8` bytes; verifies FNV-1a `== 0x12b94ef2`. = child ELF.
- stage4: `memfd_create` + `fexecve` of the child.

Reconstructed child: `scratchpad/child.elf` (24296 bytes, FNV checks out).

### 3.2 Child ELF (the "real check")

`sample.bin --check <64 hex>` decodes 32 bytes and compares them with the SECRET via SHA-256 (fcn `0x401cb0` = SHA-256; compares `SHA256(input)==SHA256(secret) -> input==secret`).

Anti-analysis ("changes its mind"): `TracerPid` (`/proc/self/status`) + `rdtsc` gate (`>0x4c4b400` cycles). Under a debugger/slow, the function that extracts the secret is called with a different pointer+size -> parses the wrong region -> false secret. The fast/untraced path is the real one.

SECRET comes from a HIKB/ICHN structure (keyed Merkle tree) embedded in the child (offset `0x5a3e`):

- 15 TLV entries `[u16 a][u16 b][u8 type][u16 len][payload]`. One `type=2` (extracted root), `type-1`/`0` decoys.
- fcn `0x402510` evaluates the tree. The `type-2` entry (file pos 0) is a LEAF (`a=b=0xffff`).
- fcn `0x402400` = PRF = `SHA256(label ‖ index_le32 ‖ child1 ‖ child2)`.
- LEAF: `keystream = SHA256("ICHN-leaf" ‖ index_le32)`, no children.
- The index is the storage slot (parse in REVERSE order): `type-2` (1st in the file) -> slot 14.

### 3.3 SECRET computation

```
raw_payload (type-2) = 49bb643965e29c024d7f44b77e202bc1c1ba3c1813f7d9d3b32477026412be56
keystream = SHA256("ICHN-leaf" + bytes[14,0,0,0])
SECRET = raw_payload XOR keystream
       = 61506bd3579b890a9397e67d59965ab5117c36a41dcddeb83126db3191ad36a7
```

### 3.4 Oracle

```
proof  = sha256(SECRET.hex())           = 4e88b5a5...
ticket = GET /ticket  (TTL 45s)
token  = sha256(f"{ticket}:{proof}")
POST /flag {ticket, token} -> {"ok": true, "flag": "HIK_REV_BROKEN_TIME_0baa7ba0c14a0f468b018e1f4ccc35ac"}
```

## 4. What didn't work

There is no record of discarded hypotheses in the original material — the static analysis reached the SECRET directly.

## 5. Conclusion / next steps

Chain closed by 100% static analysis (loader + child ELF + keyed Merkle tree), without running the binary; only the HTTP oracle was used to validate the flag. Single ticket->token->flag script available in the command history (inline); SECRET hardcoded to reproduce.

---

## Appendix — tools

- `scratchpad/child.elf` — child ELF reconstructed from the static unpacking of the loader (24296 bytes, FNV `0x12b94ef2` confirmed).
