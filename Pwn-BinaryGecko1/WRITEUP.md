<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=First+Chall+by+Binary+Gecko+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# First Chall by Binary Gecko — PWN · 200 pts · 🟢 EASY

- **Status:** ✅ SOLVED — flag obtained via offline decrypt of the blob embedded in the DLL leaked from memory.
- **Flag:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `nc <IP> <PORT>` (raw TCP, Windows Server 2022 on AWS eu-central-1; periodic restart) / HTTP `<IP>:8080` serves only `gecko2026.exe`
- **Prompt:** *(not transcribed in the session notes; the target delivers only `chall.exe`/`gecko2026.exe`, the processor DLL runs only on the server)*

---

## 0. TL;DR

1. The challenge delivers only a `chall.exe` (= `gecko2026.exe`, served over HTTP `:8080`). At runtime it loads `gecko2026-module.dll` (function `processor`) which is **not distributed** and runs only on the server.
2. **You don't need the DLL from disk.** The `processor` is a **dispatcher of 3 opcodes for R/W of the process's own memory**. The **read** opcode (`flag=1`) is a `ReadProcessMemory(self, base+counter, …)` — an **arbitrary memory leak** (~4 GB window from the DLL base).
3. With that leak we dump the entire DLL from memory → `module_dump.bin`. Inside it, right after the string `FLAG: `, there is a **60-byte encrypted blob** = the flag.
4. The DLL **never decrypts that blob** in the service flow, but the decrypt routine (per-word XOR with a built-in 4-byte key) is in the DLL itself → **decrypt it offline**.

### Chain that closed it
1. `cookie "Ekoparty 2026 - Binary Gecko CTF challenge"` -> healthy banner `"Welcome to this CTF\0"` (20B)
2. `<IBII>(N=0xd, flag=1, counter=0x0, len=0x1000)` -> leak of 4KB from the DLL base; repeat with `counter += 0x1000` until `0x12000` (the next unmapped page closes the connection)
3. Assemble `module_dump.bin` (76 KB) from the chained leaks
4. Locate `"FLAG: "` at file-off `0xd020`; 60-byte encrypted blob at `0xd026`
5. Known-plaintext `ct[:4] ^ b"HIK_"` -> 4-byte XOR key `e1 3b ee 03`; decrypt the 60 bytes -> flag

---

## 1. Artifacts

- `chall.exe` / `gecko2026.exe` — delivered host (identical), a Winsock service that loads `gecko2026-module.dll` at runtime.
- `module_dump.bin` (76 KB) — the `gecko2026-module.dll` reconstructed from memory via leak (raw image, base `0x7ffae5040000`).
- `exploit_leak.py` — leak primitive (`flag=1`), with a healthy-banner guard.
- `exploit_initrun.py`, `exploit_vm.py`, `exploit_flagsweep.py` — attempts at old hypotheses (useful protocol reference; premises refuted, see §4).
- `decrypt_flag.py` — offline decrypt of the flag blob.
- `NOTES.md` — full disassembly and session timeline.

## 2. Delivery / validation

There is no external oracle: the flag is obtained entirely offline, via memory leak + local decrypt. Flag format: `HIK_GECKO2026_CHALLENGE1_<md5 32 hex>`.

## 3. Analysis

### 3.1 Surface recon
- `:<PORT>` — raw Winsock service, 1 thread per connection, **per-IP rate-limiter ~60s cumulative** (each touch re-arms +60s; use ≥70s between connections, don't hammer).
- `:8080` — Python `SimpleHTTP` with directory listing, serves **only** `gecko2026.exe`. Tested: `gecko2026-module.dll`, `flag`, `.git` etc → 404. The DLL is **not** exposed.
- `:3389` — RDP (NLA/CredSSP), host `EC2AMAZ-IMAJVSF`, standalone Windows Server 2022. No founded credential → discarded as a vector.
- OSINT: `github.com/Binary-Gecko` has their 2024/2025 challenges (they only deliver the EXE, no source). The 2025 one is "Escape from the virtual Intel x64 CPU" — a **false lead** for 2026 (see §4).

### 3.2 Protocol (from the disassembly of `chall.exe`)
Per connection, 2 stages. Struct passed to the `processor` at `rsp+0x30`, packed `<IBII>` + body:

| offset | field | type | meaning (confirmed) |
|--------|-------|------|--------------------------|
| +0  | `field0` (N) | u32 | total size; `0xd ≤ N ≤ 0x100d`; body = `N-13` bytes |
| +4  | `flag`       | u8  | processor opcode (0/1/2) |
| +5  | `counter`    | u32 | memory offset from the DLL base (zero-extended) |
| +9  | `len`        | u32 | number of bytes returned by `send` (`len ≤ 0x1000`) |
| +13 | `data[]`     | u8[]| body of `N-13` bytes (data for Write; ignored on Read) |

- **Stage 1 (cookie):** `recv(256)` → `strcmp` against `Ekoparty 2026 - Binary Gecko CTF challenge` (42 bytes, no NUL). If it matches, it returns a 20-byte banner (`Welcome to this CTF\0` when the server is healthy). The banner fluctuates: sometimes 20 zeroed bytes come back (unstable server) — a stage2 result in those windows is garbage. Always require the healthy banner before acting.
- **Stage 2 (loop):** send a 13-byte header `<IBII>(N, flag, counter, len)` + body in the same `sendall` (if `N>0xd`, the exe does ONE `recv(N-13)` and requires everything in a single recv, otherwise it closes). The `processor` runs; if it returns 1 → `send(data, len)` and back to the loop (you can chain several); if it returns 0 → the connection dies.

### 3.3 What the `processor` actually does (from the reconstructed DLL)
Real DLL image base: `0x7ffae5040000`. Dispatcher at file-off `0x1800`. Reads `flag`; if `≥3` returns 0 (closes). Otherwise it calls `handler_table[flag]`:

| flag | handler (file-off) | action |
|------|--------------------|------|
| 0 | 0x1620 | one-shot guard (`[0xd064]==1`); writes a constant into `data[0..3]`. Guard=0 → no-op. |
| **1** | 0x1690 | `ReadProcessMemory(GetCurrentProcess(), base+counter, data[], len)` → **LEAK** |
| **2** | 0x1730 | `WriteProcessMemory(GetCurrentProcess(), base+counter, data[], len)` → **arbitrary WRITE** |
| ≥3 | — | returns 0 (closes) |

Effective address = `base + counter` (counter u32 → ~4 GB reach above the base); `len ≤ 0x1000`. **No** `CreateProcess`/`WaitForDebugEvent`/`SetThreadContext` anywhere — there is no VM or single-step. It is pure R/W of the process's own address space.

### 3.4 Exploit — leaking the DLL
`flag=1` + `counter`=offset + `len`=0x1000 reads 4 KB from `base+counter`. `counter=0` returns the DLL's own `MZ` header. Sweeping `counter = 0, 0x1000, 0x2000, …` (the gate stays open, chaining dozens of leaks in one connection) we dump the whole image: RVA `0..0x12000` mapped, `0x13000` is already an unmapped page (`ReadProcessMemory` fails → returns 0 → connection closes). Result: `module_dump.bin` (76 KB), confirmed PE32+ DLL exporting `processor`, name `gecko2026-module.dll`.

How to analyze `module_dump.bin`: it is a dump of the virtual image, not the on-disk PE. Load it as raw/flat at base `0x7ffae5040000` (`objdump -D -b binary -mi386:x86-64 --adjust-vma=0x7ffae5040000`, or Ghidra importing as raw x86-64 at that base). If you let the tool parse the section headers, it maps the VAs wrong.

### 3.5 Where the flag is
In the DLL's `.data`, file-off `0xd020`: the ASCII string `FLAG: ` followed by 60 encrypted bytes (file-off `0xd026`):

```
a972a55ca67ead48ae09de31d764ad4ba077a246af7cab32be02d866855fdc65
d30bdc30d05eda66d70fd660835f8a67d45ddc3a840e8a3bd9c411fc
```

Pattern: even-index bytes high (`0x83–0xde`, looks like keystream), odd ones mostly ASCII.

### 3.6 Solution — offline decrypt of the blob
The DLL does **not** decrypt its own blob, but the decrypt routine is there (embedded key) — so you can reproduce it offline, without any additional connection:

- **Decryptor** = `fcn@0x1160` (VA `0x7ffae5041160`): XOR of 32-bit words of the blob (`"FLAG: "+6` = file-off `0xd026`, 60 bytes) against a 4-byte key at `[0xe368]` (filled by `fcn@0x1050`). The caller `fcn@0x1240` does `add rax,6` to skip `"FLAG: "` before the XOR.
- **Key = `e1 3b ee 03`** (LE word `0x03ee3be1`). Recoverable by known-plaintext: `ct[:4] ^ "HIK_"` (`a9 72 a5 5c ^ 48 49 4b 5f = e1 3b ee 03`). XOR is involutive → the same key decrypts the 60 bytes.
- Decrypted: `HIK_GECKO2026_CHALLENGE1_` + 32 hex of MD5; the final 3 `0xff` bytes are padding.

```python
ct  = open("module_dump.bin","rb").read()[0xd026:0xd026+60]
key = bytes.fromhex("e13bee03")          # = ct[:4] ^ b"HIK_"
flag = bytes(ct[i]^key[i%4] for i in range(60)).rstrip(b"\xff").decode()
# -> HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88
```

> Alternative paths that would also close it (not needed): read the plaintext flag in another region via the leak (`ReadProcessMemory`, base+counter ~4 GB), or use the arbitrary write (`flag=2`) for code-exec.

### 3.7 Quick recipe

```
cookie  = b"Ekoparty 2026 - Binary Gecko CTF challenge"   # 42B, no NUL
# stage1: sendall(cookie); recv 20B; REQUIRE == b"Welcome to this CTF\0" (otherwise unstable server, retry)
# stage2 READ: sendall(struct.pack("<IBII", 0xd, 1, counter, 0x1000))   # flag=1, N=0xd (no body)
#   -> receives 0x1000 bytes from (base+counter). chain counter=0,0x1000,... to sweep memory.
# stage2 WRITE: sendall(struct.pack("<IBII", 0xd+len(data), 2, counter, len(data)) + data)  # flag=2
# DLL base = 0x7ffae5040000 ; the flag blob is at counter=0xd026 (60 bytes).
```

Rate-limiter ~60s/IP cumulative → 1 connection per attempt, ≥70s interval, don't hammer. Switching IP resets the penalty.

## 4. What didn't work

| Hypothesis | Result | Why |
|---|---|---|
| Stack leftover / gate `counter==T` | ✗ | There is no token gate. `counter` is just a memory offset. The "zeroed banner" that looked like a block was just the server fluctuating. |
| Single-step VM in the style of the 2025 challenge → escape → FLAG | ✗ | The 2026 `processor` has no debuggee or single-step, and no code references `FLAG: `/the blob — there is no win condition to trigger. |
| RDP / downloading the DLL from `:8080` | ✗ | No founded credential / DLL not exposed over HTTP. |
| Trivial XOR on the blob (single-byte, add/sub, XOR-counter, CBC-rolling, even/odd split, XOR against binary strings) | ✗ | Nothing yields `HIK_`; the real key only comes out via known-plaintext against the DLL's actual decryptor. |

## 5. Conclusion / next steps

It closed because the arbitrary-read primitive (`flag=1`) lets you reconstruct the entire DLL without ever needing it on disk, and the embedded decrypt routine (even though never called by the service) is enough to reproduce the algorithm offline and recover the key via known-plaintext (fixed `HIK_` at the start of the flag).

---

## Appendix — tools

- `exploit_leak.py` — `python3 exploit_leak.py`: parametrizable leak (`flag=1`, counter/len) with a healthy-banner guard; used to sweep the entire DLL image.
- `decrypt_flag.py` — `python3 decrypt_flag.py`: offline decrypt of the flag blob in `module_dump.bin` (known-plaintext 4-byte XOR).
- `exploit_initrun.py`, `exploit_vm.py`, `exploit_flagsweep.py` — attempts at discarded hypotheses (token gate / single-step VM); kept as a protocol reference.
