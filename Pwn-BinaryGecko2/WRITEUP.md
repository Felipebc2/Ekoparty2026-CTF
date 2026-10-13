<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Second+Chall+by+Binary+Gecko+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Second Chall by Binary Gecko — PWN · 400 pts · 🟡 MEDIUM

- **Status:** 🟡 OPEN — Flag 1 obtained offline (likely reused from chall 1); Flag 2 has a WPM vector that is designed and reviewed, ready to run, but not executed.
- **Flag:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88` (Flag 1; Flag 2 = —)
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `nc <IP> <PORT>` — Windows process, *low integrity*, restarted by an external watcher every ~10 min.
- **Prompt:** *"Un proceso remoto de Windows, ejecutado con nivel de integridad bajo... Obtén una o ambas flags contenidas en la memoria del proceso, mediante fuga de datos y/o compromiso del proceso."*

---

## 0. TL;DR

1. The host (`gecko2026.exe`) and its DLL are byte-for-byte identical to those of "First Chall by Binary Gecko" — the protocol and the leak/write primitive (`flag=1`/`flag=2`, `ReadProcessMemory`/`WriteProcessMemory` at `base_DLL+counter`) came for free.
2. **Flag 1** comes out through the same path as chall 1: leak of the entire DLL + offline decrypt of the embedded encrypted blob.
3. The prompt asks for "one or both" flags, "mediante fuga de datos y/o compromiso del proceso" — suggesting that **Flag 2 requires compromising the process** (write), since pure reading does not reach any new region.
4. **Flag 2** designed via `WriteProcessMemory` (`flag=2`) to patch a dead handler (`flag=0`) of the DLL itself with shellcode that does a PEB-walk and reads the host EXE (a region never reachable by reading alone) — vector ready, not executed in this session.

### Chain that closed (Flag 1)
1. Full leak of the DLL image via `flag=1` (`sweep2.py`) -> `module_dump_chall2.bin`
2. Byte-for-byte diff against the chall 1 dump: code 100% identical; only the encrypted blob, the embedded XOR key and ASLR pointers change
3. Known-plaintext (`ct[:4] ^ b"HIK_"`) -> 4-byte XOR key -> decrypt of the 60-byte blob
4. `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`

### Chain designed, not executed (Flag 2)
1. `<IBII>(N, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin` -> overwrites the dead slot of the `flag=0` handler
2. `<IBII>(N, flag=0, counter=OFF, len=0x1000)` sweeping `OFF = 0, 0x1000, ...` over the host EXE, same connection
3. Search for `HIK_`/`FLAG:` in each response

---

## 1. Artifacts

- `gecko2026.exe` — delivered host, byte-for-byte identical to the one from chall 1.
- `module_dump_chall2.bin` (76 KB) — raw dump of this chall's DLL image, via `sweep2.py` (`flag=1`).
- `exe_live_dump.bin`, `heap_live_dump.bin`, `peb_dump.bin` — auxiliary live dumps (EXE/heap/PEB).
- `wpm_shellcode.bin` (82B), `sc_absread.bin`, `sc_peb.bin`, `sc_stackscan.bin` — shellcodes assembled/verified with objdump.
- `WPM_PLAN.md` — detailed technical attachment of the WPM vector (facts vs hypothesis, shellcode source+hex).
- Scripts: `chase_e370.py`, `exploit_v2.py`, `exploit_wpm.py`, `final_scan.py`, `leak2.py`, `rpm_extended.py`, `scan_all.py`, `scan_base.py`, `scan_env.py`, `sweep2.py`.

## 2. Delivery / validation

There is no external oracle described; both flags have the format `HIK_<text>_<md5 32 hex>` and are obtained by directly reading/writing the process memory (no submission endpoint in this session's notes).

## 3. Analysis

### 3.1 Protocol (recap from chall 1 — same binary)
1. Client connects and sends the cookie: `b"Ekoparty 2026 - Binary Gecko CTF challenge"`.
2. Server replies with the health banner: `b"Welcome to this CTF\x00"` (20B). The host oscillates healthy/degraded and has a per-IP rate-limit (~65-75s) — if the banner comes back all-zero, close and retry after the cooldown.
3. After that, each request is a `struct <IBII>` header = `N(u32), flag(u8), counter(u32), len(u32)` followed by `data[]`:
   - `flag=1` → `ReadProcessMemory(self, base_DLL + counter, &resp, len)` — leak by offset.
   - `flag=2` → `WriteProcessMemory(self, base_DLL + counter, data, len)` — arbitrary write.
   - `counter` is u32, forward-only from the DLL base; `len ≤ 0x1000`.
4. The DLL base (ASLR, page-aligned `...0000`) is recoverable at runtime: there is a self-ptr at `base+0xd068` that points to the string `"FLAG:"` at `base+0xd020` → `base = (ptr@0xd068) - 0xd020`.

### 3.2 Flag 1 — offline decrypt of the DLL blob
`module_dump_chall2.bin` is the raw dump of the DLL image (`0x0..0x13000`), collected via `sweep2.py` (`flag=1`, sweeping offset by offset). Byte-for-byte diff against the chall 1 dump: code 100% identical; only the encrypted blob (`0xd026..0xd060`), the embedded 4B XOR key (`0xe368`) and ASLR pointers change.

The DLL loads the encrypted flag and has the decryptor embedded, but it is never called in the normal flow — so the decrypt is done manually, with known-plaintext (the text starts with `HIK_`):

```python
d  = open("module_dump_chall2.bin","rb").read()
ct = d[0xd026:0xd026+60]
key = bytes(c ^ p for c, p in zip(ct[:4], b"HIK_"))     # 4B key (XOR is involutive)
flag = bytes(ct[i] ^ key[i % 4] for i in range(60))
# -> HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88
```

**Flag 1:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`

⚠️ **Caveat:** the text is `GECKO2026_CHALLENGE1` and the MD5 came out identical to chall 1's — it is the same flag reused (identical host, only the seed changes per boot, but the plaintext is the same). Per the prompt ("una o ambas"), it counts as one of the two, but it is probably not the flag exclusive to chall 2. Not confirmed on the platform whether it already scored; if so, what matters is Flag 2.

### 3.3 Flag 2 — why pure reading does not reach it
Mapping of what the `flag=1` primitive can touch (reads `base_DLL + counter`, `counter` u32 forward-only):

| Region | Reachable by `flag=1`? |
|---|---|
| DLL image (`0..0x13000`) | ✅ already dumped — only has Flag 1 |
| Page right after (`0x13000`) | ❌ unmapped (confirmed live) |
| Heap / stack / host EXE | ❌ they sit below the DLL base (`0x7ffa...`); counter only moves forward |
| Other DLLs | technically ahead, but it is lib code + addresses change per boot due to ASLR |

Sweep of the 3237 pointers in the dump: 3019 point below the base (heap/EXE — unreachable) and the 68 forward-reachable ones are all IAT→neighboring DLL. None leads to Flag 2. Conclusion: Flag 2 does not come out by reading — it matches the prompt (*low integrity* + *compromiso del proceso*): it needs `WriteProcessMemory`.

### 3.4 Flag 2 — compromise vector (WPM / `flag=2`)
**Idea:** the `flag=2` write is also `base_DLL + counter` forward, and a small `counter` (`0..0x13000`) falls inside the RX image of the DLL itself. `WriteProcessMemory` ignores page protection → it is possible to patch the DLL's `.text`. Plan: plant shellcode and execute it by abusing a dead handler.

Facts (confirmed by static disassembly of `gecko2026.exe` + dump):
- **Dispatch table** at `base+0xe340`: 3 handlers — `0x1620`(flag0), `0x1690`(flag1/RPM), `0x1730`(flag2/WPM). The `flag` byte indexes the table.
- **`flag=0` is dead code post-boot:** it is a *one-shot* guard (`if DAT_e36c==1 {...; DAT_e36c=0}`) consumed at startup by the EXE itself. Afterwards, no-op. The slot `base+0x1620..0x1690` (112B, includes `0xCC` padding) is safe to overwrite without touching the RPM/WPM handlers the other teams use.
- Fixed offsets relative to the base: RPM IAT `0xa028`, dispatch table `0xe340`, slot `0x1620`.

**Shellcode (82B — `wpm_shellcode.bin`, assembled and verified with objdump):** does a PEB-walk to the first loaded module (= the host EXE), adds `counter`, and calls the real `ReadProcessMemory` (via IAT) to read `exe_base + counter` into the response buffer. Once planted, `flag=0` becomes an "RPM from the EXE" — exactly the region the original leak (DLL base) never covered.

```asm
sub rsp, 0x38
mov r11, rcx              ; rcx = &hdr (struct <IBII>+data on the handler's stack)
mov edx, [r11+5]          ; edx = hdr.counter
mov rax, [gs:0x30]        ; TEB
mov rax, [rax+0x60]       ; PEB
mov rax, [rax+0x18]       ; PEB_LDR_DATA
mov rax, [rax+0x10]       ; InLoadOrderModuleList.Flink -> 1st entry (= EXE)
mov rax, [rax+0x30]       ; DllBase of the EXE
add rax, rdx              ; exe_base + counter
mov rdx, rax              ; lpBaseAddress
lea r8,  [r11+0xd]        ; lpBuffer = hdr.data (buffer the EXE returns)
mov r9d, [r11+9]          ; nSize = hdr.len
mov rcx, -1               ; hProcess = pseudo-handle (current process)
mov qword [rsp+0x20], 0   ; lpNumberOfBytesRead = NULL
call qword [rip+0x89c0]   ; = call [base+0xa028] = *ReadProcessMemory  (only valid if planted at 0x1620)
mov eax, 1                ; always reports success -> keeps the connection alive to chain the sweep
add rsp, 0x38
ret
```

> `call [rip+0x89c0]` only resolves to `base+0xa028` **if** planted at `base+0x1620`. At another offset: `disp = 0xa028 - (destination + 0x48)`.

**Execution plan (1 connection):**
1. Cookie → require healthy banner (retry if degraded).
2. **PATCH:** `<IBII>(N, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin` → overwrites the dead slot.
3. **TRIGGER + SWEEP** (same connection): several `<IBII>(N, flag=0, counter=OFF, len=0x1000)` with `OFF = 0, 0x1000, 0x2000, ...` sweeping the EXE forward; search for `HIK_`/`FLAG:` in each response.
4. If nothing in a few MB → stop (do not escalate alone to a shellcode v2 with heap-walk without a new OK).

### 3.5 Risks (shared process)
- The patch changes the behavior of `flag=0` for all teams until the restart (~10 min). It does not crash (RPM fails "cleanly", the shellcode always returns 1), but it is a visible change to the protocol.
- The "`flag=0` is dead code" premise comes from a point reading, not an exhaustive one → low risk, not zero.
- No undo over the network — only the 10-min restart restores the binary.
- 1 connection covers patch+sweep; if the patch fails, the connection drops and it waits for the cooldown (~65-75s).

## 4. What didn't work

| Hypothesis | Result | Why |
|---|---|---|
| Reaching Flag 2 with reading only (`flag=1`) | ✗ | All forward-reachable pointers lead only to neighboring DLL code (IAT); heap/stack/EXE sit below the base and `counter` only moves forward. |

## 5. Conclusion / next steps

Flag 1 closed via leak+offline decrypt (same mechanism as chall 1, possibly a reused flag). Flag 2 stayed stuck: the `WriteProcessMemory` vector to patch the dead handler (`flag=0`) and use it as a reader of the host EXE is **fully designed, reviewed and with shellcode assembled and verified**, but was not executed in this session (risk of affecting the process shared between teams without final confirmation). Next step: execute the §3.4 plan in a single connection (patch + trigger + sweep) and, if nothing appears in a few MB of the EXE, stop — do not escalate to a shellcode v2 with heap-walk without additional validation.

---

## Appendix — tools

- `sweep2.py` — full leak of the DLL image (`flag=1`), generated `module_dump_chall2.bin`.
- `rpm_extended.py` — extended leak `flag=1` (read-only); proved that `0x13000+` is unmapped.
- `exploit_wpm.py` — trigger script for the WPM vector (patch of the `flag=0` slot + sweep of the EXE).
- `chase_e370.py`, `final_scan.py`, `leak2.py`, `scan_all.py`, `scan_base.py`, `scan_env.py`, `exploit_v2.py` — auxiliary recon/memory-scan scripts used throughout the session.
