<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Butterfly+Effect+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Butterfly Effect — REVERSE · 250 pts · 🟡 MEDIUM

- **Status:** ✅ SOLVED — obtained from the live service after clearing the 5 rounds.
- **Flag:** `HIK_BUTTERFLY_EFFECT_e555fdfcf33e97a369ae397de0413a8f`
- **Flag format:** `HIK_[text]_[md5]` (confirmed OK)
- **Access:** `nc <IP> 18663`
- **Prompt:** —

---

## 0. TL;DR

1. Static, stripped x86-64 ELF64 binary (`butterfly-check`), which validates a sequence of 12 hex words against an ID, via an ARX state machine obfuscated with an anti-debug decoy.
2. The "dead" engine is never reached (decoy); the real algorithm is an ARX with 2 accumulators (`h`, `ebp`) and 4 modes, derived from an embedded table of 19 constants.
3. Since all multiplications are by an odd constant (bijective), the update is invertible — you can build a deterministic keygen from the ID received from the service, validated by Unicorn emulation before running against the real binary.

### Chain that closed it
1. `nc <IP> 18663` -> receives an ID (32 hex) per round.
2. Keygen (`scratchpad/solver.py`) inverts the ARX and generates SEQ (12 groups of 8 hex, `-` sep).
3. `butterfly-check <ID> <SEQ>` -> VALID (confirmed in a Unicorn emulator and in the real binary).
4. Repeat for 5 rounds -> the service delivers the flag.

---

## 1. Artifacts

- `butterfly-check` — ELF64 x86-64, static, stripped, 5 KB, only syscalls (`ptrace`/`write`/`exit`). SHA256 `2802d409ac6254c1b769dc375ca4a808d12b02076811bd5890c01a531c90723e` (matches `SHA256SUMS`).
- `SHA256SUMS` — verification hash of the binary.
- Remote: `nc <IP> 18663` — 5 rounds; each gives an ID (32 hex) and requires 12 groups of 8 hex (`-` sep); 5 VALID => flag.

## 2. Delivery / validation

- CLI: `butterfly-check <ID 32hex> <SEQ 12x8hex '-'>` -> VALID/INVALID (exit 0/1).
- The remote service generates an ID per round and requires the correct SEQ; 5 consecutive VALID rounds release the flag.

## 3. Analysis

### 3.1 Anti-analysis

- `ptrace(PTRACE_TRACEME)` at the start (anti-debug; the result is not checked).
- FNV-1a self-integrity (base `0x811c9dc5`, mult `0x01000193`) over the blob `[0x200100,0x200180)`; `cmp r10d,0x6d576050`. Passes on the intact binary.
- "Dead" engine (`@0x20105e..0x2012b1`) is never reached: the gate `test cl,1` on `x*(~x)` is always even (bit0=0), so the `jne` never fires. Anti-analysis decoy.

### 3.2 Real algorithm (state machine @0x200cf9) — ARX with 2 accumulators

Embedded table @0x200100: `count=19, perm[19], target[19]`. Loop @0x200520 derives 19 constants `chk[i]` (via `perm[i]*0x9e3779b1 ^ 0xc25abd29`, fmix32, `^ target[perm[i]]`). Concrete values:

- `chk[0..3]` (per-mode mults) = `2d2afe11, 3b6a02ff, 0b82f90f, 3157079d`
- `chk[5]=1, chk[7]=22` (rotations of modes 1 and 3); `chk[8]=e6fba04f, chk[9]=9` (ebp update)
- `chk[10]=3, chk[11]=bda924db` (checkpoints); `chk[12]=20, chk[13]=2860f229` (final target)
- `chk[14]=12` (size), `chk[15]=3` (number of checkpoints), `chk[16..18]={3,6,9}` (positions)

ID (32 hex) -> 4 big-endian u32 `ID0..ID3`. Seeds: `h=ID0`, `ebp=ID2`, `mode=ID1&3`. For `idx=0..11`, it processes `word[idx]` according to `mode` (2 bits), updates `h` and then `ebp`, and at checkpoint positions compares `h` with the target. `(a|b)-(a&b)=a^b` and `lea[x^y+2*(x&y)]=x+y` obfuscate xor/add.

`h` update per word (new `h`):

- mode0: `h = (h + word*0x2d2afe11) ^ ebp`
- mode1: `h = rol(h ^ (word*0x3b6a02ff), 1) + ebp`
- mode2: `h = (h ^ ebp) + (word*0x0b82f90f)`
- mode3: `h = rol(h + word*0x3157079d, 22) ^ ebp`

After each word: `ebp = rol(ebp, 9) + 0xe6fba04f`. `mode' = ((mode+(word&1)+1) ^ (h_old>>31) + 2*((h_old>>31) & (mode^((word&1)+1)))) & 3`.

Targets:

- checkpoint `k` (`k=0,1,2`), required in `h` after word `3*(k+1)-1` (idx 2,5,8): `T = ID1*(k+1) + rol(ID0^ID3, 3*(k+1)) + 0xbda924db`
- final, `h` after word 11: `T = rol(ID0^ID1^ID2^ID3, 20) ^ 0x2860f229`

### 3.3 Keygen (invertible)

All mults are by an odd constant => bijective. Free words = 0; at positions 3,6,9,12 you invert the update of the current mode to hit the target:

- mode0: `word = ((T^ebp)-h) * inv(c0)`
- mode1: `word = (h ^ ror(T-ebp,1)) * inv(c1)`
- mode2: `word = (T-(h^ebp)) * inv(c2)`
- mode3: `word = (ror(T^ebp,22)-h) * inv(c3)` (all mod `2^32`)

### 3.4 Validation

- Exact oracle: Unicorn harness (`scratchpad/emu.py`) emulating from the entry, stubbing `ptrace`/`write`/`exit`; a trace at the dispatch `0x200cf9` revealed the state sequence and the evolution of `h`.
- Keygen (`scratchpad/solver.py`): 20/20 random IDs => VALID in the emulator.
- Ground truth: real binary in bwrap (no network, `+x` in a dir outside artifacts): resolved SEQ => VALID; zeros => INVALID. Emulator == binary.
- Client (`scratchpad/remote.py`, pwntools): 5 rounds OK => FLAG.

## 4. What didn't work

| Hypothesis | Result | Why |
|---|---|---|
| The "dead" engine (`0x20105e..0x2012b1`) being the real algorithm | ✗ | gate `test cl,1` on `x*(~x)` always even; `jne` never fires — anti-analysis decoy |

## 5. Conclusion / next steps

It closed with a deterministic keygen, validated in a Unicorn emulator and confirmed against the real binary and the live service across 5 rounds. No honeypot ("static HIK_"/"If you are an AI") found in the binary; the flag only came from the live oracle.

---

## Appendix — tools

- `scratchpad/emu.py` — Unicorn harness that emulates the binary from the entry, stubbing `ptrace`/`write`/`exit`, used as an exact oracle to validate the reversed algorithm.
- `scratchpad/solver.py` — keygen: inverts the ARX and generates the SEQ from the ID; tested 20/20 on random IDs.
- `scratchpad/remote.py` — pwntools client: solves the 5 rounds against the remote service and extracts the flag.
