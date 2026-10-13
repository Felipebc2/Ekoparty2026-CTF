<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Butterfly+Effect+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Butterfly Effect — REVERSE · 250 pts · 🟡 MEDIUM

- **Status:** ✅ RESUELTO — obtenida del servicio vivo tras limpiar las 5 rondas.
- **Flag:** `HIK_BUTTERFLY_EFFECT_e555fdfcf33e97a369ae397de0413a8f`
- **Flag format:** `HIK_[texto]_[md5]` (confirmado OK)
- **Acceso:** `nc <IP> 18663`
- **Enunciado:** —

---

## 0. TL;DR

1. Binario ELF64 x86-64 estático, stripped (`butterfly-check`), que valida una secuencia de 12 palabras hex contra un ID, vía una state machine ARX ofuscada con anti-debug decoy.
2. La engine "muerta" nunca es alcanzada (decoy); el algoritmo real es un ARX con 2 acumuladores (`h`, `ebp`) y 4 modos, derivado de una tabla embebida de 19 constantes.
3. Como todas las multiplicaciones son por constante impar (biyectivas), el update es invertible — se puede armar un keygen determinístico a partir del ID recibido del servicio, validado por emulación Unicorn antes de correr contra el binario real.

### Cadena que cerró
1. `nc <IP> 18663` -> recibe ID (32 hex) por ronda.
2. Keygen (`scratchpad/solver.py`) invierte el ARX y genera SEQ (12 grupos de 8 hex, `-` sep).
3. `butterfly-check <ID> <SEQ>` -> VALID (confirmado en emulador Unicorn y en el binario real).
4. Repetir por 5 rondas -> el servicio entrega la flag.

---

## 1. Artefactos

- `butterfly-check` — ELF64 x86-64, estático, stripped, 5 KB, solo syscalls (`ptrace`/`write`/`exit`). SHA256 `2802d409ac6254c1b769dc375ca4a808d12b02076811bd5890c01a531c90723e` (coincide con `SHA256SUMS`).
- `SHA256SUMS` — hash de verificación del binario.
- Remoto: `nc <IP> 18663` — 5 rondas; cada una da un ID (32 hex) y exige 12 grupos de 8 hex (`-` sep); 5 VALID => flag.

## 2. Entrega / validación

- CLI: `butterfly-check <ID 32hex> <SEQ 12x8hex '-'>` -> VALID/INVALID (exit 0/1).
- El servicio remoto genera un ID por ronda y exige la SEQ correcta; 5 rondas VALID consecutivas liberan la flag.

## 3. Análisis

### 3.1 Anti-análisis

- `ptrace(PTRACE_TRACEME)` al inicio (anti-debug; el resultado no se chequea).
- Auto-integridad FNV-1a (base `0x811c9dc5`, mult `0x01000193`) sobre el blob `[0x200100,0x200180)`; `cmp r10d,0x6d576050`. Pasa en el binario íntegro.
- Engine "muerta" (`@0x20105e..0x2012b1`) nunca es alcanzada: el gate `test cl,1` en `x*(~x)` es siempre par (bit0=0), así que el `jne` nunca dispara. Decoy anti-análisis.

### 3.2 Algoritmo real (state machine @0x200cf9) — ARX con 2 acumuladores

Tabla embebida @0x200100: `count=19, perm[19], target[19]`. Loop @0x200520 deriva 19 constantes `chk[i]` (vía `perm[i]*0x9e3779b1 ^ 0xc25abd29`, fmix32, `^ target[perm[i]]`). Valores concretos:

- `chk[0..3]` (mults por modo) = `2d2afe11, 3b6a02ff, 0b82f90f, 3157079d`
- `chk[5]=1, chk[7]=22` (rotaciones de los modos 1 y 3); `chk[8]=e6fba04f, chk[9]=9` (update de ebp)
- `chk[10]=3, chk[11]=bda924db` (checkpoints); `chk[12]=20, chk[13]=2860f229` (target final)
- `chk[14]=12` (tamaño), `chk[15]=3` (nº de checkpoints), `chk[16..18]={3,6,9}` (posiciones)

ID (32 hex) -> 4 u32 big-endian `ID0..ID3`. Seeds: `h=ID0`, `ebp=ID2`, `mode=ID1&3`. Para `idx=0..11`, procesa `word[idx]` según `mode` (2 bits), actualiza `h` y después `ebp`, y en posiciones de checkpoint compara `h` con el target. `(a|b)-(a&b)=a^b` y `lea[x^y+2*(x&y)]=x+y` ofuscan xor/add.

Update de `h` por palabra (nuevo `h`):

- mode0: `h = (h + word*0x2d2afe11) ^ ebp`
- mode1: `h = rol(h ^ (word*0x3b6a02ff), 1) + ebp`
- mode2: `h = (h ^ ebp) + (word*0x0b82f90f)`
- mode3: `h = rol(h + word*0x3157079d, 22) ^ ebp`

Después de cada palabra: `ebp = rol(ebp, 9) + 0xe6fba04f`. `mode' = ((mode+(word&1)+1) ^ (h_old>>31) + 2*((h_old>>31) & (mode^((word&1)+1)))) & 3`.

Targets:

- checkpoint `k` (`k=0,1,2`), exigido en `h` después de la palabra `3*(k+1)-1` (idx 2,5,8): `T = ID1*(k+1) + rol(ID0^ID3, 3*(k+1)) + 0xbda924db`
- final, `h` después de la palabra 11: `T = rol(ID0^ID1^ID2^ID3, 20) ^ 0x2860f229`

### 3.3 Keygen (invertible)

Todas las mults son por constante impar => biyectivas. Palabras libres = 0; en las posiciones 3,6,9,12 se invierte el update del modo corriente para acertar el target:

- mode0: `word = ((T^ebp)-h) * inv(c0)`
- mode1: `word = (h ^ ror(T-ebp,1)) * inv(c1)`
- mode2: `word = (T-(h^ebp)) * inv(c2)`
- mode3: `word = (ror(T^ebp,22)-h) * inv(c3)` (todo mod `2^32`)

### 3.4 Validación

- Oráculo exacto: harness Unicorn (`scratchpad/emu.py`) emulando desde el entry, stubeando `ptrace`/`write`/`exit`; un trace en el dispatch `0x200cf9` reveló la secuencia de estados y la evolución de `h`.
- Keygen (`scratchpad/solver.py`): 20/20 IDs aleatorios => VALID en el emulador.
- Ground truth: binario real en bwrap (sin red, `+x` en un dir fuera de artefactos): SEQ resuelta => VALID; ceros => INVALID. Emulador == binario.
- Cliente (`scratchpad/remote.py`, pwntools): 5 rondas OK => FLAG.

## 4. Lo que no funcionó

| Hipótesis | Resultado | Por qué |
|---|---|---|
| La engine "muerta" (`0x20105e..0x2012b1`) ser el algoritmo real | ✗ | gate `test cl,1` en `x*(~x)` siempre par; `jne` nunca dispara — decoy anti-análisis |

## 5. Conclusión / próximos pasos

Cerró con un keygen determinístico, validado en emulador Unicorn y confirmado contra el binario real y el servicio vivo en 5 rondas. Ningún honeypot ("HIK_ estático"/"If you are an AI") encontrado en el binario; la flag solo vino del oráculo vivo.

---

## Apéndice — herramientas

- `scratchpad/emu.py` — harness Unicorn que emula el binario desde el entry, stubeando `ptrace`/`write`/`exit`, usado como oráculo exacto para validar el algoritmo revertido.
- `scratchpad/solver.py` — keygen: invierte el ARX y genera la SEQ a partir del ID; probado 20/20 en IDs aleatorios.
- `scratchpad/remote.py` — cliente pwntools: resuelve las 5 rondas contra el servicio remoto y extrae la flag.
