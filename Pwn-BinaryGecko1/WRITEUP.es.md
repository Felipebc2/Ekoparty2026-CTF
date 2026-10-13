<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=First+Chall+by+Binary+Gecko+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# First Chall by Binary Gecko — PWN · 200 pts · 🟢 EASY

- **Status:** ✅ RESUELTO — flag obtenida mediante decrypt offline del blob embebido en la DLL filtrada de la memoria.
- **Flag:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `nc <IP> <PORT>` (TCP crudo, Windows Server 2022 en AWS eu-central-1; reinicio periódico) / HTTP `<IP>:8080` sirve solo `gecko2026.exe`
- **Enunciado:** *(no transcrito en las notas de la sesión; el objetivo entrega solo `chall.exe`/`gecko2026.exe`, la DLL del processor corre solo en el servidor)*

---

## 0. TL;DR

1. El desafío entrega solo un `chall.exe` (= `gecko2026.exe`, servido en el HTTP `:8080`). En runtime carga `gecko2026-module.dll` (función `processor`) que **no se distribuye** y corre solo en el servidor.
2. **No necesitas la DLL del disco.** El `processor` es un **dispatcher de 3 opcodes de R/W de la memoria del propio proceso**. El opcode de **lectura** (`flag=1`) es un `ReadProcessMemory(self, base+counter, …)` — un **leak de memoria arbitraria** (ventana de ~4 GB a partir de la base de la DLL).
3. Con ese leak filtramos la DLL entera de la memoria → `module_dump.bin`. Dentro de ella, justo después de la cadena `FLAG: `, hay un **blob cifrado de 60 bytes** = la flag.
4. La DLL **nunca descifra ese blob** en el flujo del servicio, pero la rutina de decrypt (XOR por palabra con clave embebida de 4 bytes) está en la propia DLL → **se descifra offline**.

### Cadena que cerró
1. `cookie "Ekoparty 2026 - Binary Gecko CTF challenge"` -> banner saludable `"Welcome to this CTF\0"` (20B)
2. `<IBII>(N=0xd, flag=1, counter=0x0, len=0x1000)` -> leak de 4KB a partir de la base de la DLL; repetir con `counter += 0x1000` hasta `0x12000` (la siguiente página no mapeada cierra la conexión)
3. Armar `module_dump.bin` (76 KB) a partir de los leaks encadenados
4. Localizar `"FLAG: "` en file-off `0xd020`; blob cifrado de 60 bytes en `0xd026`
5. Known-plaintext `ct[:4] ^ b"HIK_"` -> clave XOR de 4 bytes `e1 3b ee 03`; descifrar los 60 bytes -> flag

---

## 1. Artefactos

- `chall.exe` / `gecko2026.exe` — host entregado (idénticos), servicio Winsock que carga `gecko2026-module.dll` en runtime.
- `module_dump.bin` (76 KB) — la `gecko2026-module.dll` reconstruida a partir de la memoria vía leak (raw image, base `0x7ffae5040000`).
- `exploit_leak.py` — primitivo de leak (`flag=1`), con guard de banner saludable.
- `exploit_initrun.py`, `exploit_vm.py`, `exploit_flagsweep.py` — intentos de hipótesis antiguas (protocolo útil de referencia; premisas refutadas, ver §4).
- `decrypt_flag.py` — decrypt offline del blob de la flag.
- `NOTES.md` — disassembly y cronología completos de la sesión.

## 2. Entrega / validación

No hay oráculo externo: la flag se obtiene enteramente offline, vía leak de memoria + decrypt local. Formato de la flag: `HIK_GECKO2026_CHALLENGE1_<md5 32 hex>`.

## 3. Análisis

### 3.1 Recon de la superficie
- `:<PORT>` — servicio Winsock crudo, 1 hilo por conexión, **rate-limiter por IP ~60s acumulativo** (cada toque re-arma +60s; usar ≥70s entre conexiones, no martillar).
- `:8080` — `SimpleHTTP` de Python con directory listing, sirve **solo** `gecko2026.exe`. Probado: `gecko2026-module.dll`, `flag`, `.git` etc → 404. La DLL **no** está expuesta.
- `:3389` — RDP (NLA/CredSSP), host `EC2AMAZ-IMAJVSF`, Windows Server 2022 standalone. Sin credencial fundamentada → descartado como vector.
- OSINT: `github.com/Binary-Gecko` tiene sus desafíos 2024/2025 (solo entregan el EXE, sin fuente). El de 2025 es "Escape from the virtual Intel x64 CPU" — **pista falsa** para el 2026 (ver §4).

### 3.2 Protocolo (del disassembly del `chall.exe`)
Por conexión, 2 etapas. Struct pasado al `processor` en `rsp+0x30`, packed `<IBII>` + cuerpo:

| offset | campo | tipo | significado (confirmado) |
|--------|-------|------|--------------------------|
| +0  | `field0` (N) | u32 | tamaño total; `0xd ≤ N ≤ 0x100d`; cuerpo = `N-13` bytes |
| +4  | `flag`       | u8  | opcode del processor (0/1/2) |
| +5  | `counter`    | u32 | offset de memoria a partir de la base de la DLL (zero-extended) |
| +9  | `len`        | u32 | nº de bytes devueltos por el `send` (`len ≤ 0x1000`) |
| +13 | `data[]`     | u8[]| cuerpo de `N-13` bytes (datos para el Write; ignorado en el Read) |

- **Etapa 1 (cookie):** `recv(256)` → `strcmp` contra `Ekoparty 2026 - Binary Gecko CTF challenge` (42 bytes, sin NUL). Si coincide, devuelve un banner de 20 bytes (`Welcome to this CTF\0` cuando el servidor está saludable). El banner oscila: a veces vuelven 20 bytes en cero (servidor inestable) — un resultado de stage2 en esas ventanas es basura. Siempre exigir el banner saludable antes de actuar.
- **Etapa 2 (loop):** manda el header de 13 bytes `<IBII>(N, flag, counter, len)` + cuerpo en el mismo `sendall` (si `N>0xd`, el exe hace UN `recv(N-13)` y exige todo en un solo recv, si no cierra). El `processor` corre; si retorna 1 → `send(data, len)` y vuelve al loop (puedes encadenar varios); si retorna 0 → la conexión muere.

### 3.3 Lo que el `processor` realmente hace (de la DLL reconstruida)
Base real de la imagen de la DLL: `0x7ffae5040000`. Dispatcher en file-off `0x1800`. Lee `flag`; si `≥3` retorna 0 (cierra). Si no llama a `handler_table[flag]`:

| flag | handler (file-off) | acción |
|------|--------------------|------|
| 0 | 0x1620 | one-shot guard (`[0xd064]==1`); escribe una constante en `data[0..3]`. Guard=0 → no-op. |
| **1** | 0x1690 | `ReadProcessMemory(GetCurrentProcess(), base+counter, data[], len)` → **LEAK** |
| **2** | 0x1730 | `WriteProcessMemory(GetCurrentProcess(), base+counter, data[], len)` → **WRITE arbitrario** |
| ≥3 | — | retorna 0 (cierra) |

Dirección efectiva = `base + counter` (counter u32 → alcance ~4 GB por encima de la base); `len ≤ 0x1000`. **Sin** `CreateProcess`/`WaitForDebugEvent`/`SetThreadContext` en ningún lado — no hay VM ni single-step. Es puro R/W del espacio del propio proceso.

### 3.4 Exploit — filtrando la DLL
`flag=1` + `counter`=offset + `len`=0x1000 lee 4 KB de `base+counter`. `counter=0` devuelve el header `MZ` de la propia DLL. Barriendo `counter = 0, 0x1000, 0x2000, …` (el gate queda abierto, encadena decenas de leaks en una conexión) dumpeamos la imagen entera: RVA `0..0x12000` mapeado, `0x13000` ya es página no mapeada (`ReadProcessMemory` falla → retorna 0 → la conexión cierra). Resultado: `module_dump.bin` (76 KB), confirmado PE32+ DLL que exporta `processor`, nombre `gecko2026-module.dll`.

Cómo analizar `module_dump.bin`: es un dump de la imagen virtual, no el PE del disco. Cargar como raw/flat en la base `0x7ffae5040000` (`objdump -D -b binary -mi386:x86-64 --adjust-vma=0x7ffae5040000`, o Ghidra importando como raw x86-64 en esa base). Si dejas que la herramienta parsee los section headers, mapea los VAs mal.

### 3.5 Dónde está la flag
En la `.data` de la DLL, file-off `0xd020`: la cadena ASCII `FLAG: ` seguida de 60 bytes cifrados (file-off `0xd026`):

```
a972a55ca67ead48ae09de31d764ad4ba077a246af7cab32be02d866855fdc65
d30bdc30d05eda66d70fd660835f8a67d45ddc3a840e8a3bd9c411fc
```

Patrón: bytes de índice par altos (`0x83–0xde`, cara de keystream), impares mayoritariamente ASCII.

### 3.6 Solución — decrypt offline del blob
La DLL **no** descifra su propio blob, pero la rutina de decrypt está ahí (clave embebida) — así que se puede reproducir offline, sin ninguna conexión más:

- **Decryptor** = `fcn@0x1160` (VA `0x7ffae5041160`): XOR de palabras de 32 bits del blob (`"FLAG: "+6` = file-off `0xd026`, 60 bytes) contra una clave de 4 bytes en `[0xe368]` (rellenada por `fcn@0x1050`). El caller `fcn@0x1240` hace `add rax,6` para saltar `"FLAG: "` antes del XOR.
- **Clave = `e1 3b ee 03`** (word LE `0x03ee3be1`). Recuperable por known-plaintext: `ct[:4] ^ "HIK_"` (`a9 72 a5 5c ^ 48 49 4b 5f = e1 3b ee 03`). XOR es involutivo → la misma clave descifra los 60 bytes.
- Descifrado: `HIK_GECKO2026_CHALLENGE1_` + 32 hex de MD5; los 3 bytes finales `0xff` son padding.

```python
ct  = open("module_dump.bin","rb").read()[0xd026:0xd026+60]
key = bytes.fromhex("e13bee03")          # = ct[:4] ^ b"HIK_"
flag = bytes(ct[i]^key[i%4] for i in range(60)).rstrip(b"\xff").decode()
# -> HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88
```

> Vías alternativas que también cerrarían (no fueron necesarias): leer la flag en claro en otra región vía el leak (`ReadProcessMemory`, base+counter ~4 GB), o usar la escritura arbitraria (`flag=2`) para code-exec.

### 3.7 Receta rápida

```
cookie  = b"Ekoparty 2026 - Binary Gecko CTF challenge"   # 42B, sin NUL
# stage1: sendall(cookie); recv 20B; EXIGIR == b"Welcome to this CTF\0" (si no, servidor inestable, retry)
# stage2 READ: sendall(struct.pack("<IBII", 0xd, 1, counter, 0x1000))   # flag=1, N=0xd (sin cuerpo)
#   -> recibe 0x1000 bytes de (base+counter). encadena counter=0,0x1000,... para barrer memoria.
# stage2 WRITE: sendall(struct.pack("<IBII", 0xd+len(data), 2, counter, len(data)) + data)  # flag=2
# base de la DLL = 0x7ffae5040000 ; el blob de la flag está en counter=0xd026 (60 bytes).
```

Rate-limiter ~60s/IP acumulativo → 1 conexión por intento, ≥70s de intervalo, no martillar. Cambiar de IP resetea la penalidad.

## 4. Lo que no funcionó

| Hipótesis | Resultado | Por qué |
|---|---|---|
| Leftover de pila / gate `counter==T` | ✗ | No existe gate de token. `counter` es solo offset de memoria. El "banner en cero" que parecía bloquear era solo el servidor oscilando. |
| VM single-step estilo desafío 2025 → escape → FLAG | ✗ | El `processor` 2026 no tiene debuggee ni single-step, y ningún código referencia `FLAG: `/el blob — no hay condición de victoria para disparar. |
| RDP / bajar la DLL del `:8080` | ✗ | Sin credencial fundamentada / DLL no expuesta vía HTTP. |
| XOR trivial en el blob (single-byte, add/sub, XOR-counter, CBC-rolling, split par/impar, XOR contra strings del binario) | ✗ | Nada da `HIK_`; la clave real solo sale por known-plaintext contra el decryptor real de la DLL. |

## 5. Conclusión / próximos pasos

Cerró porque el primitivo de lectura arbitraria (`flag=1`) permite reconstruir la DLL entera sin necesitarla nunca en disco, y la rutina de decrypt embebida (aunque nunca sea llamada por el servicio) es suficiente para reproducir offline el algoritmo y recuperar la clave por known-plaintext (`HIK_` fijo al inicio de la flag).

---

## Apéndice — herramientas

- `exploit_leak.py` — `python3 exploit_leak.py`: leak parametrizable (`flag=1`, counter/len) con guard de banner saludable; usado para barrer la imagen entera de la DLL.
- `decrypt_flag.py` — `python3 decrypt_flag.py`: decrypt offline del blob de la flag en `module_dump.bin` (known-plaintext XOR de 4 bytes).
- `exploit_initrun.py`, `exploit_vm.py`, `exploit_flagsweep.py` — intentos de hipótesis descartadas (gate de token / VM single-step); mantenidos como referencia de protocolo.
