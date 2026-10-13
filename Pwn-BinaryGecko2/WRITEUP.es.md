<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Second+Chall+by+Binary+Gecko+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Second Chall by Binary Gecko — PWN · 400 pts · 🟡 MEDIUM

- **Status:** 🟡 ABIERTO — Flag 1 obtenida offline (probablemente reutilizada del chall 1); Flag 2 tiene un vector WPM diseñado y revisado, listo para ejecutar, pero no ejecutado.
- **Flag:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88` (Flag 1; Flag 2 = —)
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `nc <IP> <PORT>` — proceso Windows, *low integrity*, reiniciado por un watcher externo cada ~10 min.
- **Enunciado:** *"Un proceso remoto de Windows, ejecutado con nivel de integridad bajo... Obtén una o ambas flags contenidas en la memoria del proceso, mediante fuga de datos y/o compromiso del proceso."*

---

## 0. TL;DR

1. El host (`gecko2026.exe`) y su DLL son byte a byte idénticos a los del "First Chall by Binary Gecko" — el protocolo y el primitivo de leak/write (`flag=1`/`flag=2`, `ReadProcessMemory`/`WriteProcessMemory` en `base_DLL+counter`) entraron gratis.
2. **Flag 1** sale por el mismo camino que el chall 1: leak de la DLL entera + decrypt offline del blob cifrado embebido.
3. El enunciado pide "una o ambas" flags, "mediante fuga de datos y/o compromiso del proceso" — lo que sugiere que la **Flag 2 exige comprometer el proceso** (write), ya que la lectura pura no alcanza ninguna región nueva.
4. **Flag 2** diseñada vía `WriteProcessMemory` (`flag=2`) para parchear un handler muerto (`flag=0`) de la propia DLL con shellcode que hace un PEB-walk y lee el EXE host (región nunca alcanzable solo por lectura) — vector listo, no ejecutado en esta sesión.

### Cadena que cerró (Flag 1)
1. Leak completo de la imagen de la DLL vía `flag=1` (`sweep2.py`) -> `module_dump_chall2.bin`
2. Diff byte a byte contra el dump del chall 1: código 100% idéntico; solo cambian el blob cifrado, la clave XOR embebida y los punteros ASLR
3. Known-plaintext (`ct[:4] ^ b"HIK_"`) -> clave XOR de 4 bytes -> decrypt del blob de 60 bytes
4. `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`

### Cadena diseñada, no ejecutada (Flag 2)
1. `<IBII>(N, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin` -> sobrescribe el slot muerto del handler `flag=0`
2. `<IBII>(N, flag=0, counter=OFF, len=0x1000)` barriendo `OFF = 0, 0x1000, ...` sobre el EXE host, misma conexión
3. Buscar `HIK_`/`FLAG:` en cada respuesta

---

## 1. Artefactos

- `gecko2026.exe` — host entregado, byte a byte idéntico al del chall 1.
- `module_dump_chall2.bin` (76 KB) — dump raw de la imagen de la DLL de este chall, vía `sweep2.py` (`flag=1`).
- `exe_live_dump.bin`, `heap_live_dump.bin`, `peb_dump.bin` — dumps auxiliares en vivo (EXE/heap/PEB).
- `wpm_shellcode.bin` (82B), `sc_absread.bin`, `sc_peb.bin`, `sc_stackscan.bin` — shellcodes ensamblados/verificados con objdump.
- `WPM_PLAN.md` — anexo técnico detallado del vector WPM (hechos vs hipótesis, shellcode fuente+hex).
- Scripts: `chase_e370.py`, `exploit_v2.py`, `exploit_wpm.py`, `final_scan.py`, `leak2.py`, `rpm_extended.py`, `scan_all.py`, `scan_base.py`, `scan_env.py`, `sweep2.py`.

## 2. Entrega / validación

No hay oráculo externo descrito; ambas flags tienen el formato `HIK_<texto>_<md5 32 hex>` y se obtienen leyendo/escribiendo directamente la memoria del proceso (ningún endpoint de envío en las notas de esta sesión).

## 3. Análisis

### 3.1 Protocolo (recap del chall 1 — mismo binario)
1. El cliente conecta y manda el cookie: `b"Ekoparty 2026 - Binary Gecko CTF challenge"`.
2. El servidor responde el banner de salud: `b"Welcome to this CTF\x00"` (20B). El host oscila sano/degradado y tiene rate-limit por IP (~65-75s) — si el banner viene todo-cero, cierra y reintenta después del cooldown.
3. Luego, cada solicitud es un header `struct <IBII>` = `N(u32), flag(u8), counter(u32), len(u32)` seguido de `data[]`:
   - `flag=1` → `ReadProcessMemory(self, base_DLL + counter, &resp, len)` — leak por offset.
   - `flag=2` → `WriteProcessMemory(self, base_DLL + counter, data, len)` — write arbitrario.
   - `counter` es u32, forward-only desde la base de la DLL; `len ≤ 0x1000`.
4. La base de la DLL (ASLR, page-aligned `...0000`) es recuperable en runtime: hay un self-ptr en `base+0xd068` que apunta a la string `"FLAG:"` en `base+0xd020` → `base = (ptr@0xd068) - 0xd020`.

### 3.2 Flag 1 — decrypt offline del blob de la DLL
`module_dump_chall2.bin` es el dump raw de la imagen de la DLL (`0x0..0x13000`), recolectado vía `sweep2.py` (`flag=1`, barriendo offset por offset). Diff byte a byte contra el dump del chall 1: código 100% idéntico; solo cambian el blob cifrado (`0xd026..0xd060`), la clave XOR de 4B embebida (`0xe368`) y los punteros ASLR.

La DLL carga la flag cifrada y tiene el decryptor embebido, pero nunca se llama en el flujo normal — así que el decrypt se hace manualmente, con known-plaintext (el texto empieza con `HIK_`):

```python
d  = open("module_dump_chall2.bin","rb").read()
ct = d[0xd026:0xd026+60]
key = bytes(c ^ p for c, p in zip(ct[:4], b"HIK_"))     # clave de 4B (XOR es involutivo)
flag = bytes(ct[i] ^ key[i % 4] for i in range(60))
# -> HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88
```

**Flag 1:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`

⚠️ **Salvedad:** el texto es `GECKO2026_CHALLENGE1` y el MD5 salió idéntico al del chall 1 — es la misma flag reutilizada (host idéntico, solo cambia la seed por boot, pero el plaintext es el mismo). Según el enunciado ("una o ambas"), cuenta como una de las dos, pero probablemente no es la flag exclusiva del chall 2. No confirmado en la plataforma si ya puntuó; de ser así, lo que vale es la Flag 2.

### 3.3 Flag 2 — por qué la lectura pura no la alcanza
Mapeo de lo que el primitivo `flag=1` puede tocar (lee `base_DLL + counter`, `counter` u32 forward-only):

| Región | ¿Alcanzable por `flag=1`? |
|---|---|
| Imagen de la DLL (`0..0x13000`) | ✅ ya dumpeada — solo tiene la Flag 1 |
| Página justo después (`0x13000`) | ❌ no-mapeada (confirmado en vivo) |
| Heap / stack / EXE host | ❌ quedan debajo de la base de la DLL (`0x7ffa...`); counter solo avanza hacia adelante |
| Otras DLLs | técnicamente adelante, pero es código de lib + las direcciones cambian por ASLR en cada boot |

Barrido de los 3237 punteros del dump: 3019 apuntan debajo de la base (heap/EXE — inalcanzables) y los 68 alcanzables hacia adelante son todos IAT→DLL vecina. Ninguno lleva a la Flag 2. Conclusión: la Flag 2 no sale por lectura — concuerda con el enunciado (*low integrity* + *compromiso del proceso*): necesita `WriteProcessMemory`.

### 3.4 Flag 2 — vector de compromiso (WPM / `flag=2`)
**Idea:** la escritura `flag=2` también es `base_DLL + counter` forward, y un `counter` pequeño (`0..0x13000`) cae dentro de la imagen RX de la propia DLL. `WriteProcessMemory` ignora la protección de página → se puede parchear el `.text` de la DLL. Plan: plantar shellcode y ejecutarlo abusando de un handler muerto.

Hechos (confirmados por disassembly estático de `gecko2026.exe` + dump):
- **Dispatch table** en `base+0xe340`: 3 handlers — `0x1620`(flag0), `0x1690`(flag1/RPM), `0x1730`(flag2/WPM). El byte `flag` indexa la tabla.
- **`flag=0` es dead code post-boot:** es un guard *one-shot* (`if DAT_e36c==1 {...; DAT_e36c=0}`) consumido en el startup por el propio EXE. Después, no-op. El slot `base+0x1620..0x1690` (112B, incluye padding `0xCC`) es seguro de sobrescribir sin tocar los handlers de RPM/WPM que usan los otros equipos.
- Offsets fijos relativos a la base: RPM IAT `0xa028`, dispatch table `0xe340`, slot `0x1620`.

**Shellcode (82B — `wpm_shellcode.bin`, ensamblado y verificado con objdump):** hace un PEB-walk hasta el primer módulo cargado (= el EXE host), suma `counter`, y llama al `ReadProcessMemory` real (vía IAT) para leer `exe_base + counter` en el buffer de respuesta. Una vez plantado, `flag=0` pasa a ser un "RPM desde el EXE" — exactamente la región que el leak original (base de la DLL) nunca cubrió.

```asm
sub rsp, 0x38
mov r11, rcx              ; rcx = &hdr (struct <IBII>+data en la pila del handler)
mov edx, [r11+5]          ; edx = hdr.counter
mov rax, [gs:0x30]        ; TEB
mov rax, [rax+0x60]       ; PEB
mov rax, [rax+0x18]       ; PEB_LDR_DATA
mov rax, [rax+0x10]       ; InLoadOrderModuleList.Flink -> 1a entry (= EXE)
mov rax, [rax+0x30]       ; DllBase del EXE
add rax, rdx              ; exe_base + counter
mov rdx, rax              ; lpBaseAddress
lea r8,  [r11+0xd]        ; lpBuffer = hdr.data (buffer que el EXE devuelve)
mov r9d, [r11+9]          ; nSize = hdr.len
mov rcx, -1               ; hProcess = pseudo-handle (proceso actual)
mov qword [rsp+0x20], 0   ; lpNumberOfBytesRead = NULL
call qword [rip+0x89c0]   ; = call [base+0xa028] = *ReadProcessMemory  (solo vale si plantado en 0x1620)
mov eax, 1                ; siempre reporta éxito -> mantiene la conexión viva para encadenar el sweep
add rsp, 0x38
ret
```

> `call [rip+0x89c0]` solo resuelve a `base+0xa028` **si** se planta en `base+0x1620`. En otro offset: `disp = 0xa028 - (destino + 0x48)`.

**Plan de ejecución (1 conexión):**
1. Cookie → exigir banner sano (retry si degradado).
2. **PATCH:** `<IBII>(N, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin` → sobrescribe el slot muerto.
3. **TRIGGER + SWEEP** (misma conexión): varios `<IBII>(N, flag=0, counter=OFF, len=0x1000)` con `OFF = 0, 0x1000, 0x2000, ...` barriendo el EXE hacia adelante; buscar `HIK_`/`FLAG:` en cada respuesta.
4. Si no hay nada en unos MB → parar (no escalar solo a un shellcode v2 con heap-walk sin un nuevo OK).

### 3.5 Riesgos (proceso compartido)
- El patch cambia el comportamiento de `flag=0` para todos los equipos hasta el restart (~10 min). No crashea (RPM falla "limpio", el shellcode siempre retorna 1), pero es una alteración visible del protocolo.
- La premisa "`flag=0` es dead code" es de una lectura puntual, no exhaustiva → riesgo bajo, no cero.
- Sin deshacer por la red — solo el restart de 10 min restaura el binario.
- 1 conexión cubre patch+sweep; si el patch falla, la conexión cae y espera el cooldown (~65-75s).

## 4. Lo que no funcionó

| Hipótesis | Resultado | Por qué |
|---|---|---|
| Alcanzar la Flag 2 solo con lectura (`flag=1`) | ✗ | Todos los punteros alcanzables forward llevan solo a código de DLL vecina (IAT); heap/stack/EXE quedan debajo de la base y `counter` solo avanza hacia adelante. |

## 5. Conclusión / próximos pasos

La Flag 1 cerró por leak+decrypt offline (mismo mecanismo que el chall 1, posiblemente flag reutilizada). La Flag 2 quedó trabada: el vector de `WriteProcessMemory` para parchear el handler muerto (`flag=0`) y usarlo como lector del EXE host está **totalmente diseñado, revisado y con shellcode ensamblado y verificado**, pero no fue ejecutado en esta sesión (riesgo de afectar el proceso compartido entre equipos sin confirmación final). Próximo paso: ejecutar el plan de la §3.4 en una única conexión (patch + trigger + sweep) y, si no aparece nada en unos MB del EXE, parar — no escalar a un shellcode v2 con heap-walk sin validación adicional.

---

## Apéndice — herramientas

- `sweep2.py` — leak completo de la imagen de la DLL (`flag=1`), generó `module_dump_chall2.bin`.
- `rpm_extended.py` — leak extendido `flag=1` (read-only); probó que `0x13000+` es no-mapeado.
- `exploit_wpm.py` — script de disparo del vector WPM (patch del slot `flag=0` + sweep del EXE).
- `chase_e370.py`, `final_scan.py`, `leak2.py`, `scan_all.py`, `scan_base.py`, `scan_env.py`, `exploit_v2.py` — scripts auxiliares de reconocimiento/scan de memoria usados a lo largo de la sesión.
