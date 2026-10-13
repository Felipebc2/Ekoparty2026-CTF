<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=First+Chall+by+Binary+Gecko+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

# First Chall by Binary Gecko — PWN · 200 pts · 🟢 EASY

- **Status:** ✅ RESOLVIDO — flag obtida por decrypt offline do blob embarcado na DLL vazada da memória.
- **Flag:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** `nc <IP> <PORT>` (TCP cru, Windows Server 2022 em AWS eu-central-1; restart periódico) / HTTP `<IP>:8080` serve só `gecko2026.exe`
- **Enunciado:** *(não transcrito nas notas da sessão; alvo entrega apenas `chall.exe`/`gecko2026.exe`, a DLL do processor roda só no servidor)*

---

## 0. TL;DR

1. O desafio entrega só um `chall.exe` (= `gecko2026.exe`, servido no HTTP `:8080`). Em runtime ele carrega `gecko2026-module.dll` (função `processor`) que **não é distribuída** e roda só no servidor.
2. **Não precisa da DLL de disco.** O `processor` é um **dispatcher de 3 opcodes de R/W da memória do próprio processo**. O opcode de **leitura** (`flag=1`) é um `ReadProcessMemory(self, base+counter, …)` — um **leak de memória arbitrária** (janela de ~4 GB a partir da base da DLL).
3. Com esse leak vazamos a DLL inteira da memória → `module_dump.bin`. Dentro dela, logo após a string `FLAG: `, há um **blob cifrado de 60 bytes** = a flag.
4. A DLL **nunca decifra esse blob** no fluxo do serviço, mas a rotina de decrypt (XOR por palavra com chave embutida de 4 bytes) está na própria DLL → **decifra-se offline**.

### Cadeia que fechou
1. `cookie "Ekoparty 2026 - Binary Gecko CTF challenge"` -> banner saudável `"Welcome to this CTF\0"` (20B)
2. `<IBII>(N=0xd, flag=1, counter=0x0, len=0x1000)` -> leak de 4KB a partir da base da DLL; repetir com `counter += 0x1000` até `0x12000` (próxima página não-mapeada fecha a conexão)
3. Montar `module_dump.bin` (76 KB) a partir dos leaks encadeados
4. Localizar `"FLAG: "` em file-off `0xd020`; blob cifrado de 60 bytes em `0xd026`
5. Known-plaintext `ct[:4] ^ b"HIK_"` -> chave XOR de 4 bytes `e1 3b ee 03`; decifrar os 60 bytes -> flag

---

## 1. Artefatos

- `chall.exe` / `gecko2026.exe` — host entregue (idênticos), serviço Winsock que carrega `gecko2026-module.dll` em runtime.
- `module_dump.bin` (76 KB) — a `gecko2026-module.dll` reconstruída a partir da memória via leak (raw image, base `0x7ffae5040000`).
- `exploit_leak.py` — primitivo de leak (`flag=1`), com guard de banner saudável.
- `exploit_initrun.py`, `exploit_vm.py`, `exploit_flagsweep.py` — tentativas de hipóteses antigas (protocolo útil de referência; premissas refutadas, ver §4).
- `decrypt_flag.py` — decrypt offline do blob da flag.
- `NOTES.md` — disassembly e cronologia completos da sessão.

## 2. Entrega / validação

Não há oráculo externo: a flag é obtida inteiramente offline, via leak de memória + decrypt local. Formato da flag: `HIK_GECKO2026_CHALLENGE1_<md5 32 hex>`.

## 3. Análise

### 3.1 Recon da superfície
- `:<PORT>` — serviço Winsock cru, 1 thread por conexão, **rate-limiter por IP ~60s acumulativo** (cada toque re-arma +60s; usar ≥70s entre conexões, não martelar).
- `:8080` — `SimpleHTTP` Python com directory listing, serve **só** `gecko2026.exe`. Testado: `gecko2026-module.dll`, `flag`, `.git` etc → 404. A DLL **não** está exposta.
- `:3389` — RDP (NLA/CredSSP), host `EC2AMAZ-IMAJVSF`, Windows Server 2022 standalone. Sem credencial fundamentada → descartado como vetor.
- OSINT: `github.com/Binary-Gecko` tem os desafios 2024/2025 deles (só entregam o EXE, sem fonte). O de 2025 é "Escape from the virtual Intel x64 CPU" — **pista falsa** para o 2026 (ver §4).

### 3.2 Protocolo (do disassembly do `chall.exe`)
Por conexão, 2 estágios. Struct passado ao `processor` em `rsp+0x30`, packed `<IBII>` + corpo:

| offset | campo | tipo | significado (confirmado) |
|--------|-------|------|--------------------------|
| +0  | `field0` (N) | u32 | tamanho total; `0xd ≤ N ≤ 0x100d`; corpo = `N-13` bytes |
| +4  | `flag`       | u8  | opcode do processor (0/1/2) |
| +5  | `counter`    | u32 | offset de memória a partir da base da DLL (zero-extended) |
| +9  | `len`        | u32 | nº de bytes devolvidos pelo `send` (`len ≤ 0x1000`) |
| +13 | `data[]`     | u8[]| corpo de `N-13` bytes (dados pro Write; ignorado no Read) |

- **Stage 1 (cookie):** `recv(256)` → `strcmp` com `Ekoparty 2026 - Binary Gecko CTF challenge` (42 bytes, sem NUL). Se bate, devolve um banner de 20 bytes (`Welcome to this CTF\0` quando o servidor está saudável). O banner oscila: às vezes volta 20 bytes zerados (servidor instável) — resultado de stage2 nessas janelas é lixo. Sempre exigir o banner saudável antes de agir.
- **Stage 2 (loop):** manda header de 13 bytes `<IBII>(N, flag, counter, len)` + corpo no mesmo `sendall` (se `N>0xd`, o exe faz UM `recv(N-13)` e exige tudo num recv só, senão fecha). O `processor` roda; se retorna 1 → `send(data, len)` e volta pro loop (dá pra encadear vários); se retorna 0 → a conexão morre.

### 3.3 O que o `processor` realmente faz (da DLL reconstruída)
Base real da imagem da DLL: `0x7ffae5040000`. Dispatcher em file-off `0x1800`. Lê `flag`; se `≥3` retorna 0 (fecha). Senão chama `handler_table[flag]`:

| flag | handler (file-off) | ação |
|------|--------------------|------|
| 0 | 0x1620 | one-shot guard (`[0xd064]==1`); escreve uma constante em `data[0..3]`. Guard=0 → no-op. |
| **1** | 0x1690 | `ReadProcessMemory(GetCurrentProcess(), base+counter, data[], len)` → **LEAK** |
| **2** | 0x1730 | `WriteProcessMemory(GetCurrentProcess(), base+counter, data[], len)` → **WRITE arbitrário** |
| ≥3 | — | retorna 0 (fecha) |

Endereço efetivo = `base + counter` (counter u32 → alcance ~4 GB acima da base); `len ≤ 0x1000`. **Sem** `CreateProcess`/`WaitForDebugEvent`/`SetThreadContext` em lugar nenhum — não há VM nem single-step. É puro R/W do espaço do próprio processo.

### 3.4 Exploit — vazando a DLL
`flag=1` + `counter`=offset + `len`=0x1000 lê 4 KB de `base+counter`. `counter=0` devolve o header `MZ` da própria DLL. Varrendo `counter = 0, 0x1000, 0x2000, …` (o gate fica aberto, encadeia dezenas de leaks numa conexão) dumpamos a imagem inteira: RVA `0..0x12000` mapeado, `0x13000` já é página não-mapeada (`ReadProcessMemory` falha → retorna 0 → conexão fecha). Resultado: `module_dump.bin` (76 KB), confirmado PE32+ DLL que exporta `processor`, nome `gecko2026-module.dll`.

Como analisar `module_dump.bin`: é um dump da imagem virtual, não o PE de disco. Carregar como raw/flat na base `0x7ffae5040000` (`objdump -D -b binary -mi386:x86-64 --adjust-vma=0x7ffae5040000`, ou Ghidra importando como raw x86-64 nessa base). Se deixar a ferramenta parsear os section headers, ela mapeia os VAs errado.

### 3.5 Onde está a flag
Na `.data` da DLL, file-off `0xd020`: a string ASCII `FLAG: ` seguida de 60 bytes cifrados (file-off `0xd026`):

```
a972a55ca67ead48ae09de31d764ad4ba077a246af7cab32be02d866855fdc65
d30bdc30d05eda66d70fd660835f8a67d45ddc3a840e8a3bd9c411fc
```

Padrão: bytes de índice par altos (`0x83–0xde`, cara de keystream), ímpares majoritariamente ASCII.

### 3.6 Solução — decrypt offline do blob
A DLL **não** decifra o próprio blob, mas a rotina de decrypt está lá (chave embutida) — então dá pra reproduzir offline, sem nenhuma conexão a mais:

- **Decryptor** = `fcn@0x1160` (VA `0x7ffae5041160`): XOR de palavras de 32 bits do blob (`"FLAG: "+6` = file-off `0xd026`, 60 bytes) contra uma chave de 4 bytes em `[0xe368]` (preenchida por `fcn@0x1050`). O caller `fcn@0x1240` faz `add rax,6` pra pular `"FLAG: "` antes do XOR.
- **Chave = `e1 3b ee 03`** (word LE `0x03ee3be1`). Recuperável por known-plaintext: `ct[:4] ^ "HIK_"` (`a9 72 a5 5c ^ 48 49 4b 5f = e1 3b ee 03`). XOR é involutivo → a mesma chave decifra os 60 bytes.
- Decifrado: `HIK_GECKO2026_CHALLENGE1_` + 32 hex de MD5; os 3 bytes finais `0xff` são padding.

```python
ct  = open("module_dump.bin","rb").read()[0xd026:0xd026+60]
key = bytes.fromhex("e13bee03")          # = ct[:4] ^ b"HIK_"
flag = bytes(ct[i]^key[i%4] for i in range(60)).rstrip(b"\xff").decode()
# -> HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88
```

> Vias alternativas que também fechariam (não precisaram): ler a flag em claro noutra região via o leak (`ReadProcessMemory`, base+counter ~4 GB), ou usar a escrita arbitrária (`flag=2`) pra code-exec.

### 3.7 Receita rápida

```
cookie  = b"Ekoparty 2026 - Binary Gecko CTF challenge"   # 42B, sem NUL
# stage1: sendall(cookie); recv 20B; EXIGIR == b"Welcome to this CTF\0" (senão servidor instável, retry)
# stage2 READ: sendall(struct.pack("<IBII", 0xd, 1, counter, 0x1000))   # flag=1, N=0xd (sem corpo)
#   -> recebe 0x1000 bytes de (base+counter). encadeia counter=0,0x1000,... pra varrer memória.
# stage2 WRITE: sendall(struct.pack("<IBII", 0xd+len(data), 2, counter, len(data)) + data)  # flag=2
# base da DLL = 0x7ffae5040000 ; o blob da flag está em counter=0xd026 (60 bytes).
```

Rate-limiter ~60s/IP acumulativo → 1 conexão por tentativa, ≥70s de intervalo, não martelar. Trocar de IP zera a penalidade.

## 4. O que não funcionou

| Hipótese | Resultado | Por quê |
|---|---|---|
| Leftover de pilha / gate `counter==T` | ✗ | Não existe gate de token. `counter` é só offset de memória. O "banner zerado" que parecia bloquear era só o servidor oscilando. |
| VM single-step estilo desafio 2025 → escape → FLAG | ✗ | O `processor` 2026 não tem debuggee nem single-step, e nenhum código referencia `FLAG: `/o blob — não há condição de vitória a disparar. |
| RDP / baixar a DLL do `:8080` | ✗ | Sem credencial fundamentada / DLL não exposta via HTTP. |
| XOR trivial no blob (single-byte, add/sub, XOR-counter, CBC-rolling, split par/ímpar, XOR contra strings do binário) | ✗ | Nada dá `HIK_`; a chave real só sai por known-plaintext contra o decryptor real da DLL. |

## 5. Conclusão / próximos passos

Fechou porque o primitivo de leitura arbitrária (`flag=1`) permite reconstruir a DLL inteira sem nunca precisar dela em disco, e a rotina de decrypt embutida (mesmo nunca chamada pelo serviço) é suficiente para reproduzir offline o algoritmo e recuperar a chave por known-plaintext (`HIK_` fixo no início da flag).

---

## Apêndice — ferramentas

- `exploit_leak.py` — `python3 exploit_leak.py`: leak parametrizável (`flag=1`, counter/len) com guard de banner saudável; usado para varrer a imagem da DLL inteira.
- `decrypt_flag.py` — `python3 decrypt_flag.py`: decrypt offline do blob da flag em `module_dump.bin` (known-plaintext XOR de 4 bytes).
- `exploit_initrun.py`, `exploit_vm.py`, `exploit_flagsweep.py` — tentativas de hipóteses descartadas (gate de token / VM single-step); mantidos como referência de protocolo.
