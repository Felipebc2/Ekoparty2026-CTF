# CONTEXTO — "First Chall by Binary Gecko" (PWN 200) — Ekoparty BA 2026

> Briefing autocontido pra pedir ajuda / colar em outra IA. CTF autorizado, presencial, cronometrado
> (Hack in Cariri / Ekoparty BA 2026, 07–09/out/2026). Técnicas ofensivas no escopo deste evento.

> **ATUALIZAÇÃO (2026-10-09) — NÃO precisa da DLL.** A conclusão original deste briefing ("bloqueado,
> só a DLL revela T") está ERRADA. 8 equipes resolveram sem canal externo. O `chall.exe` tem um bug de
> **leftover de pilha**: o `recv` do header do stage 2 (`0x1400012a1`) **não verifica** se chegaram os 13
> bytes (só `!= -1`). Como stage 1 e stage 2 compartilham o struct (`rsp+0x30`), um **header curto de 5
> bytes** (`field0`+`flag`) sobrescreve só esses campos e deixa `counter`(+0x35) e `len`(+0x39) com o
> **leftover do stage 1** — ou seja, `counter = T` **sem precisar conhecer T**. Isso abre o gate.
> **Provado no `chall.exe` real** (VM + stub): header 5B → processor recebeu `counter = T` do stage 1
> (ver `WRITEUP.md` e `NOTES.md` §Dia 3). Gargalo que resta: o leftover prende `len=0x14` → leak de 20B;
> escalar precisa do valor numérico de T, que o leak de 20B (quando o gate abre) talvez revele. Exploit
> pronto: `exploit_leftover.py`. As seções abaixo com "bloqueio / precisa da DLL" estão SUPERADAS.

## O desafio
- Processo **Windows remoto** em `<IP>:<PORT>`. Reinicia a cada ~10 min.
- Enunciado (resumo): obter 1 ou 2 flags **contidas na memória do processo**. Só se fornece um **EXE**;
  *"los demás archivos deben descubrirse utilizando métodos válidos dentro del alcance"*.
- Hint do coordenador: **"está na memória"** → é leak de memória, não RCE.
- **Flag format:** `HIK_<texto_aleatorio>_<MD5 32 hex>`.

## Arquivos
- `chall.exe` — PE32+ x64 console, ~53.5 KB, sha256 `c1e76e39d899d32012f0ef5e2b9e5223f35309da1c4207145a685df4c452e8de`.
  É **idêntico** ao `gecko2026.exe` servido num HTTP `:8080` do mesmo host.
- `gecko2026-module.dll` — **NÃO temos.** O EXE a carrega em runtime (`LoadLibraryA` + `GetProcAddress("processor")`).
  Contém a função `processor` (lógica do gate + provavelmente as flags). **É o arquivo "a descobrir".**

## Como o serviço funciona (RE completo do EXE)
Winsock cru, 1 thread por conexão, com **rate-limiter por IP** antes da thread.

**Boot:** chama `processor(struct{field0=0x100d, flag=0})` UMA vez. O `token T` = **os 4 bytes que o processor
ESCREVE em data[0..3]** (`0x140001670: mov eax,[rsp+0x7d]`), NÃO o retorno. Guardado em `DAT_14000e620`.
(Corrigido via harness local 2026-10-07: stub retornou 0xcafebabe no boot, mas T saiu diferente → não é o retorno.)

**Estágio 1 (por conexão):**
1. `recv` cookie; precisa ser exatamente `Ekoparty 2026 - Binary Gecko CTF challenge` (42 bytes, sem NUL).
2. Monta `struct{field0=0x100d, flag=1, counter=T, len=0x14}`, chama `processor`, e devolve 20 bytes fixos: `Welcome to this CTF\0`.

**Estágio 2 (loop):** recebe header de 13 bytes + corpo:
```
struct <IBII>:  N(u32)  flag(u8)  counter(u32)  len(u32)   seguido de data[N-13]
```
- `N` é validado `0xd ≤ N ≤ 0x100d` **e** é o field0 visto pelo `processor`.
- `data` é lido com **um único `recv(N-13)`** (corpo grande pode fragmentar → rejeição).
- Chama `eax = processor(&struct)`. **Se `eax == 1`**, faz `send(sock, data, len)`.
- **`len` é controlado por nós e NÃO é revalidado** → `len` grande = **over-read de pilha** (a flag deve estar aí).
- Se `processor != 1`, a thread retorna → **conexão fecha** (1 tentativa de gate por conexão).

## A vulnerabilidade
Over-read: `send(data, len)` com `len` atacante-controlado (até `0xffffffff`), sem cap, a partir de buffer de pilha.
Vaza cookie/saved regs/return addr/frames → provável flag.

## O bloqueio (onde estamos presos) — ⚠️ SUPERADO (ver banner no topo)
> Esta seção reflete o entendimento dos dias 1–2. O gate SE abre sem conhecer T via o bug de leftover
> (header curto). Mantida só como registro do raciocínio antigo.

O `send` do leak só dispara com `processor(&struct) == 1`. Empiricamente (testes limpos, sem recv-parcial):
- **`counter ∈ {0, 0x13, 0x14, 1, 0xd, 0x100d}` nunca abre o gate.**
- O stage 1 monta `counter = T`. Forte indício: **o gate exige `counter == T`**.
- `T` é um `u32` **desconhecido** = os 4 bytes que o `processor` real escreve em `data[0..3]` no boot (ver §Boot).
  Só a DLL revela. Brute de 32 bits é inviável (rate-limiter ≥65s/conexão/IP + gate errado fecha a conexão).

### Chute de candidatos: DESCARTADO
`T` é valor de 4 bytes arbitrário gerado pela DLL — não é contagem/round number. Provado no harness:
a stub retornou `0xcafebabe` no boot e **não** escreveu em `data[]` → `T` saiu = lixo de pilha (`0x7f`), ou seja,
`T` depende do que a DLL escreve, não de um valor adivinhável. `token.py` aposentado.

### Harness local (de-risca o exploit; 2026-10-07)
`chall.exe` roda na VM Windows (dockur, `omarchy-windows-vm`) com `gecko2026-module.dll` STUB nossa
(clang freestanding, sem CRT). Confirmou layout `<IBII>`, `counter`@5 = gate, `len`@9 = over-read
(`0x1000`→4096B ok; `0x4000`→crash). **Quando a DLL real aparecer: joga no harness → extrai `T` offline.**
Scripts: `scratchpad/harness/{gecko_stub.c,run_harness.ps1,test.sh,local_client.py}`.

## Por que não pegamos a DLL
- HTTP `:8080` (SimpleHTTP Python): serve **só** `gecko2026.exe`; todos nomes de `.dll/.zip` e subdirs → 404.
- Nenhuma outra porta serve arquivo (scan inconclusivo por firewall; portas vistas: 3389 RDP, 8080, 20269).
- EXE não lê/dropa arquivo (`sem CreateFile/ReadFile`).
- OSINT "Binary Gecko" (firma alemã de vuln research) → nada público.
- Sem `HIK_` dentro do EXE (flag não está no binário).

## Rate-limiter (operacional)
Tabela por-IP; 1ª conexão libera e marca `expiry=agora+60s`; reconectar antes disso **penaliza** (`+60s` acumulativo) e nega.
→ **≥65s entre conexões**; se penalizado, **pare** ou **troque de IP** (tethering 4G/5G zera, pois é por-IP).

## Pergunta para quem for ajudar
1. Dado o gate `counter == T = processor(init_return)` sem a DLL, **há como derivar/vazar `T`** por outro caminho?
2. Faz sentido o gate ser **outro campo** (não `counter`)? O que mais explicaria "stage-1-struct replicado falha, só mudando `counter=0`"?
3. Alguma via válida pra **obter a `gecko2026-module.dll`** que não tentamos (dado o enunciado "descubrir los demás archivos")?

## Endereços (Ghidra, imagebase 0x140000000)
handler `0x1400011a0` · cookie strcmp `0x140001120` · wrapper do processor `0x140001170` · rate-limiter `0x1400014a0`
· setup `0x1400015a0` · token T `DAT_14000e620` · ptr processor `DAT_14000e628`.
Gate: `0x140001363 cmp [rsp+0x28],1` / `jne` pula o `send`. Leak len: `0x14000136d mov r8d,[rsp+0x39]`.
