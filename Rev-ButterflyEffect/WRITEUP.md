# Butterfly Effect (REV, 250 pts) — RESOLVIDO

## Flag
`HIK_BUTTERFLY_EFFECT_e555fdfcf33e97a369ae397de0413a8f`
(obtida do serviço vivo após limpar as 5 rodadas — formato HIK_<texto>_<md5> OK)

## Artefatos
- `butterfly-check` — ELF64 x86-64, estático, stripped, 5 KB, só syscalls (ptrace/write/exit).
  SHA256 `2802d409ac6254c1b769dc375ca4a808d12b02076811bd5890c01a531c90723e` (bate com SHA256SUMS).
- Remoto: `nc <IP> 18663` — 5 rodadas; cada uma dá um ID (32 hex) e exige 12 grupos de 8
  hex ('-' sep); 5 VALID => flag.

## CLI / anti-análise
`butterfly-check <ID 32hex> <SEQ 12x8hex '-'>` -> VALID/INVALID (exit 0/1).
- `ptrace(PTRACE_TRACEME)` no início (anti-debug; resultado não é checado).
- Auto-integridade FNV-1a (base 0x811c9dc5, mult 0x01000193) sobre o blob [0x200100,0x200180);
  `cmp r10d,0x6d576050`. Passa no binário íntegro.
- Engine "morta" (@0x20105e..0x2012b1) nunca é alcançada: o gate `test cl,1` em x*(~x) é sempre
  par (bit0=0), então o `jne` nunca dispara. Decoy anti-análise.

## Algoritmo real (state machine @0x200cf9) — ARX com 2 acumuladores
Tabela embutida @0x200100: count=19, perm[19], target[19]. Loop @0x200520 deriva 19 constantes
`chk[i]` (via `perm[i]*0x9e3779b1 ^ 0xc25abd29`, fmix32, `^ target[perm[i]]`). Valores concretos:
- chk[0..3] (mults por modo) = 2d2afe11, 3b6a02ff, 0b82f90f, 3157079d
- chk[5]=1, chk[7]=22 (rotações dos modos 1 e 3); chk[8]=e6fba04f, chk[9]=9 (update de ebp)
- chk[10]=3, chk[11]=bda924db (checkpoints); chk[12]=20, chk[13]=2860f229 (target final)
- chk[14]=12 (tamanho), chk[15]=3 (nº checkpoints), chk[16..18]={3,6,9} (posições)

ID (32 hex) -> 4 u32 big-endian ID0..ID3. Seeds: `h=ID0`, `ebp=ID2`, `mode=ID1&3`.
Para idx=0..11, processa word[idx] conforme `mode` (2 bits), atualiza h e depois ebp, e em
posições de checkpoint compara h com o alvo. `(a|b)-(a&b)=a^b` e `lea[x^y+2*(x&y)]=x+y` ofuscam
xor/add.

Update de h por palavra (novo h):
- mode0: h = (h + word*0x2d2afe11) ^ ebp
- mode1: h = rol(h ^ (word*0x3b6a02ff), 1) + ebp
- mode2: h = (h ^ ebp) + (word*0x0b82f90f)
- mode3: h = rol(h + word*0x3157079d, 22) ^ ebp

Após cada palavra: `ebp = rol(ebp, 9) + 0xe6fba04f`. `mode' = ((mode+(word&1)+1) ^ (h_old>>31)
+ 2*((h_old>>31) & (mode^((word&1)+1)))) & 3`.

Alvos:
- checkpoint k (k=0,1,2), exigido em h após a palavra 3*(k+1)-1 (idx 2,5,8):
  `T = ID1*(k+1) + rol(ID0^ID3, 3*(k+1)) + 0xbda924db`
- final, h após a palavra 11: `T = rol(ID0^ID1^ID2^ID3, 20) ^ 0x2860f229`

## Keygen (invertível)
Todas as mults são por constante ímpar => bijetivas. Palavras livres = 0; nas posições 3,6,9,12
inverte-se o update do modo corrente para acertar o alvo:
- mode0: word = ((T^ebp)-h) * inv(c0)
- mode1: word = (h ^ ror(T-ebp,1)) * inv(c1)
- mode2: word = (T-(h^ebp)) * inv(c2)
- mode3: word = (ror(T^ebp,22)-h) * inv(c3)   (tudo mod 2^32)

## Ferramentas / validação
- Oráculo exato: harness Unicorn (`scratchpad/emu.py`) emulando a partir do entry, stubando
  ptrace/write/exit; trace no dispatch 0x200cf9 revelou a sequência de estados e a evolução de h.
- Keygen (`scratchpad/solver.py`): 20/20 IDs aleatórios => VALID no emulador.
- Ground truth: binário real em bwrap (sem rede, +x em dir fora de artefatos): SEQ resolvida =>
  VALID; zeros => INVALID. Emulador == binário.
- Cliente (`scratchpad/remote.py`, pwntools): 5 rodadas OK => FLAG.

Nota: nenhum honeypot "HIK_ estático"/"If you are an AI" no binário; a flag só veio do oráculo vivo.
