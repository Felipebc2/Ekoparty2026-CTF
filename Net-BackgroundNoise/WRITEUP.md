# NET — "Background Noise" (packet / ICMP covert channel) — EM ABERTO

**Status:** não resolvido (budget estourado dia 2, 2026-10-09). **Flag:** —
**Acesso:** `nc <IP> 16009` — 700 pts (HARD).
*"The message is not where a normal protocol would put it. Recover what left."*

## Família PACKET (harness confirmado nesta porta)
- Banner: `Background Noise - 700 pts / session 120s / sid <32hex>`.
- Cmds: `help | capture [sec] | getpcap | tcpdump <args> | submit <proof> | quit`.
- `getpcap` → `--- BEGIN PCAP --- <base64> --- END PCAP ---`.
- **proof = `sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))`** (hash do TEXTO
  base64 sem whitespace; confirmado pelo próprio `help`).
- Tudo na MESMA conexão TCP (reconectar zera sid+pcap).
- **submit DÁ feedback real:** resposta `incorrect.` para proof errado (≠ Helpdesk). Logo dá pra
  iterar/validar quando a `answer` certa for conhecida.

## Estrutura do pcap (100% mapeada, linktype=1 Ethernet, MACs = 00:00:00:00:00:00 → pcap sintético)
Só IPv4/ICMP. Tráfego = echo request/reply entre **10.13.9.17 (pinger) ↔ 10.13.9.9 (server)**.
- Em 45s: 1602 pacotes = 801 echo request (type 8) + 801 echo reply (type 0), pareados 1:1.
- Organizado em "rounds" (~2s de gap entre eles). Cada round = **sweep de ping fixo**:
  - Grupo A: `icmp.seq` 0..47 (48 pacotes)
  - Grupo B: `icmp.seq` 1000..1095 (96 pacotes)
  - (ranges IDÊNTICOS em todo round — estrutura fixa, não carrega dado)
- ICMP identifier = **412 (0x019c) constante** em todos os 1602 pacotes.
- Frame = 43 bytes (14 eth + 20 ip + 9 icmp = 8 hdr + **1 byte de data**). TTL=64, TOS=0,
  code=0, DF set nos requests. Tudo constante.

## O que foi DESCARTADO (confiável — ver scripts em scratchpad/bn_*.py)
Cada campo cai em 1 de 3 baldes: **constante**, **contador +1 limpo (decoy)**, ou **ruído
uniforme que MUDA a cada round (decoy)**. Nenhum carrega mensagem estável.
- **Payload (1 byte/pkt):** request==reply (echo RFC, 0 diferenças). Random. XOR com sid
  (hex/ascii), sha256(sid), md5(sid), single-byte 0..255, por grupo/round → sem `HIK`.
- **req ip.id:** contador +1 global perfeito (10026,10027,…) atravessando rounds. Decoy "normal".
- **reply ip.id ("background noise"):** contador monotônico com **delta uniforme 1..41** (sem o
  reset de round). Deltas DIFEREM a cada round → ruído genuíno, não repetição de mensagem.
  Testado: delta&0xff, delta%95+32, bit-planes (LSB/parity/median-split, msb/lsb, 8 offsets),
  ip.id mod128, low byte, por grupo A/B → sem `HIK` nem ASCII.
- **icmp.seq:** contador estruturado (0-47,1000-1095) idêntico por round.
- **icmp.ident:** 412 constante. **ttl/tos/code/verihl/flags/fragoff/totlen:** constantes.
- **Ethernet MAC:** 00..00. **Checksums IP/ICMP:** corretos/derivados (tshark: "Good").
- **Timing:** inter-pacote ~40ms + jitter 200-600us unimodal = ruído; splits binários
  (>40.5ms,>41ms) não deram ASCII. Timestamps us do pcap (lo byte, %95+32, %128) → ruído.
- tshark `-z expert`: nenhum malformed; só `eth:ethertype:ip:icmp:data`.

## Honeypots / armadilhas
- O **payload** é exatamente "onde um protocolo normal poria o dado" → o enunciado diz que NÃO
  está lá. Confirmado random/decoy (igual LongCall/LookupDesk/Night Shift da família).
- reply ip.id parece canal encoberto clássico, mas os deltas são ruído uniforme por design
  ("Background Noise").

## Por que travou / próximos passos manuais
A `answer` do oráculo é uma **string específica** que não consegui determinar. Testados e
REJEITADOS no submit vivo (feedback `incorrect.`): `10.13.9.17`, `10.13.9.9`, ambos combinados
com `:`, `412`, `0x19c`, `ip.id`, `ipid`, `ip_id`, `ip id`, `identifier`, `icmp`, `icmp.ident`,
`icmp.seq`, `ttl`, `sequence`, `1000`, `47`, `48`, `96`.

Hipóteses abertas para destravar (em ordem):
1. **Campo invariante = portador.** Como os campos variáveis mudam todo round, a mensagem só pode
   estar nos campos ESTÁVEIS (ident 412, ranges de seq, IPs) OU num keystream determinístico.
   → Fazer 2+ getpcap em sessões distintas e **diffar campo a campo**: o que for idêntico entre
   capturas é o portador real.
2. **Keystream PRNG.** payload (ou reply-ipid-delta) = mensagem XOR keystream de MT19937/LCG
   semeado por algo fixo (sid? ident 412? seq?). Tentar randcrack exige 624 saídas de 32 bits
   consecutivas — o payload dá só 8 bits/pkt (randcrack direto não serve); investigar se os 801
   bytes são saídas truncadas e se há seed pequeno brute-forçável.
3. **Mapeamento de alfabeto no reply-ipid-delta.** delta 1..41 pode indexar um alfabeto de ~41
   símbolos definido pelo autor. Precisa de crib (ex.: forçar que o início decodifique `HIK_`).
   Obstáculo: deltas diferem por round, então não há um stream único.
4. **RE-LER o card da plataforma** atrás do FORMATO da answer (LookupDesk falhou exatamente por
   não saber o formato esperado). O oráculo tem feedback → com o formato certo, brute dirigido
   resolve em uma sessão.

## Artefatos
- `bn.b64` — getpcap (texto base64, 45s, sid 9a7cbcb41f68a5b919152b9bdd4c4a02).
- `bn.pcap` — pcap decodificado (dado não confiável; abrir com `-r`, nunca executar).
- Scripts de análise: `/tmp/.../scratchpad/bn_*.py` (capture, parse, align, brute bits, xor,
  timing, ident). `bn_live.py` = harness de submit com feedback (reusar p/ validar a answer).

## Sessão 2026-10-09 (ângulos 1+2: diff cross-sessão + oráculo vivo) — ainda EM ABERTO
**ANGLE 1 (diff cross-sessão) = CONCLUSIVO: NÃO existe portador invariante.** 2 sessões TCP
distintas (sids df9ce05a…, 2523529709…), captura 18s cada, alinhadas pacote-a-pacote:
- **ttl/tos/icmp.ident**: 321/321 idênticos — mas são CONSTANTES genuínas (64/0/412), não carregam msg.
- **payload(1B)/ip.id/icmp.seq**: 0–1/321 idênticos entre sessões → random por sessão. `seq` difere
  só por offset de fase. Round = seq 1000..1095 (96) + 0..47 (48) = 144 pkts (confirmado).
- Conclusão: nenhum campo variável casa entre sessões → hipótese "decodificar mensagem estável" MORTA.
  Se há mensagem, é per-sessão e indistinguível de ruído.

**Gaps de ip.id (reply) = ruído genuíno (reconfirmado).** ipid do server = contador GLOBAL
monotônico; deltas entre replies = 1..41 UNIFORME (outliers 651/1854/309/1196 = fronteiras de round).
Decode direto/−1/%95/parity-bits (msb+lsb) → sem ASCII, sem `HIK`.

**Payload sweep local (sess0, por round e grupo G0/G1000, ordenado por seq):** razão imprimível 0.35
(= aleatório), melhor single-byte XOR r=0.39, sem `HIK`. Payload é 100% ruído.

**`tcpdump` server-side = stub.** Bare `tcpdump` → "ok" + "listening on eth0 … EN10MB" mas eth0 fica
SILENCIOSA (0 pkts em 25s). Flags extras (`-XX`/múltiplas) → "rejected" (allowlist, igual Front Desk).
`info` → ".". Sem comando oculto de pista.

**88 submits com feedback vivo (22 candidatos × 4 variantes de hash) = TODOS `incorrect.`** (junk
confirmou oráculo). Hash: sha256 do b64 sem `=`, com `=`, bytes raw, b64.strip(). Candidatos: IPs
10.13.9.9/.17 e combos `:` (ambos sentidos), ip.id/ipid/identification/icmp.ident/identifier,
412/0x19c, combos IP:campo, background noise/noise/covert. → **A variante de hash NÃO é o bloqueio**
(b64-sem-`=` = exatamente a que o colega usou e funcionou no Duty Roster). O bloqueio é a STRING.

**MESMA parede dos irmãos "Recover what left": LookupDesk(16004), Outbox(16005), Front Desk, Long
Call.** Todos: payload random-by-design + oráculo c/ feedback + answer = identificador estrutural num
FORMATO EXATO não-documentado; banner/help sem pista. Cada writeup conclui o mesmo: falta o card literal.

**IMPEDIMENTO e próximo passo manual (ordem de ROI):**
1. **Pedir ao colega que resolveu Duty Roster(350)/Helpdesk(300) a convenção EXATA de answer** dessa
   família. Duty Roster venceu com `who:where:port:interval` (itens nomeados pelo enunciado, por `:`).
   Background Noise precisa saber QUAIS itens o card nomeia.
2. **Ler o card literal de "Background Noise" (700 pts) na plataforma** — "Recover what left" é
   paráfrase; o card provável nomeia o campo/host/valor exato a submeter.
3. Com o formato, brute dirigido curto em 1 sessão sobre: src=10.13.9.9 (covert sender)/dst=10.13.9.17/
   ICMP echo/ident 412/campo ip.id. Blind brute esgotado (irmãos: 278–460 cada, 0 hit) → não insistir.

## Artefatos (sessão 09/out)
- `bn_sess0.b64`, `bn_sess1.b64` — 2 capturas 18s p/ diff cross-sessão (ANGLE 1).
- Scripts: scratchpad `bn_xsess.py` (diff), `bn_gaps.py` (ipid gaps), `bn_sweep.py` (payload),
  `bn_sub.py` (88 submits 4-hash), `bn_help.py`/`bn_bare.py` (tcpdump/banner probe).

## Sessão 2026-10-09 (ângulo TIMING + ordem + payload-por-seq) — REFUTADO, ainda EM ABERTO
Hipótese do canal de timing (intervalos inter-pacote) testada a fundo e **REFUTADA**. Pcap é
ruído por design em TODOS os canais. Resultados decisivos (scripts `bn_timing.py`, `bn_t2.py`,
`bn_t3.py`, `bn_order.py`, `bn_seqpay.py`):
- **Estrutura de timing:** cada par = request -> (gap minusculo) reply -> (gap ~40ms) proximo req.
  req->reply gap: mode ~20-30us, 82 valores unicos espalhados CONTINUOS 15-200us+ (cauda ate 4.8ms).
  Inter-par: ~40.5ms (mean 40531us, stdev 700us), 398 valores unicos de 800 = **jitter continuo,
  NAO quantizacao autorada**. median-threshold -> bytes com 0.24 imprimivel (ruido). Decodes
  raw/g-base/g//10/g%256/(g-base)+32 e threshold+-offset em ambos sentidos -> **sem HIK, sem ASCII**.
- **Ordem dos pacotes (cand. e):** seq estritamente sequencial dentro do round (0..47, depois
  1000..1095) - SEM permutacao, sem dado. Contagem por round constante = 144 (48+96). Sem dado.
- **Payload-por-seq (lead do writeup anterior):** payload NAO e constante por seq entre rounds
  (4-6 valores distintos por seq) -> random por round, majority-vote = bytes aleatorios. **Nao e
  mensagem de 144 bytes repetida.** Confirma payload 100% ruido.
- **Oraculo vivo reconfirmado** (sid a5703be4...): retorna `incorrect.` (feedback OK). Testada a
  tupla estilo Duty-Roster NUNCA tentada antes: `who:where:proto:interval` com 12 variantes
  (`10.13.9.17:10.13.9.9:icmp:40ms|0.04|40|25|144`, sentidos trocados, com 412/echo) -> **todas
  `incorrect.`**. Hash = sha256 do b64 sem whitespace (variante que funcionou no Duty Roster).

**Conclusao:** nenhum campo/timing/ordem/payload do pcap carrega mensagem estavel - e o gimmick
"Background Noise". O bloqueio continua sendo o **FORMATO EXATO da answer**, nao documentado no
banner/help/card parafrase. Precisa do card literal da plataforma ou da convencao do colega que
resolveu Duty Roster. Blind brute segue esgotado (0 hit em ~100 submits acumulados).
