<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Background+Noise+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <a href="WRITEUP.es.md">Español</a> · <b>Português (BR)</b></p>

# Background Noise — NET (Packet) · 700 pts · 🔴 HARD

- **Status:** 🟡 EM ABERTO — budget estourado no dia 2 (2026-10-09); protocolo e pcap 100% mapeados, mas a `answer` do oráculo não foi determinada.
- **Flag:** —
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** `nc <IP> <PORT>` (porta `16009` nas notas da sessão)
- **Enunciado:** *"The message is not where a normal protocol would put it. Recover what left."*

---

## 0. TL;DR

1. Harness da família PACKET: banner `Background Noise - 700 pts / session 120s / sid <32hex>`; comandos `help | capture [sec] | getpcap | tcpdump <args> | submit <proof> | quit`.
2. `getpcap` devolve um pcap sintético (MACs zeradas, linktype Ethernet) só com tráfego ICMP echo request/reply entre dois IPs fixos, organizado em "rounds" de sweep.
3. Cada campo do pacote cai em um de três baldes — constante, contador limpo, ou ruído uniforme que muda por round — e nenhum carrega mensagem estável. Confirmado por diff cross-sessão: nenhum campo variável bate entre duas sessões distintas.
4. `submit` dá feedback real (`incorrect.`), então o bloqueio não é técnica de decodificação — é não saber o **formato exato da `answer`** esperada pelo oráculo. ~190 submits acumulados ao longo da sessão, todos `incorrect.`.
5. A pista central ("the message is not where a normal protocol would put it") é a própria armadilha: o payload — onde um protocolo normal poria dado — é ruído por design; a "mensagem" aparentemente não existe como payload decodificável, e a resposta esperada é provavelmente um identificador estrutural do tráfego (nos moldes de `Duty Roster`, que usa `who:where:port:interval`).

### Cadeia que NÃO fechou
1. `capture [sec]` -> `getpcap` -> decodificar pcap (1602 pacotes ICMP, 2 IPs, ident 412 constante)
2. Testar payload, `ip.id` (request e reply), `icmp.seq`, timing inter-pacote, ordem dos pacotes como portadores de mensagem -> todos refutados como ruído/decoy
3. ~190 submits com `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))` variando `answer` e a forma do hash do pcap -> todos `incorrect.`

---

## 1. Artefatos

- `bn.b64` — `getpcap` (texto base64, captura de 45s, sid `9a7cbcb41f68a5b919152b9bdd4c4a02`).
- `bn.pcap` — pcap decodificado a partir de `bn.b64` (dado não confiável; abrir só com `-r`, nunca executar).
- `bn_sess0.b64`, `bn_sess1.b64` — 2 capturas de 18s em sessões TCP distintas, usadas para diff cross-sessão.

## 2. Entrega / validação

- `getpcap` → `--- BEGIN PCAP --- <base64> --- END PCAP ---`.
- `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))` — hash do texto base64 sem whitespace (confirmado pelo próprio `help`).
- Tudo na mesma conexão TCP (reconectar zera `sid`+pcap).
- `submit` dá feedback real: resposta `incorrect.` para proof errado (diferente do Helpdesk) — permite iterar/validar quando a `answer` certa for conhecida.

## 3. Análise

### 3.1 Estrutura do pcap (100% mapeada)
`linktype=1` Ethernet, MACs `00:00:00:00:00:00` → pcap sintético. Só IPv4/ICMP. Tráfego = echo request/reply entre dois IPs fixos do laboratório (pinger ↔ server).
- Em 45s: 1602 pacotes = 801 echo request (type 8) + 801 echo reply (type 0), pareados 1:1.
- Organizado em "rounds" (~2s de gap entre eles). Cada round = sweep de ping fixo: grupo A `icmp.seq` 0..47 (48 pacotes), grupo B `icmp.seq` 1000..1095 (96 pacotes) — ranges idênticos em todo round, estrutura fixa, não carrega dado.
- ICMP identifier = 412 (`0x019c`) constante em todos os 1602 pacotes.
- Frame = 43 bytes (14 eth + 20 ip + 9 icmp = 8 hdr + 1 byte de data). TTL=64, TOS=0, code=0, DF set nos requests. Tudo constante.

### 3.2 O que foi descartado (confiável — scripts `bn_*.py`)
Cada campo cai em 1 de 3 baldes: constante, contador +1 limpo (decoy), ou ruído uniforme que muda a cada round (decoy). Nenhum carrega mensagem estável.
- **Payload (1 byte/pkt):** request==reply (echo RFC, 0 diferenças). Random. XOR com sid (hex/ascii), sha256(sid), md5(sid), single-byte 0..255, por grupo/round → sem `HIK`.
- **req ip.id:** contador +1 global perfeito (10026,10027,…) atravessando rounds. Decoy "normal".
- **reply ip.id ("background noise"):** contador monotônico com delta uniforme 1..41 (sem o reset de round). Deltas DIFEREM a cada round → ruído genuíno, não repetição de mensagem. Testado: delta&0xff, delta%95+32, bit-planes (LSB/parity/median-split, msb/lsb, 8 offsets), ip.id mod128, low byte, por grupo A/B → sem `HIK` nem ASCII.
- **icmp.seq:** contador estruturado (0-47,1000-1095) idêntico por round.
- **icmp.ident:** 412 constante. ttl/tos/code/verihl/flags/fragoff/totlen: constantes.
- **Ethernet MAC:** 00..00. Checksums IP/ICMP: corretos/derivados (tshark: "Good").
- **Timing:** inter-pacote ~40ms + jitter 200-600us unimodal = ruído; splits binários (>40.5ms,>41ms) não deram ASCII. Timestamps us do pcap (lo byte, %95+32, %128) → ruído.
- `tshark -z expert`: nenhum malformed; só `eth:ethertype:ip:icmp:data`.

### 3.3 Diff cross-sessão (ANGLE 1) — conclusivo: não existe portador invariante
2 sessões TCP distintas (sids `df9ce05a…`, `2523529709…`), captura 18s cada, alinhadas pacote-a-pacote:
- `ttl`/`tos`/`icmp.ident`: 321/321 idênticos — mas são constantes genuínas (64/0/412), não carregam mensagem.
- `payload(1B)`/`ip.id`/`icmp.seq`: 0–1/321 idênticos entre sessões → random por sessão. `seq` difere só por offset de fase. Round = seq 1000..1095 (96) + 0..47 (48) = 144 pkts (confirmado).
- Conclusão: nenhum campo variável casa entre sessões → a hipótese "decodificar mensagem estável" está morta. Se há mensagem, é per-sessão e indistinguível de ruído.

### 3.4 Canal de timing — testado a fundo e refutado
Estrutura de timing: cada par = request → (gap minúsculo) reply → (gap ~40ms) próximo req. `req→reply` gap: mode ~20-30us, 82 valores únicos espalhados contínuos 15-200us+ (cauda até 4.8ms). Inter-par: ~40.5ms (mean 40531us, stdev 700us), 398 valores únicos de 800 = jitter contínuo, não quantização autorada. Median-threshold → bytes com 0.24 imprimível (ruído). Decodes raw/g-base/g//10/g%256/(g-base)+32 e threshold±offset em ambos sentidos → sem `HIK`, sem ASCII.

**Ordem dos pacotes:** seq estritamente sequencial dentro do round (0..47, depois 1000..1095) — sem permutação, sem dado. Contagem por round constante = 144 (48+96).

**Payload-por-seq:** payload não é constante por seq entre rounds (4-6 valores distintos por seq) → random por round, majority-vote dá bytes aleatórios. Não é mensagem de 144 bytes repetida. Confirma payload 100% ruído.

### 3.5 `tcpdump` server-side e outros comandos
Bare `tcpdump` → "ok" + "listening on eth0 … EN10MB" mas eth0 fica silenciosa (0 pkts em 25s). Flags extras (`-XX`/múltiplas) → "rejected" (allowlist, igual Front Desk). `info` → ".". Sem comando oculto de pista.

### 3.6 Submits acumulados com feedback vivo
88 submits (22 candidatos × 4 variantes de hash) = todos `incorrect.` (junk confirmou oráculo). Hash testado: sha256 do b64 sem `=`, com `=`, bytes raw, b64.strip(). Candidatos: IPs do laboratório e combos `:` (ambos sentidos), `ip.id`/`ipid`/`identification`/`icmp.ident`/`identifier`, `412`/`0x19c`, combos IP:campo, `background noise`/`noise`/`covert`. A variante de hash não é o bloqueio (b64-sem-`=` = exatamente a que funcionou no Duty Roster) — o bloqueio é a string da `answer`.

Rodada adicional: tupla estilo Duty-Roster (`who:where:proto:interval`, 12 variantes com os dois IPs, `icmp`/`echo`, `412`, e o intervalo em `ms`/`s`/valores inteiros, ambos sentidos) → todas `incorrect.`.

Total acumulado na sessão: ~190 submits sem hit.

## 4. O que não funcionou

| Hipótese | Resultado | Por quê |
|---|---|---|
| Payload do pacote carrega a mensagem | ✗ | É exatamente "onde um protocolo normal poria o dado" — o próprio enunciado diz que NÃO está lá; confirmado random/decoy. |
| `reply ip.id` como canal encoberto clássico | ✗ | Parece canal encoberto, mas os deltas são ruído uniforme por design ("Background Noise"); decodes de bit-plane/alfabeto não deram ASCII. |
| Keystream PRNG (MT19937/LCG) sobre payload ou delta de ip.id | parcialmente aberta | Randcrack direto não serve (só 8 bits/pkt); não foi possível confirmar seed pequeno brute-forçável no tempo disponível. |
| Canal de timing inter-pacote | ✗ | Jitter contínuo (não quantizado); nenhum split/threshold deu ASCII. |
| Ordem/permutação dos pacotes | ✗ | Seq estritamente sequencial dentro do round, sem permutação. |
| ~190 candidatos de `answer` (IPs, ident, campos, tuplas estilo Duty Roster) × variantes de hash | ✗ | Todos `incorrect.`; variante de hash confirmada correta (igual Duty Roster), então o problema é a string/formato da `answer`, não o hash. |

## 5. Conclusão / próximos passos

Nenhum campo, timing, ordem ou payload do pcap carrega mensagem estável — é o próprio gimmick de "Background Noise". O bloqueio final é o **formato exato da `answer`** esperada pelo oráculo, que não está documentado no banner/help e não foi possível inferir por brute-force dirigido dentro do budget. Mesma parede observada nos desafios-irmãos da família "Recover what left" (`LookupDesk`, `Outbox`, `Front Desk`, `Long Call`).

Próximos passos (ordem de ROI):
1. Obter a convenção exata de `answer` dessa família com quem resolveu `Duty Roster` (350 pts) — venceu com `who:where:port:interval`, itens nomeados pelo enunciado da plataforma, separados por `:`.
2. Reler o card literal de "Background Noise" na plataforma — "Recover what left" é paráfrase; o card provavelmente nomeia o campo/host/valor exato a submeter.
3. Com o formato correto, um brute dirigido curto numa única sessão sobre os IPs do pcap, ICMP echo, ident 412 e `ip.id` deve bastar — blind brute já está esgotado (0 hit em ~190 submits acumulados), não insistir nessa via.

---

## Apêndice — ferramentas

- Scripts de análise (fora deste diretório, scratchpad da sessão): `bn_sweep.py`/`bn_timing.py`/`bn_t2.py`/`bn_t3.py`/`bn_order.py`/`bn_seqpay.py` (payload, timing, ordem), `bn_gaps.py` (gaps de ip.id), `bn_xsess.py` (diff cross-sessão), `bn_sub.py`/`bn_live.py` (harness de submit com feedback), `bn_help.py`/`bn_bare.py` (probe de banner/tcpdump).
