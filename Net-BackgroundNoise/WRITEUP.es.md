<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Background+Noise+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Background Noise — NET (Packet) · 700 pts · 🔴 HARD

- **Status:** 🟡 ABIERTO — budget agotado el día 2 (2026-10-09); protocolo y pcap 100% mapeados, pero el `answer` del oráculo no fue determinado.
- **Flag:** —
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `nc <IP> <PORT>` (puerto `16009` en las notas de la sesión)
- **Enunciado:** *"The message is not where a normal protocol would put it. Recover what left."*

---

## 0. TL;DR

1. Harness de la familia PACKET: banner `Background Noise - 700 pts / session 120s / sid <32hex>`; comandos `help | capture [sec] | getpcap | tcpdump <args> | submit <proof> | quit`.
2. `getpcap` devuelve un pcap sintético (MACs en cero, linktype Ethernet) solo con tráfico ICMP echo request/reply entre dos IPs fijas, organizado en "rounds" de sweep.
3. Cada campo del paquete cae en uno de tres baldes — constante, contador limpio, o ruido uniforme que cambia por round — y ninguno lleva un mensaje estable. Confirmado por diff cross-sesión: ningún campo variable coincide entre dos sesiones distintas.
4. `submit` da feedback real (`incorrect.`), así que el bloqueo no es técnica de decodificación — es no saber el **formato exacto del `answer`** esperado por el oráculo. ~190 submits acumulados a lo largo de la sesión, todos `incorrect.`.
5. La pista central ("the message is not where a normal protocol would put it") es la propia trampa: el payload — donde un protocolo normal pondría dato — es ruido por diseño; el "mensaje" aparentemente no existe como payload decodificable, y la respuesta esperada es probablemente un identificador estructural del tráfico (al estilo de `Duty Roster`, que usa `who:where:port:interval`).

### Cadena que NO cerró
1. `capture [sec]` -> `getpcap` -> decodificar pcap (1602 paquetes ICMP, 2 IPs, ident 412 constante)
2. Probar payload, `ip.id` (request y reply), `icmp.seq`, timing inter-paquete, orden de los paquetes como portadores de mensaje -> todos refutados como ruido/decoy
3. ~190 submits con `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))` variando `answer` y la forma del hash del pcap -> todos `incorrect.`

---

## 1. Artefactos

- `bn.b64` — `getpcap` (texto base64, captura de 45s, sid `9a7cbcb41f68a5b919152b9bdd4c4a02`).
- `bn.pcap` — pcap decodificado a partir de `bn.b64` (dato no confiable; abrir solo con `-r`, nunca ejecutar).
- `bn_sess0.b64`, `bn_sess1.b64` — 2 capturas de 18s en sesiones TCP distintas, usadas para el diff cross-sesión.

## 2. Entrega / validación

- `getpcap` → `--- BEGIN PCAP --- <base64> --- END PCAP ---`.
- `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))` — hash del texto base64 sin whitespace (confirmado por el propio `help`).
- Todo en la misma conexión TCP (reconectar reinicia `sid`+pcap).
- `submit` da feedback real: respuesta `incorrect.` para un proof incorrecto (a diferencia de Helpdesk) — permite iterar/validar cuando el `answer` correcto sea conocido.

## 3. Análisis

### 3.1 Estructura del pcap (100% mapeada)
`linktype=1` Ethernet, MACs `00:00:00:00:00:00` → pcap sintético. Solo IPv4/ICMP. Tráfico = echo request/reply entre dos IPs fijas del laboratorio (pinger ↔ server).
- En 45s: 1602 paquetes = 801 echo request (type 8) + 801 echo reply (type 0), pareados 1:1.
- Organizado en "rounds" (~2s de gap entre ellos). Cada round = sweep de ping fijo: grupo A `icmp.seq` 0..47 (48 paquetes), grupo B `icmp.seq` 1000..1095 (96 paquetes) — rangos idénticos en todo round, estructura fija, no lleva dato.
- ICMP identifier = 412 (`0x019c`) constante en los 1602 paquetes.
- Frame = 43 bytes (14 eth + 20 ip + 9 icmp = 8 hdr + 1 byte de data). TTL=64, TOS=0, code=0, DF set en los requests. Todo constante.

### 3.2 Lo que fue descartado (confiable — scripts `bn_*.py`)
Cada campo cae en 1 de 3 baldes: constante, contador +1 limpio (decoy), o ruido uniforme que cambia cada round (decoy). Ninguno lleva un mensaje estable.
- **Payload (1 byte/pkt):** request==reply (echo RFC, 0 diferencias). Random. XOR con sid (hex/ascii), sha256(sid), md5(sid), single-byte 0..255, por grupo/round → sin `HIK`.
- **req ip.id:** contador +1 global perfecto (10026,10027,…) atravesando rounds. Decoy "normal".
- **reply ip.id ("background noise"):** contador monotónico con delta uniforme 1..41 (sin el reset de round). Los deltas DIFIEREN cada round → ruido genuino, no repetición de mensaje. Probado: delta&0xff, delta%95+32, bit-planes (LSB/parity/median-split, msb/lsb, 8 offsets), ip.id mod128, low byte, por grupo A/B → sin `HIK` ni ASCII.
- **icmp.seq:** contador estructurado (0-47,1000-1095) idéntico por round.
- **icmp.ident:** 412 constante. ttl/tos/code/verihl/flags/fragoff/totlen: constantes.
- **Ethernet MAC:** 00..00. Checksums IP/ICMP: correctos/derivados (tshark: "Good").
- **Timing:** inter-paquete ~40ms + jitter 200-600us unimodal = ruido; splits binarios (>40.5ms,>41ms) no dieron ASCII. Timestamps us del pcap (lo byte, %95+32, %128) → ruido.
- `tshark -z expert`: ningún malformed; solo `eth:ethertype:ip:icmp:data`.

### 3.3 Diff cross-sesión (ANGLE 1) — conclusivo: no existe portador invariante
2 sesiones TCP distintas (sids `df9ce05a…`, `2523529709…`), captura 18s cada una, alineadas paquete-a-paquete:
- `ttl`/`tos`/`icmp.ident`: 321/321 idénticos — pero son constantes genuinas (64/0/412), no llevan mensaje.
- `payload(1B)`/`ip.id`/`icmp.seq`: 0–1/321 idénticos entre sesiones → random por sesión. `seq` difiere solo por un offset de fase. Round = seq 1000..1095 (96) + 0..47 (48) = 144 pkts (confirmado).
- Conclusión: ningún campo variable coincide entre sesiones → la hipótesis "decodificar un mensaje estable" está muerta. Si hay mensaje, es per-sesión e indistinguible de ruido.

### 3.4 Canal de timing — probado a fondo y refutado
Estructura de timing: cada par = request → (gap minúsculo) reply → (gap ~40ms) próximo req. Gap `req→reply`: mode ~20-30us, 82 valores únicos esparcidos continuos 15-200us+ (cola hasta 4.8ms). Inter-par: ~40.5ms (mean 40531us, stdev 700us), 398 valores únicos de 800 = jitter continuo, no cuantización autorada. Median-threshold → bytes con 0.24 imprimible (ruido). Decodes raw/g-base/g//10/g%256/(g-base)+32 y threshold±offset en ambos sentidos → sin `HIK`, sin ASCII.

**Orden de los paquetes:** seq estrictamente secuencial dentro del round (0..47, después 1000..1095) — sin permutación, sin dato. Conteo por round constante = 144 (48+96).

**Payload-por-seq:** el payload no es constante por seq entre rounds (4-6 valores distintos por seq) → random por round, majority-vote da bytes aleatorios. No es un mensaje de 144 bytes repetido. Confirma payload 100% ruido.

### 3.5 `tcpdump` server-side y otros comandos
Bare `tcpdump` → "ok" + "listening on eth0 … EN10MB" pero eth0 queda silenciosa (0 pkts en 25s). Flags extras (`-XX`/múltiples) → "rejected" (allowlist, igual que Front Desk). `info` → ".". Sin comando oculto de pista.

### 3.6 Submits acumulados con feedback vivo
88 submits (22 candidatos × 4 variantes de hash) = todos `incorrect.` (junk confirmó el oráculo). Hash probado: sha256 del b64 sin `=`, con `=`, bytes raw, b64.strip(). Candidatos: las IPs del laboratorio y combos `:` (ambos sentidos), `ip.id`/`ipid`/`identification`/`icmp.ident`/`identifier`, `412`/`0x19c`, combos IP:campo, `background noise`/`noise`/`covert`. La variante de hash no es el bloqueo (b64-sin-`=` = exactamente la que funcionó en Duty Roster) — el bloqueo es la string del `answer`.

Ronda adicional: tupla estilo Duty-Roster (`who:where:proto:interval`, 12 variantes con las dos IPs, `icmp`/`echo`, `412`, y el intervalo en `ms`/`s`/valores enteros, ambos sentidos) → todas `incorrect.`.

Total acumulado en la sesión: ~190 submits sin hit.

## 4. Lo que no funcionó

| Hipótesis | Resultado | Por qué |
|---|---|---|
| El payload del paquete lleva el mensaje | ✗ | Es exactamente "donde un protocolo normal pondría el dato" — el propio enunciado dice que NO está ahí; confirmado random/decoy. |
| `reply ip.id` como canal encubierto clásico | ✗ | Parece canal encubierto, pero los deltas son ruido uniforme por diseño ("Background Noise"); decodes de bit-plane/alfabeto no dieron ASCII. |
| Keystream PRNG (MT19937/LCG) sobre payload o delta de ip.id | parcialmente abierta | Randcrack directo no sirve (solo 8 bits/pkt); no fue posible confirmar un seed pequeño brute-forzable en el tiempo disponible. |
| Canal de timing inter-paquete | ✗ | Jitter continuo (no cuantizado); ningún split/threshold dio ASCII. |
| Orden/permutación de los paquetes | ✗ | Seq estrictamente secuencial dentro del round, sin permutación. |
| ~190 candidatos de `answer` (IPs, ident, campos, tuplas estilo Duty Roster) × variantes de hash | ✗ | Todos `incorrect.`; variante de hash confirmada correcta (igual que Duty Roster), así que el problema es la string/formato del `answer`, no el hash. |

## 5. Conclusión / próximos pasos

Ningún campo, timing, orden o payload del pcap lleva un mensaje estable — es el propio gimmick de "Background Noise". El bloqueo final es el **formato exacto del `answer`** esperado por el oráculo, que no está documentado en el banner/help y no fue posible inferir por brute-force dirigido dentro del budget. Misma pared observada en los desafíos-hermanos de la familia "Recover what left" (`LookupDesk`, `Outbox`, `Front Desk`, `Long Call`).

Próximos pasos (orden de ROI):
1. Obtener la convención exacta de `answer` de esta familia con quien resolvió `Duty Roster` (350 pts) — ganó con `who:where:port:interval`, items nombrados por el enunciado de la plataforma, separados por `:`.
2. Releer el card literal de "Background Noise" en la plataforma — "Recover what left" es paráfrasis; el card probablemente nombra el campo/host/valor exacto a enviar.
3. Con el formato correcto, un brute dirigido corto en una única sesión sobre las IPs del pcap, ICMP echo, ident 412 y `ip.id` debería bastar — el blind brute ya está agotado (0 hit en ~190 submits acumulados), no insistir en esa vía.

---

## Apéndice — herramientas

- Scripts de análisis (fuera de este directorio, scratchpad de la sesión): `bn_sweep.py`/`bn_timing.py`/`bn_t2.py`/`bn_t3.py`/`bn_order.py`/`bn_seqpay.py` (payload, timing, orden), `bn_gaps.py` (gaps de ip.id), `bn_xsess.py` (diff cross-sesión), `bn_sub.py`/`bn_live.py` (harness de submit con feedback), `bn_help.py`/`bn_bare.py` (probe de banner/tcpdump).
