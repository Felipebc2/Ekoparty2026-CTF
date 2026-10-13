<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Background+Noise+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Background Noise — NET (Packet) · 700 pts · 🔴 HARD

- **Status:** 🟡 OPEN — budget blown on day 2 (2026-10-09); protocol and pcap 100% mapped, but the oracle's `answer` was not determined.
- **Flag:** —
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `nc <IP> <PORT>` (port `16009` in the session notes)
- **Prompt:** *"The message is not where a normal protocol would put it. Recover what left."*

---

## 0. TL;DR

1. PACKET family harness: banner `Background Noise - 700 pts / session 120s / sid <32hex>`; commands `help | capture [sec] | getpcap | tcpdump <args> | submit <proof> | quit`.
2. `getpcap` returns a synthetic pcap (zeroed MACs, Ethernet linktype) with only ICMP echo request/reply traffic between two fixed IPs, organized into "rounds" of sweeps.
3. Each packet field falls into one of three buckets — constant, clean counter, or uniform noise that changes per round — and none carries a stable message. Confirmed by cross-session diff: no variable field matches between two distinct sessions.
4. `submit` gives real feedback (`incorrect.`), so the blocker is not a decoding technique — it is not knowing the **exact format of the `answer`** expected by the oracle. ~190 submits accumulated over the session, all `incorrect.`.
5. The central hint ("the message is not where a normal protocol would put it") is the trap itself: the payload — where a normal protocol would put data — is noise by design; the "message" apparently does not exist as a decodable payload, and the expected answer is probably a structural identifier of the traffic (along the lines of `Duty Roster`, which uses `who:where:port:interval`).

### Chain that did NOT close
1. `capture [sec]` -> `getpcap` -> decode pcap (1602 ICMP packets, 2 IPs, constant ident 412)
2. Test payload, `ip.id` (request and reply), `icmp.seq`, inter-packet timing, packet order as message carriers -> all refuted as noise/decoy
3. ~190 submits with `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))` varying `answer` and the form of the pcap hash -> all `incorrect.`

---

## 1. Artifacts

- `bn.b64` — `getpcap` (base64 text, 45s capture, sid `9a7cbcb41f68a5b919152b9bdd4c4a02`).
- `bn.pcap` — pcap decoded from `bn.b64` (untrusted data; open only with `-r`, never execute).
- `bn_sess0.b64`, `bn_sess1.b64` — 2 captures of 18s in distinct TCP sessions, used for the cross-session diff.

## 2. Delivery / validation

- `getpcap` → `--- BEGIN PCAP --- <base64> --- END PCAP ---`.
- `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))` — hash of the base64 text without whitespace (confirmed by `help` itself).
- Everything on the same TCP connection (reconnecting resets `sid`+pcap).
- `submit` gives real feedback: `incorrect.` response for a wrong proof (unlike Helpdesk) — lets you iterate/validate once the right `answer` is known.

## 3. Analysis

### 3.1 Pcap structure (100% mapped)
`linktype=1` Ethernet, MACs `00:00:00:00:00:00` → synthetic pcap. IPv4/ICMP only. Traffic = echo request/reply between two fixed lab IPs (pinger ↔ server).
- In 45s: 1602 packets = 801 echo request (type 8) + 801 echo reply (type 0), paired 1:1.
- Organized into "rounds" (~2s gap between them). Each round = fixed ping sweep: group A `icmp.seq` 0..47 (48 packets), group B `icmp.seq` 1000..1095 (96 packets) — identical ranges in every round, fixed structure, carries no data.
- ICMP identifier = 412 (`0x019c`) constant across all 1602 packets.
- Frame = 43 bytes (14 eth + 20 ip + 9 icmp = 8 hdr + 1 byte of data). TTL=64, TOS=0, code=0, DF set on requests. All constant.

### 3.2 What was discarded (reliable — scripts `bn_*.py`)
Each field falls into 1 of 3 buckets: constant, clean +1 counter (decoy), or uniform noise that changes each round (decoy). None carries a stable message.
- **Payload (1 byte/pkt):** request==reply (echo RFC, 0 differences). Random. XOR with sid (hex/ascii), sha256(sid), md5(sid), single-byte 0..255, per group/round → no `HIK`.
- **req ip.id:** perfect global +1 counter (10026,10027,…) crossing rounds. "Normal" decoy.
- **reply ip.id ("background noise"):** monotonic counter with uniform delta 1..41 (without the round reset). Deltas DIFFER each round → genuine noise, not a repeated message. Tested: delta&0xff, delta%95+32, bit-planes (LSB/parity/median-split, msb/lsb, 8 offsets), ip.id mod128, low byte, per group A/B → no `HIK` nor ASCII.
- **icmp.seq:** structured counter (0-47,1000-1095) identical per round.
- **icmp.ident:** 412 constant. ttl/tos/code/verihl/flags/fragoff/totlen: constant.
- **Ethernet MAC:** 00..00. IP/ICMP checksums: correct/derived (tshark: "Good").
- **Timing:** inter-packet ~40ms + jitter 200-600us unimodal = noise; binary splits (>40.5ms,>41ms) gave no ASCII. Pcap us timestamps (low byte, %95+32, %128) → noise.
- `tshark -z expert`: no malformed; only `eth:ethertype:ip:icmp:data`.

### 3.3 Cross-session diff (ANGLE 1) — conclusive: no invariant carrier exists
2 distinct TCP sessions (sids `df9ce05a…`, `2523529709…`), 18s capture each, aligned packet-by-packet:
- `ttl`/`tos`/`icmp.ident`: 321/321 identical — but these are genuine constants (64/0/412), carrying no message.
- `payload(1B)`/`ip.id`/`icmp.seq`: 0–1/321 identical between sessions → random per session. `seq` differs only by a phase offset. Round = seq 1000..1095 (96) + 0..47 (48) = 144 pkts (confirmed).
- Conclusion: no variable field matches between sessions → the "decode a stable message" hypothesis is dead. If there is a message, it is per-session and indistinguishable from noise.

### 3.4 Timing channel — tested thoroughly and refuted
Timing structure: each pair = request → (tiny gap) reply → (gap ~40ms) next req. `req→reply` gap: mode ~20-30us, 82 unique values spread continuous 15-200us+ (tail up to 4.8ms). Inter-pair: ~40.5ms (mean 40531us, stdev 700us), 398 unique of 800 values = continuous jitter, not authored quantization. Median-threshold → bytes with 0.24 printable (noise). Decodes raw/g-base/g//10/g%256/(g-base)+32 and threshold±offset in both directions → no `HIK`, no ASCII.

**Packet order:** strictly sequential seq within the round (0..47, then 1000..1095) — no permutation, no data. Constant count per round = 144 (48+96).

**Payload-per-seq:** payload is not constant per seq across rounds (4-6 distinct values per seq) → random per round, majority-vote gives random bytes. It is not a repeated 144-byte message. Confirms payload 100% noise.

### 3.5 Server-side `tcpdump` and other commands
Bare `tcpdump` → "ok" + "listening on eth0 … EN10MB" but eth0 stays silent (0 pkts in 25s). Extra flags (`-XX`/multiple) → "rejected" (allowlist, like Front Desk). `info` → ".". No hidden hint command.

### 3.6 Accumulated submits with live feedback
88 submits (22 candidates × 4 hash variants) = all `incorrect.` (junk confirmed the oracle). Hash tested: sha256 of the b64 without `=`, with `=`, raw bytes, b64.strip(). Candidates: the lab IPs and `:` combos (both directions), `ip.id`/`ipid`/`identification`/`icmp.ident`/`identifier`, `412`/`0x19c`, IP:field combos, `background noise`/`noise`/`covert`. The hash variant is not the blocker (b64-without-`=` = exactly the one that worked in Duty Roster) — the blocker is the `answer` string.

Additional round: Duty-Roster-style tuple (`who:where:proto:interval`, 12 variants with the two IPs, `icmp`/`echo`, `412`, and the interval in `ms`/`s`/integer values, both directions) → all `incorrect.`.

Total accumulated in the session: ~190 submits with no hit.

## 4. What didn't work

| Hypothesis | Result | Why |
|---|---|---|
| The packet payload carries the message | ✗ | It is exactly "where a normal protocol would put the data" — the prompt itself says it is NOT there; confirmed random/decoy. |
| `reply ip.id` as a classic covert channel | ✗ | Looks like a covert channel, but the deltas are uniform noise by design ("Background Noise"); bit-plane/alphabet decodes gave no ASCII. |
| PRNG keystream (MT19937/LCG) over payload or ip.id delta | partially open | Direct randcrack does not work (only 8 bits/pkt); could not confirm a small brute-forceable seed in the available time. |
| Inter-packet timing channel | ✗ | Continuous jitter (not quantized); no split/threshold gave ASCII. |
| Packet order/permutation | ✗ | Strictly sequential seq within the round, no permutation. |
| ~190 `answer` candidates (IPs, ident, fields, Duty-Roster-style tuples) × hash variants | ✗ | All `incorrect.`; hash variant confirmed correct (same as Duty Roster), so the problem is the `answer` string/format, not the hash. |

## 5. Conclusion / next steps

No field, timing, order, or payload of the pcap carries a stable message — it is the "Background Noise" gimmick itself. The final blocker is the **exact format of the `answer`** expected by the oracle, which is not documented in the banner/help and could not be inferred by directed brute-force within the budget. Same wall observed in the sibling challenges of the "Recover what left" family (`LookupDesk`, `Outbox`, `Front Desk`, `Long Call`).

Next steps (order of ROI):
1. Obtain the exact `answer` convention of this family from whoever solved `Duty Roster` (350 pts) — won with `who:where:port:interval`, items named by the platform prompt, separated by `:`.
2. Re-read the literal "Background Noise" card on the platform — "Recover what left" is a paraphrase; the card probably names the exact field/host/value to submit.
3. With the correct format, a short directed brute in a single session over the pcap IPs, ICMP echo, ident 412 and `ip.id` should suffice — blind brute is already exhausted (0 hit in ~190 accumulated submits), do not insist on that path.

---

## Appendix — tools

- Analysis scripts (outside this directory, session scratchpad): `bn_sweep.py`/`bn_timing.py`/`bn_t2.py`/`bn_t3.py`/`bn_order.py`/`bn_seqpay.py` (payload, timing, order), `bn_gaps.py` (ip.id gaps), `bn_xsess.py` (cross-session diff), `bn_sub.py`/`bn_live.py` (submit harness with feedback), `bn_help.py`/`bn_bare.py` (banner/tcpdump probe).
