<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Duty+Roster+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Duty Roster — NET (Packet) · 350 pts · 🟡 MEDIUM

> [!WARNING]
> **Incomplete documentation.** This challenge was solved, but the final solution (full chain and/or flag) has not yet been documented in this writeup. The content below covers only what was recorded.

- **Status:** ✅ SOLVED — final solution not documented (see warning above).
- **Flag:** — (not documented)
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `nc <IP> 16007`
- **Prompt:** *"Identify who, where, which port, and how often."* (per the comment in `solve.py`)

---

## 0. TL;DR

1. **Packet** family challenge: a harness with `capture`/`getpcap`/`submit` over a TCP session, which captures a synthetic pcap of a "beacon" (repetitive TCP traffic) and expects the answer (`answer`) to identify the **structural** metadata of that beacon — not the payload.
2. The prompt names 4 items: **who** (source IP), **where** (destination IP), **port** (destination TCP port) and **how often** (interval between beacons).
3. Winning `answer`: `who:where:port:interval`, with `who`/`where` = IPs, `port` = TCP port, `interval` = median of the interval between the beacon's `SYN` packets, in seconds.
4. `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text))`, tested with 2 variants of the pcap hash (base64 text and raw bytes) in the same TCP session.
5. This directory preserves the script (`solve.py`) as the **Rosetta stone** of the Packet family — the same logic of "name the items from the prompt, join with `:`" was reapplied (unsuccessfully) on `Background Noise`.

### Chain that closed (per the script comments)
1. Connect, read `sid` from the banner
2. `capture 30` -> `getpcap` -> decode base64 -> pcap
3. `tshark` over the pcap: find repeated `SYN` streams (`tcp.flags.syn==1 && tcp.flags.ack==0`), group by `(src, dst, dstport)`, compute the median of the interval between openings
4. Build `answer` candidates from `who:where:port:interval` (various formattings of the separator and the interval)
5. `submit sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64))` in a loop, until the response contains `HIK`

---

## 1. Artifacts

- `solve.py` — the only artifact present in this directory. A comment at the top of the file documents the `answer` convention discovered; the code itself was copied and adapted (reconstructed dunders, adjusted `getpcap` regex) for reuse as a harness for other Packet-family challenges.

## 2. Delivery / validation

- TCP session harness (`<IP>:16007`): banner with `sid <32hex>`, commands including `capture [sec]`, `getpcap`, `submit <proof>`.
- `getpcap` returns the pcap between `BEGIN PCAP`/`END PCAP` markers, in base64.
- `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_text_no_ws))`. The script tests this variant and also the hash over the raw decoded bytes, in the same session.

## 3. Analysis

### 3.1 The Packet family's `answer` convention
Comment in `solve.py`:

> "Rosetta stone of the PACKET family: answer = the items the prompt names, joined by ':', STRUCTURAL (metadata of the stream that beacons), NOT the payload."

For Duty Roster, the prompt ("Identify who, where, which port, and how often.") names:
- `who` = source IP of the beacon
- `where` = destination IP
- `port` = destination TCP port
- `how often` = median of the interval between `SYN` openings (in seconds)

Likely winning format: `who:where:port:interval` (separator `:`, interval in a format like `"5s"`/`"5"`).

### 3.2 Deriving the streams (via `tshark`)
`derive_streams()` runs two `tshark` passes over the decoded pcap:
1. Filter `tcp.flags.syn==1 && tcp.flags.ack==0`, extracting `frame.time_relative`, `ip.src`, `ip.dst`, `tcp.dstport` — groups by `(src, dst, dstport)` and computes the median of the deltas between consecutive opening times.
2. Filter `tcp.len>0`, to estimate the data volume per stream (`client_data`), used only as context/ordering.

The streams are ordered by `count` (number of SYNs) descending; those that repeat (`count>=3`) are the "beacon" candidates.

### 3.3 Candidate generation and submission
`build_candidates()` generates various formattings of `who`, `where`, `port` and `interval` (integer, with `s`/`sec`/`ms`/`seconds`, with `.0`, etc.) combined with separators (`:`, space, comma, `>`, `|`, `/`, `-`), prioritizing formats with 2-3 occurrences of `:` (more likely given the `who:where:port[:interval]` pattern).

For each candidate, it tests `proof` with the pcap hash in 2 forms (base64 text `h_b64` and raw bytes `h_raw`), within a budget of ~108s of submits in the same TCP session, stopping at the first `HIK` found in the response.

## 4. What didn't work

Not documented in the artifacts of this directory — the script only records the final logic (already adjusted for the winning format) and does not preserve the history of earlier attempts.

## 5. Conclusion / next steps

The challenge was solved using the `who:where:port:interval` convention, but the flag itself and the full log of the solving session were not preserved in this directory — only the final script. This writeup documents what is recoverable from `solve.py`: the protocol, the stream-derivation logic via `tshark` and the building/submission of the `answer` candidates. If the flag is needed again, running `solve.py` against a fresh session of the challenge (if still live) should reproduce it.

---

## Appendix — tools

- `solve.py` — `python3 solve.py`: connects to the harness, captures the pcap, derives beacon streams via `tshark`, generates `answer` candidates in the `who:where:port:interval` format and tests `submit` in a loop until it finds `HIK` in the response (writes `FLAG.txt` in the directory if found).
