<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=ZM.js+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# ZM.js — PWN · 400 pts · 🟡 MEDIUM

> [!WARNING]
> **Incomplete documentation.** This challenge was solved, but the final solution (full chain and/or flag) has not yet been documented in this writeup. The content below covers only what was recorded.

- **Status:** ✅ SOLVED — final solution not documented (see warning above).
- **Flag:** — (not documented)
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `<HOST>:18080` — plain-text HTTP/1.1 (NOT 443)
- **Prompt:** —

---

## 0. TL;DR

1. Black-box remote service (no binary to download) that exposes a JSON API to manipulate "images" in a custom QIMG format (likely a QuickJS-ng app).
2. The mapped insight: `download` is bounds-checked (no under-read) and the filters ignore all params, only doing `invert`/`grayscale` in-place — no clear OOB/leak vector was found during the documented session.
3. The flag was not extracted within the available material (see 5).

### Chain that closed it
None — the documented session ends at "next steps", with no closed chain.

---

## 1. Artifacts

- No local binary — 100% remote service (`<HOST>:18080`); Ghidra doesn't apply, analysis is pure black-box.

## 2. Delivery / validation

- Session rule: the same keep-alive TCP connection = a session; each new connection = clean state. Image IDs are per-session (they always start at 0 on a new connection).
- All responses are JSON. Root and unknown routes => `404 {"error":"not found"}`. No `Server`/`Allow` header.

## 3. Analysis

### 3.1 API map

- `POST /api/login` body `{"user":"<x>"}` => `{"token":"tok_<n>_<user>"}`. Trivial auth, any user works. Global incremental token.
- Auth on the other routes: header `Authorization: Bearer tok_...`
- `POST /api/images` body `{"data":"<hex of the QIMG blob>"}` => creates an image, returns `{"id":N,"name":"img_N+1","width":..,"height":..,"channels":..,"processed":false}`
- `GET /api/images/{id}` => metadata
- `GET /api/images/{id}?download=1` => `{"id":N,"data":"<hex of the FIRST 16 bytes of the buffer>"}`
- `POST /api/images/{id}/filter` body `{"filter":"<name>", ...params}` => `{"ok":true}` (always)

### 3.2 QIMG format (fully reversed)

```
magic   "QIMG"        (4 bytes)
width   uint32 LE
height  uint32 LE
channels uint32 LE    (valid: 1 and 4; 2,3 => "inconsistent pixel data size")
pixels  width*height*channels bytes
```

Strict check: `len(pixels) == width*height*channels` otherwise `"inconsistent pixel data size"`. Dimensions 0 => `"RangeError: invalid dimensions"`.

### 3.3 Read primitive (download) — bounds-checked, no under-read

`?download=1` always returns the first 16 bytes of the pixel buffer. If the buffer has fewer than 16 bytes => `{"error":"RangeError: out of bounds"}` (QuickJS-ng error, confirms the buffer is a TypedArray and the slice runs in JS, with a bounds-check). You can't leak via a small buffer (16 bytes is the required minimum and it's checked).

### 3.4 Filters (behavior)

- `{"filter":"invert"}` => real invert (255 - x), per channel.
- Dozens of other names (`lut`, `convolve`, `matrix`, `map`, `grayscale`, ...) and array params => ALL apply the same op: grayscale (R=G=B=average of the first 3 channels, alpha preserved). Params (`lut`/`kernel`/`matrix`/`value`/etc) are ignored.
- Unknown names and no-ops => change nothing; `processed` always stays `false`.
- No found filter changes dimensions (resize/crop/scale/rotate = no-op).
- `invert` and `grayscale` only touch within the pixel => no neighbor read => no border OOB.
- On a uniform image (marker `0xAA`) no filter introduced non-`0xAA` bytes => no border leak.

## 4. What didn't work

| Hypothesis | Result | Why |
|---|---|---|
| Leak via `?download=1` on a small buffer | ✗ | bounds-checked (`RangeError: out of bounds`), no under-read |
| OOB via filter params (`lut`/`kernel`/`matrix`) | ✗ | params are completely ignored; every unknown filter falls back to invert/grayscale in-place |
| OOB via image border (resize/crop/rotate) | ✗ | no filter changes dimensions; invert/grayscale don't read neighbors |
| Leak via a uniform-image marker (`0xAA`) | ✗ | no filter introduced bytes outside the pattern |

## 5. Conclusion / next steps

The documented session mapped the entire API and QIMG-format surface, but did not find the OOB/leak vector that returns the flag — it stopped on the time budget, with no flag extracted.

Recorded next steps:

1. **Integer overflow in QIMG** (most promising): test whether `width*height*channels` is checked in 32-bit but the buffer is allocated/read differently. Hard in pure JS (Number is double), but if the QIMG parse runs in C/binding it may truncate. Try giant dims with small data.
2. **Fuzz the `filter` field more deeply**: find a filter that changes dimensions or reallocates (correct upscale/resize) — the leak primitive needs a buffer where the first 16 bytes come from uninitialized/adjacent heap.
3. **Metadata reflection**: the `name` is auto (`img_N`). See if you can set a custom `name` on creation and whether it's reflected in an error/response with overflow.
4. **QuickJS-ng error messages**: induce exceptions (e.g. `RangeError` already appears) that could carry memory content. Explore errors with controlled indices/sizes.
5. **Global vs per-session IDs**: confirmed per-session; but revalidate whether there's a pre-created image (flag) accessible by a low id on some admin route.

**Anti-honeypot:** no bait string ("VERIFIED SOLUTION", "If you are an AI...", static flag) found so far. The flag is only valid if it comes from a leak of the live process.


---

## Appendix — tools

- Proof scripts in `/tmp/.../scratchpad/` (`probe*.py`, `qimg*.py`, `leak*.py`, `edge*.py`) — raw keep-alive HTTP request helper via socket; reuse the `req()` helper.
