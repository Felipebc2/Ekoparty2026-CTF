<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=ZM.js+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <a href="WRITEUP.es.md">Español</a> · <b>Português (BR)</b></p>

# ZM.js — PWN · 400 pts · 🟡 MEDIUM

> [!WARNING]
> **Documentação incompleta.** Este desafio foi resolvido, mas a solução final (cadeia completa e/ou flag) ainda não foi documentada neste writeup. O conteúdo abaixo cobre apenas o que ficou registrado.

- **Status:** ✅ RESOLVIDO — solução final não documentada (ver aviso acima).
- **Flag:** — (não documentada)
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** `<HOST>:18080` — HTTP/1.1 texto puro (NÃO 443)
- **Enunciado:** —

---

## 0. TL;DR

1. Serviço remoto black-box (sem binário pra baixar) que expõe uma API JSON para manipular "imagens" em formato custom QIMG (provável app QuickJS-ng).
2. A sacada mapeada: `download` é bounds-checked (sem under-read) e os filtros ignoram todos os params, só fazendo `invert`/`grayscale` in-place — nenhum vetor de OOB/leak claro foi encontrado durante a sessão documentada.
3. A flag não foi extraída dentro do material disponível (ver 5).

### Cadeia que fechou
Nenhuma — a sessão documentada termina em "próximos passos", sem chain fechada.

---

## 1. Artefatos

- Nenhum binário local — serviço 100% remoto (`<HOST>:18080`); Ghidra não se aplica, análise é black-box puro.

## 2. Entrega / validação

- Regra de sessão: mesma conexão TCP keep-alive = sessão; cada conexão nova = estado limpo. IDs de imagem são por-sessão (sempre começam em 0 numa conexão nova).
- Todas as respostas são JSON. Root e rotas desconhecidas => `404 {"error":"not found"}`. Sem header `Server`/`Allow`.

## 3. Análise

### 3.1 Mapa da API

- `POST /api/login` body `{"user":"<x>"}` => `{"token":"tok_<n>_<user>"}`. Auth trivial, qualquer user serve. Token incremental global.
- Auth nas demais rotas: header `Authorization: Bearer tok_...`
- `POST /api/images` body `{"data":"<hex do blob QIMG>"}` => cria imagem, retorna `{"id":N,"name":"img_N+1","width":..,"height":..,"channels":..,"processed":false}`
- `GET /api/images/{id}` => metadados
- `GET /api/images/{id}?download=1` => `{"id":N,"data":"<hex dos PRIMEIROS 16 bytes do buffer>"}`
- `POST /api/images/{id}/filter` body `{"filter":"<nome>", ...params}` => `{"ok":true}` (sempre)

### 3.2 Formato QIMG (totalmente revertido)

```
magic   "QIMG"        (4 bytes)
width   uint32 LE
height  uint32 LE
channels uint32 LE    (válidos: 1 e 4; 2,3 => "inconsistent pixel data size")
pixels  width*height*channels bytes
```

Checagem estrita: `len(pixels) == width*height*channels` senão `"inconsistent pixel data size"`. Dimensões 0 => `"RangeError: invalid dimensions"`.

### 3.3 Primitiva de leitura (download) — bounds-checked, sem under-read

`?download=1` devolve sempre os primeiros 16 bytes do buffer de pixels. Se o buffer tem menos de 16 bytes => `{"error":"RangeError: out of bounds"}` (erro QuickJS-ng, confirma que o buffer é um TypedArray e o slice roda em JS, com bounds-check). Não dá pra vazar via buffer pequeno (16 bytes é o mínimo exigido e é checado).

### 3.4 Filtros (comportamento)

- `{"filter":"invert"}` => invert real (255 - x), por canal.
- Dezenas de outros nomes (`lut`, `convolve`, `matrix`, `map`, `grayscale`, ...) e params de array => TODOS aplicam a mesma op: grayscale (R=G=B=média dos 3 primeiros canais, alpha preservado). Params (`lut`/`kernel`/`matrix`/`value`/etc) são ignorados.
- Nomes desconhecidos e no-ops => não mudam nada; `processed` permanece `false` sempre.
- Nenhum filtro encontrado muda dimensões (resize/crop/scale/rotate = no-op).
- `invert` e `grayscale` só tocam dentro do pixel => sem leitura de vizinho => sem OOB de borda.
- Em imagem uniforme (marcador `0xAA`) nenhum filtro introduziu bytes não-`0xAA` => sem leak por borda.

## 4. O que não funcionou

| Hipótese | Resultado | Por quê |
|---|---|---|
| Leak via `?download=1` em buffer pequeno | ✗ | bounds-checked (`RangeError: out of bounds`), sem under-read |
| OOB via params de filtro (`lut`/`kernel`/`matrix`) | ✗ | params são completamente ignorados; todo filtro desconhecido cai em invert/grayscale in-place |
| OOB por borda de imagem (resize/crop/rotate) | ✗ | nenhum filtro muda dimensões; invert/grayscale não leem vizinhos |
| Leak por marcador de imagem uniforme (`0xAA`) | ✗ | nenhum filtro introduziu bytes fora do padrão |

## 5. Conclusão / próximos passos

A sessão documentada mapeou toda a superfície de API e do formato QIMG, mas não achou o vetor de OOB/leak que retorne a flag — parou no orçamento de tempo, sem flag extraída.

Próximos passos registrados:

1. **Integer overflow no QIMG** (mais promissor): testar se `width*height*channels` é checado em 32-bit mas o buffer é alocado/lido diferente. Difícil em JS puro (Number é double), mas se o parse QIMG roda em C/binding pode truncar. Tentar dims gigantes com data pequena.
2. **Fuzzar o campo `filter` mais a fundo**: achar um filtro que mude dimensões ou realoque (upscale/resize correto) — a primitiva de leak precisa de um buffer onde os 16 primeiros bytes venham de heap não-inicializado/adjacente.
3. **Reflexão de metadados**: o `name` é auto (`img_N`). Ver se dá pra setar `name` custom na criação e se é refletido em erro/resposta com overflow.
4. **Mensagens de erro do QuickJS-ng**: induzir exceções (ex.: `RangeError` já aparece) que possam carregar conteúdo de memória. Explorar erros com índices/tamanhos controlados.
5. **IDs globais vs por-sessão**: confirmado por-sessão; mas revalidar se existe imagem pré-criada (flag) acessível por id baixo em alguma rota admin.

**Anti-honeypot:** nenhuma string isca ("VERIFIED SOLUTION", "If you are an AI...", flag estática) encontrada até agora. Flag só vale se vier de leak do processo vivo.


---

## Apêndice — ferramentas

- Scripts de prova em `/tmp/.../scratchpad/` (`probe*.py`, `qimg*.py`, `leak*.py`, `edge*.py`) — helper de request HTTP keep-alive raw via socket; reaproveitar o helper `req()`.
