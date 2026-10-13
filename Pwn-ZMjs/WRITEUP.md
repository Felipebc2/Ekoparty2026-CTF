# ZM.js — Binary Exploitation (400 pts, HARD)

Status: EM ANDAMENTO — superfície mapeada, flag NÃO extraída (parei no orçamento de tempo).
Alvo: `<HOST>:18080` — HTTP/1.1 texto puro (NÃO 443).
Regra: mesma conexão TCP keep-alive = sessão. Cada conexão nova = estado limpo. IDs de imagem
são por-sessão (sempre começam em 0 numa conexão nova).
NOTA: não há binário pra baixar (serviço remoto) — Ghidra NÃO se aplica, é black-box puro.

## O que FUNCIONOU (mapa da API)

Todas as respostas são JSON. Root e rotas desconhecidas => 404 `{"error":"not found"}`.
Sem header Server/Allow. Servidor custom (provável app QuickJS-ng).

Rotas descobertas:
- `POST /api/login`  body `{"user":"<x>"}`  => `{"token":"tok_<n>_<user>"}`. Auth trivial,
  qualquer user serve. Token incremental global.
- Auth nas demais rotas: header `Authorization: Bearer tok_...`
- `POST /api/images`  body `{"data":"<hex do blob QIMG>"}` => cria imagem,
  retorna `{"id":N,"name":"img_N+1","width":..,"height":..,"channels":..,"processed":false}`
- `GET  /api/images/{id}`  => metadados
- `GET  /api/images/{id}?download=1` => `{"id":N,"data":"<hex dos PRIMEIROS 16 bytes do buffer>"}`
- `POST /api/images/{id}/filter`  body `{"filter":"<nome>", ...params}` => `{"ok":true}` (sempre)

## Formato QIMG (totalmente revertido)

```
magic   "QIMG"        (4 bytes)
width   uint32 LE
height  uint32 LE
channels uint32 LE    (válidos: 1 e 4; 2,3 => "inconsistent pixel data size")
pixels  width*height*channels bytes
```
Checagem estrita: `len(pixels) == width*height*channels` senão "inconsistent pixel data size".
Dimensões 0 => "RangeError: invalid dimensions".

## Primitiva de leitura (download) — bounds-checked, SEM under-read

`?download=1` devolve SEMPRE os **primeiros 16 bytes** do buffer de pixels.
Se o buffer tem < 16 bytes => `{"error":"RangeError: out of bounds"}` (erro QuickJS-ng,
confirma que o buffer é um TypedArray e o slice roda em JS, com bounds-check).
=> NÃO dá pra vazar via buffer pequeno (16 bytes é o mínimo exigido e é checado).

## Filtros (comportamento)

- `{"filter":"invert"}` => invert real (255 - x), por canal.
- Dezenas de outros nomes ("lut","convolve","matrix","map","grayscale",...) e params de array
  => TODOS aplicam a MESMA op: **grayscale** (R=G=B=média dos 3 primeiros canais, alpha preservado).
  Params (lut/kernel/matrix/value/etc) são IGNORADOS.
- Nomes desconhecidos e no-ops => não mudam nada; `processed` permanece `false` sempre.
- Nenhum filtro encontrado muda dimensões (resize/crop/scale/rotate = no-op).
- invert e grayscale só tocam dentro do pixel => sem leitura de vizinho => sem OOB de borda.
- Em imagem uniforme (marcador 0xAA) nenhum filtro introduziu bytes não-0xAA => sem leak por borda.

## O que TRAVOU / impedimentos

Mapeei toda a superfície mas não achei o vetor de OOB/leak que retorne a flag:
- download é bounds-checked (16 bytes, min 16) — sem under-read.
- filtros ignoram params e só fazem invert/grayscale in-place — sem OOB por param nem por borda.
- nenhum filtro de resize/upscale que realoque e copie com leitura além da origem.

## Próximos passos (manual)

1. **Integer overflow no QIMG** (mais promissor): testar se `width*height*channels` é checado em
   32-bit mas o buffer é alocado/lido diferente. Difícil em JS puro (Number é double), mas se o
   parse QIMG roda em C/binding pode truncar. Tentar dims gigantes com data pequena.
2. **Fuzzar o campo filter mais a fundo**: achar um filtro que mude dimensões ou realoque
   (upscale/resize correto) — a primitiva de leak precisa de um buffer onde os 16 primeiros bytes
   venham de heap não-inicializado/adjacente.
3. **Reflexão de metadados**: o `name` é auto ("img_N"). Ver se dá pra setar `name` custom na
   criação e se é refletido em erro/resposta com overflow.
4. **Mensagens de erro do QuickJS-ng**: induzir exceções (ex.: RangeError já aparece) que possam
   carregar conteúdo de memória. Explorar erros com índices/tamanhos controlados.
5. **IDs globais vs por-sessão**: confirmado por-sessão; mas revalidar se existe imagem pré-criada
   (flag) acessível por id baixo em alguma rota admin.

## Scripts de prova
Em `/tmp/.../scratchpad/` (probe*.py, qimg*.py, leak*.py, edge*.py) — helper de request HTTP
keep-alive raw via socket. Reaproveitar o helper `req()`.

## Anti-honeypot
Nenhuma string isca ("VERIFIED SOLUTION", "If you are an AI...", flag estática) encontrada até
agora. Flag só vale se vier de leak do processo vivo.
