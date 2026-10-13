<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Duty+Roster+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <a href="WRITEUP.es.md">Español</a> · <b>Português (BR)</b></p>

# Duty Roster — NET (Packet) · 350 pts · 🟡 MEDIUM

> [!WARNING]
> **Documentação incompleta.** Este desafio foi resolvido, mas a solução final (cadeia completa e/ou flag) ainda não foi documentada neste writeup. O conteúdo abaixo cobre apenas o que ficou registrado.

- **Status:** ✅ RESOLVIDO — solução final não documentada (ver aviso acima).
- **Flag:** — (não documentada)
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** `nc <IP> 16007`
- **Enunciado:** *"Identify who, where, which port, and how often."* (conforme comentário no `solve.py`)

---

## 0. TL;DR

1. Desafio da família **Packet**: um harness com `capture`/`getpcap`/`submit` sobre uma sessão TCP, que captura um pcap sintético de um "beacon" (tráfego TCP repetitivo) e espera que a resposta (`answer`) identifique os metadados **estruturais** desse beacon — não o payload.
2. O enunciado nomeia 4 itens: **who** (IP de origem), **where** (IP de destino), **port** (porta TCP de destino) e **how often** (intervalo entre os beacons).
3. `answer` vencedora: `who:where:port:interval`, com `who`/`where` = IPs, `port` = porta TCP, `interval` = mediana do intervalo entre pacotes `SYN` do beacon, em segundos.
4. `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_texto))`, testado com 2 variantes de hash do pcap (texto base64 e bytes raw) na mesma sessão TCP.
5. Este diretório preserva o script (`solve.py`) como **pedra de Roseta** da família Packet — a mesma lógica de "nomear os itens do enunciado, juntar por `:`" foi reaplicada (sem sucesso) em `Background Noise`.

### Cadeia que fechou (conforme comentários do script)
1. Conectar, ler `sid` do banner
2. `capture 30` -> `getpcap` -> decodificar base64 -> pcap
3. `tshark` sobre o pcap: achar streams `SYN` repetidos (`tcp.flags.syn==1 && tcp.flags.ack==0`), agrupar por `(src, dst, dstport)`, calcular mediana do intervalo entre aberturas
4. Montar candidatos de `answer` a partir de `who:where:port:interval` (várias formatações de separador e do intervalo)
5. `submit sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64))` em loop, até a resposta conter `HIK`

---

## 1. Artefatos

- `solve.py` — único artefato presente neste diretório. Comentário no topo do arquivo documenta a convenção de `answer` descoberta; o próprio código foi copiado e adaptado (dunders reconstruídos, regex do `getpcap` ajustada) para reuso como harness de outros desafios da família Packet.

## 2. Entrega / validação

- Harness de sessão TCP (`<IP>:16007`): banner com `sid <32hex>`, comandos incluindo `capture [sec]`, `getpcap`, `submit <proof>`.
- `getpcap` devolve o pcap entre marcadores `BEGIN PCAP`/`END PCAP`, em base64.
- `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_texto_sem_ws))`. O script testa essa variante e também o hash sobre os bytes raw decodificados, na mesma sessão.

## 3. Análise

### 3.1 Convenção de `answer` da família Packet
Comentário no `solve.py`:

> "Pedra de Roseta da família PACKET: o answer = os itens que o enunciado nomeia, juntados por ':', ESTRUTURAIS (metadados do stream que faz beacon), NÃO o payload."

Para Duty Roster, o enunciado ("Identify who, where, which port, and how often.") nomeia:
- `who` = IP de origem do beacon
- `where` = IP de destino
- `port` = porta TCP de destino
- `how often` = mediana do intervalo entre aberturas `SYN` (em segundos)

Formato vencedor provável: `who:where:port:interval` (separador `:`, interval em formato tipo `"5s"`/`"5"`).

### 3.2 Derivação dos streams (via `tshark`)
`derive_streams()` roda duas passagens de `tshark` sobre o pcap decodificado:
1. Filtro `tcp.flags.syn==1 && tcp.flags.ack==0`, extraindo `frame.time_relative`, `ip.src`, `ip.dst`, `tcp.dstport` — agrupa por `(src, dst, dstport)` e calcula a mediana dos deltas entre tempos consecutivos de abertura.
2. Filtro `tcp.len>0`, para estimar o volume de dados por stream (`client_data`), usado apenas como contexto/ordenação.

Os streams são ordenados por `count` (nº de SYNs) decrescente; os que repetem (`count>=3`) são os candidatos a "beacon".

### 3.3 Geração de candidatos e submissão
`build_candidates()` gera várias formatações de `who`, `where`, `port` e `interval` (inteiro, com `s`/`sec`/`ms`/`seconds`, com `.0`, etc.) combinadas com separadores (`:`, espaço, vírgula, `>`, `|`, `/`, `-`), priorizando formatos com 2-3 ocorrências de `:` (mais prováveis pelo padrão `who:where:port[:interval]`).

Para cada candidato, testa `proof` com o hash do pcap em 2 formas (texto base64 `h_b64` e bytes raw `h_raw`), dentro de um budget de ~108s de submits na mesma sessão TCP, parando no primeiro `HIK` encontrado na resposta.

## 4. O que não funcionou

Não documentado nos artefatos deste diretório — o script só registra a lógica final (já ajustada para o formato vencedor) e não preserva o histórico de tentativas anteriores.

## 5. Conclusão / próximos passos

O desafio foi resolvido usando a convenção `who:where:port:interval`, mas a flag em si e o log completo da sessão de resolução não foram preservados neste diretório — só o script final. Este writeup documenta o que é recuperável de `solve.py`: o protocolo, a lógica de derivação dos streams via `tshark` e a construção/submissão dos candidatos de `answer`. Se a flag for necessária novamente, rodar `solve.py` contra uma nova sessão do desafio (se ainda ativo) deve reproduzi-la.

---

## Apêndice — ferramentas

- `solve.py` — `python3 solve.py`: conecta no harness, captura o pcap, deriva streams de beacon via `tshark`, gera candidatos de `answer` no formato `who:where:port:interval` e testa `submit` em loop até achar `HIK` na resposta (grava `FLAG.txt` no diretório se encontrar).
