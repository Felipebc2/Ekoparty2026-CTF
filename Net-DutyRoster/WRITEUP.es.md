<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Duty+Roster+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Duty Roster — NET (Packet) · 350 pts · 🟡 MEDIUM

> [!WARNING]
> **Documentación incompleta.** Este desafío fue resuelto, pero la solución final (cadena completa y/o flag) aún no fue documentada en este writeup. El contenido de abajo cubre solo lo que quedó registrado.

- **Status:** ✅ RESUELTO — solución final no documentada (ver aviso arriba).
- **Flag:** — (no documentada)
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `nc <IP> 16007`
- **Enunciado:** *"Identify who, where, which port, and how often."* (según el comentario en `solve.py`)

---

## 0. TL;DR

1. Desafío de la familia **Packet**: un harness con `capture`/`getpcap`/`submit` sobre una sesión TCP, que captura un pcap sintético de un "beacon" (tráfico TCP repetitivo) y espera que la respuesta (`answer`) identifique los metadatos **estructurales** de ese beacon — no el payload.
2. El enunciado nombra 4 ítems: **who** (IP de origen), **where** (IP de destino), **port** (puerto TCP de destino) y **how often** (intervalo entre los beacons).
3. `answer` ganadora: `who:where:port:interval`, con `who`/`where` = IPs, `port` = puerto TCP, `interval` = mediana del intervalo entre los paquetes `SYN` del beacon, en segundos.
4. `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_texto))`, probado con 2 variantes de hash del pcap (texto base64 y bytes raw) en la misma sesión TCP.
5. Este directorio preserva el script (`solve.py`) como **piedra de Rosetta** de la familia Packet — la misma lógica de "nombrar los ítems del enunciado, unir por `:`" fue reaplicada (sin éxito) en `Background Noise`.

### Cadena que cerró (según los comentarios del script)
1. Conectar, leer `sid` del banner
2. `capture 30` -> `getpcap` -> decodificar base64 -> pcap
3. `tshark` sobre el pcap: encontrar streams `SYN` repetidos (`tcp.flags.syn==1 && tcp.flags.ack==0`), agrupar por `(src, dst, dstport)`, calcular la mediana del intervalo entre aperturas
4. Armar candidatos de `answer` a partir de `who:where:port:interval` (varias formataciones del separador y del intervalo)
5. `submit sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64))` en loop, hasta que la respuesta contenga `HIK`

---

## 1. Artefactos

- `solve.py` — único artefacto presente en este directorio. Un comentario en la cabecera del archivo documenta la convención de `answer` descubierta; el propio código fue copiado y adaptado (dunders reconstruidos, regex del `getpcap` ajustada) para reuso como harness de otros desafíos de la familia Packet.

## 2. Entrega / validación

- Harness de sesión TCP (`<IP>:16007`): banner con `sid <32hex>`, comandos incluyendo `capture [sec]`, `getpcap`, `submit <proof>`.
- `getpcap` devuelve el pcap entre los marcadores `BEGIN PCAP`/`END PCAP`, en base64.
- `proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_texto_sin_ws))`. El script prueba esa variante y también el hash sobre los bytes raw decodificados, en la misma sesión.

## 3. Análisis

### 3.1 La convención de `answer` de la familia Packet
Comentario en `solve.py`:

> "Piedra de Rosetta de la familia PACKET: answer = los ítems que el enunciado nombra, unidos por ':', ESTRUCTURALES (metadatos del stream que hace beacon), NO el payload."

Para Duty Roster, el enunciado ("Identify who, where, which port, and how often.") nombra:
- `who` = IP de origen del beacon
- `where` = IP de destino
- `port` = puerto TCP de destino
- `how often` = mediana del intervalo entre las aperturas `SYN` (en segundos)

Formato ganador probable: `who:where:port:interval` (separador `:`, interval en un formato tipo `"5s"`/`"5"`).

### 3.2 Derivación de los streams (vía `tshark`)
`derive_streams()` corre dos pasadas de `tshark` sobre el pcap decodificado:
1. Filtro `tcp.flags.syn==1 && tcp.flags.ack==0`, extrayendo `frame.time_relative`, `ip.src`, `ip.dst`, `tcp.dstport` — agrupa por `(src, dst, dstport)` y calcula la mediana de los deltas entre tiempos consecutivos de apertura.
2. Filtro `tcp.len>0`, para estimar el volumen de datos por stream (`client_data`), usado solo como contexto/ordenamiento.

Los streams se ordenan por `count` (nº de SYNs) descendente; los que repiten (`count>=3`) son los candidatos a "beacon".

### 3.3 Generación de candidatos y envío
`build_candidates()` genera varias formataciones de `who`, `where`, `port` e `interval` (entero, con `s`/`sec`/`ms`/`seconds`, con `.0`, etc.) combinadas con separadores (`:`, espacio, coma, `>`, `|`, `/`, `-`), priorizando formatos con 2-3 ocurrencias de `:` (más probables por el patrón `who:where:port[:interval]`).

Para cada candidato, prueba `proof` con el hash del pcap en 2 formas (texto base64 `h_b64` y bytes raw `h_raw`), dentro de un budget de ~108s de submits en la misma sesión TCP, deteniéndose en el primer `HIK` encontrado en la respuesta.

## 4. Lo que no funcionó

No documentado en los artefactos de este directorio — el script solo registra la lógica final (ya ajustada para el formato ganador) y no preserva el historial de intentos anteriores.

## 5. Conclusión / próximos pasos

El desafío fue resuelto usando la convención `who:where:port:interval`, pero la flag en sí y el log completo de la sesión de resolución no fueron preservados en este directorio — solo el script final. Este writeup documenta lo que es recuperable de `solve.py`: el protocolo, la lógica de derivación de los streams vía `tshark` y la construcción/envío de los candidatos de `answer`. Si la flag fuera necesaria de nuevo, correr `solve.py` contra una nueva sesión del desafío (si sigue activo) debería reproducirla.

---

## Apéndice — herramientas

- `solve.py` — `python3 solve.py`: conecta al harness, captura el pcap, deriva streams de beacon vía `tshark`, genera candidatos de `answer` en el formato `who:where:port:interval` y prueba `submit` en loop hasta encontrar `HIK` en la respuesta (graba `FLAG.txt` en el directorio si lo encuentra).
