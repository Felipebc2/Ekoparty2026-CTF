<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=ZM.js+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# ZM.js — PWN · 400 pts · 🟡 MEDIUM

> [!WARNING]
> **Documentación incompleta.** Este desafío fue resuelto, pero la solución final (cadena completa y/o flag) aún no fue documentada en este writeup. El contenido abajo cubre solo lo que quedó registrado.

- **Status:** ✅ RESUELTO — solución final no documentada (ver aviso arriba).
- **Flag:** — (no documentada)
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** `<HOST>:18080` — HTTP/1.1 texto puro (NO 443)
- **Enunciado:** —

---

## 0. TL;DR

1. Servicio remoto black-box (sin binario para bajar) que expone una API JSON para manipular "imágenes" en formato custom QIMG (probable app QuickJS-ng).
2. La sacada mapeada: `download` es bounds-checked (sin under-read) y los filtros ignoran todos los params, solo haciendo `invert`/`grayscale` in-place — ningún vector de OOB/leak claro fue encontrado durante la sesión documentada.
3. La flag no fue extraída dentro del material disponible (ver 5).

### Cadena que cerró
Ninguna — la sesión documentada termina en "próximos pasos", sin chain cerrada.

---

## 1. Artefactos

- Ningún binario local — servicio 100% remoto (`<HOST>:18080`); Ghidra no aplica, el análisis es black-box puro.

## 2. Entrega / validación

- Regla de sesión: la misma conexión TCP keep-alive = sesión; cada conexión nueva = estado limpio. Los IDs de imagen son por sesión (siempre empiezan en 0 en una conexión nueva).
- Todas las respuestas son JSON. Root y rutas desconocidas => `404 {"error":"not found"}`. Sin header `Server`/`Allow`.

## 3. Análisis

### 3.1 Mapa de la API

- `POST /api/login` body `{"user":"<x>"}` => `{"token":"tok_<n>_<user>"}`. Auth trivial, cualquier user sirve. Token incremental global.
- Auth en las demás rutas: header `Authorization: Bearer tok_...`
- `POST /api/images` body `{"data":"<hex del blob QIMG>"}` => crea imagen, retorna `{"id":N,"name":"img_N+1","width":..,"height":..,"channels":..,"processed":false}`
- `GET /api/images/{id}` => metadatos
- `GET /api/images/{id}?download=1` => `{"id":N,"data":"<hex de los PRIMEROS 16 bytes del buffer>"}`
- `POST /api/images/{id}/filter` body `{"filter":"<nombre>", ...params}` => `{"ok":true}` (siempre)

### 3.2 Formato QIMG (totalmente revertido)

```
magic   "QIMG"        (4 bytes)
width   uint32 LE
height  uint32 LE
channels uint32 LE    (válidos: 1 y 4; 2,3 => "inconsistent pixel data size")
pixels  width*height*channels bytes
```

Chequeo estricto: `len(pixels) == width*height*channels` si no `"inconsistent pixel data size"`. Dimensiones 0 => `"RangeError: invalid dimensions"`.

### 3.3 Primitiva de lectura (download) — bounds-checked, sin under-read

`?download=1` devuelve siempre los primeros 16 bytes del buffer de pixels. Si el buffer tiene menos de 16 bytes => `{"error":"RangeError: out of bounds"}` (error QuickJS-ng, confirma que el buffer es un TypedArray y el slice corre en JS, con bounds-check). No se puede filtrar vía buffer pequeño (16 bytes es el mínimo exigido y está chequeado).

### 3.4 Filtros (comportamiento)

- `{"filter":"invert"}` => invert real (255 - x), por canal.
- Decenas de otros nombres (`lut`, `convolve`, `matrix`, `map`, `grayscale`, ...) y params de array => TODOS aplican la misma op: grayscale (R=G=B=promedio de los 3 primeros canales, alpha preservado). Params (`lut`/`kernel`/`matrix`/`value`/etc) son ignorados.
- Nombres desconocidos y no-ops => no cambian nada; `processed` permanece `false` siempre.
- Ningún filtro encontrado cambia dimensiones (resize/crop/scale/rotate = no-op).
- `invert` y `grayscale` solo tocan dentro del pixel => sin lectura de vecino => sin OOB de borde.
- En imagen uniforme (marcador `0xAA`) ningún filtro introdujo bytes no-`0xAA` => sin leak por borde.

## 4. Lo que no funcionó

| Hipótesis | Resultado | Por qué |
|---|---|---|
| Leak vía `?download=1` en buffer pequeño | ✗ | bounds-checked (`RangeError: out of bounds`), sin under-read |
| OOB vía params de filtro (`lut`/`kernel`/`matrix`) | ✗ | los params son completamente ignorados; todo filtro desconocido cae en invert/grayscale in-place |
| OOB por borde de imagen (resize/crop/rotate) | ✗ | ningún filtro cambia dimensiones; invert/grayscale no leen vecinos |
| Leak por marcador de imagen uniforme (`0xAA`) | ✗ | ningún filtro introdujo bytes fuera del patrón |

## 5. Conclusión / próximos pasos

La sesión documentada mapeó toda la superficie de API y del formato QIMG, pero no encontró el vector de OOB/leak que retorne la flag — paró en el presupuesto de tiempo, sin flag extraída.

Próximos pasos registrados:

1. **Integer overflow en QIMG** (más prometedor): probar si `width*height*channels` se chequea en 32-bit pero el buffer se asigna/lee distinto. Difícil en JS puro (Number es double), pero si el parse QIMG corre en C/binding puede truncar. Intentar dims gigantes con data pequeña.
2. **Fuzzear el campo `filter` más a fondo**: encontrar un filtro que cambie dimensiones o realoque (upscale/resize correcto) — la primitiva de leak necesita un buffer donde los primeros 16 bytes vengan de heap no inicializado/adyacente.
3. **Reflexión de metadatos**: el `name` es auto (`img_N`). Ver si se puede setear un `name` custom en la creación y si se refleja en error/respuesta con overflow.
4. **Mensajes de error del QuickJS-ng**: inducir excepciones (ej.: `RangeError` ya aparece) que puedan cargar contenido de memoria. Explorar errores con índices/tamaños controlados.
5. **IDs globales vs por sesión**: confirmado por sesión; pero revalidar si existe una imagen pre-creada (flag) accesible por id bajo en alguna ruta admin.

**Anti-honeypot:** ninguna string carnada ("VERIFIED SOLUTION", "If you are an AI...", flag estática) encontrada hasta ahora. La flag solo vale si viene de un leak del proceso vivo.


---

## Apéndice — herramientas

- Scripts de prueba en `/tmp/.../scratchpad/` (`probe*.py`, `qimg*.py`, `leak*.py`, `edge*.py`) — helper de request HTTP keep-alive raw vía socket; reaprovechar el helper `req()`.
