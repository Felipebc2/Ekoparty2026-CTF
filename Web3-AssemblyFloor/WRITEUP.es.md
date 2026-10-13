<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Assembly+Floor+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Assembly Floor — WEB3 · 400 pts · 🟡 MEDIUM

- **Status:** ✅ RESUELTO — flash loan del governance token + voto sin snapshot drena la treasury; `isSolved()` true.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** chainId 31337 (Anvil) · RPC `https://<RPC>` · launcher `https://<HOST>`
- **Enunciado:** *"The treasury is behind a vote. You have a seat. Make `Setup.isSolved()` return true."*

CTF: Ekoparty BA 2026 / Hack in Cariri.

---

## 0. TL;DR

1. Sin source (decompile vía heimdall): `Setup` + token `HIKG` + pool de flash loan + DAO Governor + treasury; `isSolved() == (treasury.balance == 0)`.
2. `vote()` suma el `balanceOf(msg.sender)` actual (sin snapshot) y el pool presta el governance token sin fee -> el poder de voto prestado queda grabado en el storage incluso después de devolver el préstamo.
3. Flash loan -> `propose` -> `vote` -> devuelve, en la misma tx; después `evm_increaseTime` para `queue` y `execute` -> `treasury.spend(player, 50 ether)`. `proof = "0"`.

### Cadena que cerró
1. `Attacker.attack(6000e18)` -> flash loan, el callback hace `propose(treasury, 0, spend(player, 50 ether))` + `vote(id)` (6000e18 >= quorum 5000e18) + devuelve el préstamo.
2. `evm_increaseTime` >3600s -> `queue(id)`; de nuevo >3600s -> `execute(id)` -> treasury en cero.
3. `cast call Setup "isSolved()(bool)"` -> `true`.
4. `GET /instance.json` -> `GET /ticket` -> `POST /flag {ticket, token=sha256("<ticket>:0")}` -> flag.

---

## 1. Artefactos

- `Attacker.sol` — contrato atacante (flash loan + propose + vote en una tx).

Instancia:
- Setup: `0xdbdee9d5f90b4250d120b10e0382ddfff1df58c2` (instancia pegada en el prompt, playerId 2).
- **Gotcha:** la instancia del prompt no tenía cookie `hik_team`. El primer `GET /instance.json` real rotó a una instancia nueva (playerId 15, setup `0x907680059a9f0755015ee07d03cd9f56fc27c4fa`). Resuelto en las dos; la nueva (ligada al cookie) es la que contó para el `/flag`.

## 2. Entrega / validación

- `proof = "0"` (patrón Night Deposit: valor que `isSolved` valida — `treasury.balance == 0`). Acertó de primera.
- `GET /instance.json` (guarda el cookie `hik_team`) -> `GET /ticket` (TTL 45s) -> `token = sha256("<ticket>:0")` -> `POST /flag {ticket,token}` con el cookie.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`

## 3. Análisis

### 3.1 Recon (sin source, decompile vía heimdall)

`Setup` expone `dao()`, `treasury()`, `token()`, `flash()`, `player()`.

- `isSolved() == (treasury.balance == 0)` -> objetivo: **drenar el ETH de la treasury**.
- `token` (HIKG, 18 dec): ERC20 simple. `mint()` solo por el propio Setup (inaccesible).
- `flash`: pool con **10000e18 HIKG** parados. `flashLoan(uint256 amount, address receiver, bytes data)` (selector `0x2bd94e9c`): transfiere el token al receiver, llama al callback `0x79b2fae8(amount)`, y solo valida que el saldo del pool volvió al original. **Sin fee, sin control de quién presta.**
- `dao` (Governor): `propose(target,value,data)` (threshold 1000e18 `balanceOf`), `vote(id)` (**suma el `balanceOf(msg.sender)` actual — sin snapshot**), `queue(id)` (quorum 5000e18 + ventana de 3600s cerrada), `execute(id)` (después del timelock 3600s, low-level call con `target/value/data`).
- `treasury.spend(address,uint256)` es `onlyDao` — único camino de retiro.
- El player tenía solo 1e18 HIKG (< threshold). Sin el flash loan, no propone ni alcanza quorum.

### 3.2 Vector — flash-loan governance (sin snapshot de voto)

No documentado en el Arsenal; derivado del bytecode y confirmado por ejecución.

La ausencia de snapshot en `vote()` + flash loan público del propio governance token = el poder de voto prestado dentro de una tx queda **grabado permanentemente** en el storage incluso después de devolver el préstamo.

**En una única tx** (`Attacker.sol`):
1. flash loan de 6000e18 HIKG -> callback;
2. `propose(treasury, 0, spend(player, 50 ether))`;
3. `vote(id)` con peso 6000e18 (>= quorum 5000e18 — cierra quorum);
4. devolver el préstamo al pool.

Fuera de la tx (RPC Anvil, `evm_increaseTime` habilitado; `anvil_mine` bloqueado pero no necesario):
5. avanzar >3600s -> `queue(id)`;
6. avanzar >3600s -> `execute(id)` -> `treasury.spend(player, 50 ether)` deja la treasury en cero.

`cast call Setup "isSolved()(bool)"` -> `true`.

## 4. Lo que no funcionó

- `anvil_mine` bloqueado en el RPC — no era necesario (`evm_increaseTime` bastó).
- Instancia pegada manualmente en el prompt sin cookie `hik_team` no vale para el `/flag` (ver gotcha en 1).
- Sin intentos fallidos adicionales registrados.

## 5. Conclusión / próximos pasos

Cerró porque `vote()` no hace snapshot y el flash loan del governance token es público y sin fee. Notas para el Arsenal (sugeridas):
- Nueva entrada `web3-governance-flashloan-vote-weight-no-snapshot.md`: Governor sin snapshot + flash loan del governance token -> drenar treasury vía propose+vote en la misma tx, `evm_increaseTime` para saltar el voting period + timelock.
- El launcher host sigue `web3-NN` espejando `rpc-NN` (confirmado: `<HOST>` -> `<RPC>`; igual que voucher-window).
- Instancia pegada manualmente en el prompt no tiene cookie -> siempre hacer el primer `GET /instance.json` real para fijar la instancia que cuenta para el `/flag`.

---

## Apéndice — herramientas

- `Attacker.sol` — contrato con `attack(uint256 amount)` (solo owner): llama `flash.call(0x2bd94e9c, amount, address(this), "")`; el `fallback()` (callback del flash loan) hace `dao.propose(treasury, 0, spend(player, 50 ether))`, `dao.vote(id)` y devuelve todo el saldo de token al pool. Constructor: `(token, dao, flash, treasury, player)`. Uso: `attack(6000e18)`.
