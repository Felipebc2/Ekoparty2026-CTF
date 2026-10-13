<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Carcara+Markets+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><a href="WRITEUP.md">English</a> · <b>Español</b> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Carcara Markets — WEB3 · 450 pts · 🔴 HARD

- **Status:** ✅ RESUELTO — exploit punta a punta, flag obtenida.
- **Flag:** `HIK_WEB3_ORACLE_d6036e30b782007df2b879030f515065`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acceso:** RPC `https://<HOST>` · `GET /instance.json` (card de la instancia) · chainId `31337`
- **Enunciado:** *"Tokens, a pool, a price feed, and a lending desk are on chain. Starting balances are on Setup. Make Setup.isSolved() return true."*

---

## 0. TL;DR

1. Setup expone `dex()`, `flash()`, `lending()`, `oracle()`, `player()`, `usd()` — sin source, todo reconstruido vía `cast call` + heimdall decompile.
2. El "oráculo" promete TWAP (`twapPrice()`), pero esa función es una constante decoy; el precio real usado por la lending desk se lee directo del spot price de las reservas del AMM (`0x50e308f6()` = `usdReserve()*1e18/hikReserve()`), sin protección.
3. Flash loan de USD sin fee + swap que pumpea el precio del pool en ~439x + depósito del HIK comprado como colateral + borrow en el LTV inflado drena la lending desk; repaga el flash loan en la misma tx y la flag sale del proof-oracle HTTP.

### Cadena que cerró
1. `flash.flashLoan(1500e18, address(this), "")` -> presta 1500e18 USD sin fee.
2. `dex.call(0x8ac326bd, 1500e18, 0)` (USD-in -> HIK-out) -> las reservas salen de 100/100 y el precio del HIK sube de 1e18 a ~439e18.
3. `lending.depositCollateral(~95.2e18 HIK)` + `lending.borrow(9500e18)` -> LTV 90% sobre colateral con precio inflado permite sacar casi toda la caja de la lending desk.
4. `usd.transfer(flash, 1500e18)` -> repaga el flash loan sin deber nada.
5. `Setup.isSolved()` -> `true` (`usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18`).
6. `GET /ticket` -> `token = sha256(f"{ticket}:500000000000000000000")` -> `POST /flag` -> flag.

---

## 1. Artefactos

- `instance.json` — datos de la instancia fijada (RPC, player, dirección del `Setup`; valores sensibles redactados).
- `setup_code.hex` — bytecode runtime del `Setup`.
- `setup_decompiled/`, `dex_decompiled/`, `lending_decompiled/`, `flash_decompiled/`, `oracle_decompiled/`, `usd_decompiled/`, `hik_decompiled/` — salidas del heimdall (decompile).
- `dex_sol/`, `lending_sol/`, `flash_sol/`, `oracle_sol/`, `setup_sol/` — reconstrucción en Solidity a partir del decompile, usada para escribir el exploit.
- `attacker_proj/` — proyecto Foundry con `src/Attacker.sol` (contrato de exploit).

## 2. Entrega / validación

- `Setup.isSolved()` tiene que retornar `true` on-chain (`usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18`).
- Proof HTTP: `GET /instance.json` (cookie `hik_team`) -> exploit on-chain -> `GET /ticket` (TTL corto) -> `token = sha256(f"{ticket}:{proof}")`, donde `proof` es `usd.balanceOf(lending)` post-exploit, en decimal -> `POST /flag {"ticket","token"}` -> `{"flag": "..."}`.

## 3. Análisis

### 3.1 Arquitectura de los contratos (reversed, sin source)

Setup getters: `dex() flash() lending() oracle() player() usd()`.

- **usd** (`Fake USD`/`fUSD`, 18 dec) — ERC20 "stablecoin", `minter() == Setup`.
- **HIK token** (`0xc49330a5...`) — collateral asset, no expuesto por getter del Setup (hallado vía `Unresolved_23b872dd(msg.sender)` en el bytecode del dex/lending). Player empieza con `100e18` HIK.
- **dex** — AMM constant-product manual (sin LP token): `store_a` = reserva HIK, `store_b` = `usdReserve()`. Fee 0.3% (`997/1000`, igual Uniswap v2). Selectores reales: `0x8ac326bd(amountIn,minOut)` = swap USD-in → HIK-out; `0x1518a0ec(amountIn,minOut)` = swap HIK-in → USD-out; `getAmountOut(amountIn,reserveIn,reserveOut)`; `usdReserve()`; `0x5fad8f7c()` = reserva HIK. Reservas iniciales: `100e18` HIK / `100e18` USD (precio 1:1).
- **oracle** — `twapPrice()` es una constante decoy (siempre `1e18`); la función real (`0x50e308f6()`) lee spot price en vivo: `usdReserve()*1e18/hikReserve()` del dex — sin TWAP de hecho, sin protección.
- **lending** — `depositCollateral(uint256)` (`0xbad4a01f`, pull vía `transferFrom` del HIK), `borrow(uint256)` (`0xc5ebeaec`): `debt[msg.sender]+amt <= LTV_BPS(9000) * collateral*price/1e18 / 10000`, paga en `usd`. Empieza con `10000e18` USD.
- **flash** — flash loan de usd (zero fee): `flashLoan(uint256 amount, address borrower, bytes data)` (`0x2bd94e9c`), exige que `borrower` sea contrato, llama `borrower.<selector 0x79b2fae8>(amount)` de callback, y al final chequea `balanceOf(this)` después `>=` antes ("unpaid" si no repaga). Empieza con `2000e18` USD.
- **Setup.isSolved()**: `usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18` — drenar la lending desk (>9000e18 USD) sin quedar debiendo en el flash loan.

### 3.2 El bug — oráculo de spot price leído directo de las reservas del AMM (sin TWAP real)

`oracle` promete TWAP (nombre de la función `twapPrice`, pero es una constante muerta/decoy) y en la práctica usa el precio instantáneo del pool `dex`. Pool fino (`100e18`/`100e18`) + flash loan de capital (`2000e18` USD, sin fee) = manipulación clásica estilo "flash-loan + spot-oracle" (Harvest/Cheese Bank/bZx-style). No documentado antes en el Arsenal — es un patrón nuevo, no el `web3-mint-on-swap-no-conservation-loop`.

### 3.3 Exploit — 1 tx atómica vía contrato

`attacker_proj/src/Attacker.sol`:

1. `flash.flashLoan(1500e18, address(this), "")` → flash transfiere `1500e18` USD y llama el callback (`fallback()` decodificando selector `0x79b2fae8` manualmente — no existe nombre textual que coincida con ese 4-byte, así que el fallback trata el calldata crudo en vez de intentar hallar el nombre real).
2. En el callback: `usd.approve(dex, 1500e18)` + `dex.call(0x8ac326bd, 1500e18, 0)` → compra HIK con todo el USD prestado. Las reservas van de `100/100` a `~4.78 HIK / 2100 USD` → el precio salta de `1e18` a `~439e18` (439x).
3. Deposita el HIK recién comprado (`~95.2e18`) como colateral (`lending.depositCollateral`).
4. `lending.borrow(9500e18)` — con el precio inflado, el LTV de 90% permite prestar mucho más que el valor real del colateral; la lending desk solo tiene `10000e18`, así que sobran `500e18` (`<1000e18` ✓).
5. Repaga el flash loan (`usd.transfer(flash, 1500e18)`) — flash vuelve a `2000e18` exactos (✓).

```bash
export PATH="$PATH:$HOME/.config/.foundry/bin"
RPC="https://<HOST>"
# instance.json: usd, hik(0xc49330a5...), dex, lending, flash, player PK
forge create src/Attacker.sol:Attacker --private-key $PK --rpc-url "$RPC" --broadcast \
  --constructor-args $USD $HIK $DEX $LENDING $FLASH
cast send $ATTACKER "attack(uint256,uint256)" 1500000000000000000000 9500000000000000000000 \
  --private-key $PK --rpc-url "$RPC" --gas-limit 3000000
cast call $SETUP "isSolved()(bool)" --rpc-url "$RPC"   # -> true
```

Probado antes en fork local (`anvil --fork-url $RPC`) y después en la instancia real — mismo resultado (`lending=500e18`, `flash=2000e18`, `isSolved()==true`).

### 3.4 Flag — proof

`proof = usd.balanceOf(lending)` después del exploit, en decimal = `"500000000000000000000"` (acertó de primera — mismo patrón "proof = valor exacto que `isSolved()` valida, en decimal" del Night Deposit/Voucher Window).

```
GET /instance.json  (cookie hik_team)
cast send ... (exploit arriba) -> isSolved()==true
GET /ticket -> {"ticket":...}
token = sha256(f"{ticket}:500000000000000000000")
POST /flag {"ticket","token"} -> {"flag":"HIK_WEB3_ORACLE_d6036e30b782007df2b879030f515065"}
```

## 4. Lo que no funcionó

No hay registro de hipótesis descartadas en el material original — solo el camino que cerró de primera (ver 3.4).

## 5. Conclusión / próximos pasos

El exploit cerró en 1 tx atómica: flash loan sin fee para manipular el spot price del AMM, usado directamente como "oráculo" por la lending desk, permitiendo borrow por encima del colateral real. Flag confirmada por el proof-oracle HTTP.


---

## Apéndice — herramientas

- `attacker_proj/src/Attacker.sol` — contrato Foundry de exploit (flash loan + swap de pump + deposit + borrow + repay); ejecución vía `forge create` + `cast send` (ver 3.3).
- heimdall (decompile) sobre el bytecode runtime de cada contrato (`*_decompiled/`) para recuperar selectores y lógica sin source.
