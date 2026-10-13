<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Assembly+Floor+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

<p align="center"><b>English</b> · <a href="WRITEUP.es.md">Español</a> · <a href="WRITEUP.pt-BR.md">Português (BR)</a></p>

# Assembly Floor — WEB3 · 400 pts · 🟡 MEDIUM

- **Status:** ✅ SOLVED — flash loan of the governance token + vote without snapshot drains the treasury; `isSolved()` true.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`
- **Flag format:** `HIK_[text]_[md5]`
- **Access:** chainId 31337 (Anvil) · RPC `https://<RPC>` · launcher `https://<HOST>`
- **Prompt:** *"The treasury is behind a vote. You have a seat. Make `Setup.isSolved()` return true."*

CTF: Ekoparty BA 2026 / Hack in Cariri.

---

## 0. TL;DR

1. No source (decompile via heimdall): `Setup` + token `HIKG` + flash loan pool + DAO Governor + treasury; `isSolved() == (treasury.balance == 0)`.
2. `vote()` sums the current `balanceOf(msg.sender)` (no snapshot) and the pool lends the governance token with no fee -> the borrowed voting power stays written in storage even after returning the loan.
3. Flash loan -> `propose` -> `vote` -> return, in the same tx; then `evm_increaseTime` to `queue` and `execute` -> `treasury.spend(player, 50 ether)`. `proof = "0"`.

### Chain that closed
1. `Attacker.attack(6000e18)` -> flash loan, the callback does `propose(treasury, 0, spend(player, 50 ether))` + `vote(id)` (6000e18 >= quorum 5000e18) + returns the loan.
2. `evm_increaseTime` >3600s -> `queue(id)`; again >3600s -> `execute(id)` -> treasury zeroed.
3. `cast call Setup "isSolved()(bool)"` -> `true`.
4. `GET /instance.json` -> `GET /ticket` -> `POST /flag {ticket, token=sha256("<ticket>:0")}` -> flag.

---

## 1. Artifacts

- `Attacker.sol` — attacker contract (flash loan + propose + vote in one tx).

Instance:
- Setup: `0xdbdee9d5f90b4250d120b10e0382ddfff1df58c2` (instance pasted in the prompt, playerId 2).
- **Gotcha:** the prompt instance had no `hik_team` cookie. The first real `GET /instance.json` rotated to a new instance (playerId 15, setup `0x907680059a9f0755015ee07d03cd9f56fc27c4fa`). Solved on both; the new one (tied to the cookie) is the one that counted for `/flag`.

## 2. Delivery / validation

- `proof = "0"` (Night Deposit pattern: value that `isSolved` validates — `treasury.balance == 0`). Hit it on the first try.
- `GET /instance.json` (saves the `hik_team` cookie) -> `GET /ticket` (TTL 45s) -> `token = sha256("<ticket>:0")` -> `POST /flag {ticket,token}` with the cookie.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`

## 3. Analysis

### 3.1 Recon (no source, decompile via heimdall)

`Setup` exposes `dao()`, `treasury()`, `token()`, `flash()`, `player()`.

- `isSolved() == (treasury.balance == 0)` -> goal: **drain the treasury's ETH**.
- `token` (HIKG, 18 dec): simple ERC20. `mint()` only by Setup itself (inaccessible).
- `flash`: pool with **10000e18 HIKG** sitting idle. `flashLoan(uint256 amount, address receiver, bytes data)` (selector `0x2bd94e9c`): transfers the token to the receiver, calls the callback `0x79b2fae8(amount)`, and only validates that the pool balance returned to the original. **No fee, no control of who borrows.**
- `dao` (Governor): `propose(target,value,data)` (threshold 1000e18 `balanceOf`), `vote(id)` (**sums the current `balanceOf(msg.sender)` — no snapshot**), `queue(id)` (quorum 5000e18 + 3600s window closed), `execute(id)` (after a 3600s timelock, low-level call with `target/value/data`).
- `treasury.spend(address,uint256)` is `onlyDao` — the only withdrawal path.
- Player had only 1e18 HIKG (< threshold). Without the flash loan, cannot propose or reach quorum.

### 3.2 Vector — flash-loan governance (no vote snapshot)

Not documented in the Arsenal; derived from the bytecode and confirmed by execution.

The absence of a snapshot in `vote()` + public flash loan of the governance token itself = borrowed voting power inside a tx stays **permanently written** in storage even after returning the loan.

**In a single tx** (`Attacker.sol`):
1. flash loan of 6000e18 HIKG -> callback;
2. `propose(treasury, 0, spend(player, 50 ether))`;
3. `vote(id)` with weight 6000e18 (>= quorum 5000e18 — closes quorum);
4. return the loan to the pool.

Outside the tx (Anvil RPC, `evm_increaseTime` enabled; `anvil_mine` blocked but not needed):
5. advance >3600s -> `queue(id)`;
6. advance >3600s -> `execute(id)` -> `treasury.spend(player, 50 ether)` zeroes the treasury.

`cast call Setup "isSolved()(bool)"` -> `true`.

## 4. What didn't work

- `anvil_mine` blocked on the RPC — it was not needed (`evm_increaseTime` was enough).
- Instance pasted manually in the prompt with no `hik_team` cookie does not count for `/flag` (see gotcha in 1).
- No additional failed attempts recorded.

## 5. Conclusion / next steps

It closed because `vote()` does not snapshot and the flash loan of the governance token is public and fee-less. Notes for the Arsenal (suggested):
- New entry `web3-governance-flashloan-vote-weight-no-snapshot.md`: Governor without snapshot + flash loan of the governance token -> drain the treasury via propose+vote in the same tx, `evm_increaseTime` to skip the voting period + timelock.
- The launcher host follows `web3-NN` mirroring `rpc-NN` (confirmed: `<HOST>` -> `<RPC>`; same as voucher-window).
- Instance pasted manually in the prompt has no cookie -> always do the first real `GET /instance.json` to pin the instance that counts for `/flag`.

---

## Appendix — tools

- `Attacker.sol` — contract with `attack(uint256 amount)` (owner only): calls `flash.call(0x2bd94e9c, amount, address(this), "")`; the `fallback()` (flash loan callback) does `dao.propose(treasury, 0, spend(player, 50 ether))`, `dao.vote(id)` and returns the whole token balance to the pool. Constructor: `(token, dao, flash, treasury, player)`. Usage: `attack(6000e18)`.
