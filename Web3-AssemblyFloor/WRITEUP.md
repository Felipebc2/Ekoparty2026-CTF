# Assembly Floor — Web3 (400 pts)

**CTF:** Ekoparty BA 2026 / Hack in Cariri · **Status:** ✅ Resolvido · **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`

> "The treasury is behind a vote. You have a seat. Make `Setup.isSolved()` return true."

## Instância

- chainId 31337 (Anvil) · RPC `https://<HOST>` · launcher `https://<HOST>`
- Setup: `0xdbdee9d5f90b4250d120b10e0382ddfff1df58c2` (instância colada no prompt, playerId 2)
- **Gotcha:** a instância do prompt não tinha cookie `hik_team`. O primeiro `GET /instance.json` real rotacionou pra instância nova (playerId 15, setup `0x907680059a9f0755015ee07d03cd9f56fc27c4fa`). Resolvido nas duas; a nova (ligada ao cookie) é a que contou pro `/flag`.

## Recon (sem source, decompile via heimdall)

`Setup` expõe `dao()`, `treasury()`, `token()`, `flash()`, `player()`.

- `isSolved() == (treasury.balance == 0)` → objetivo: **drenar o ETH da treasury**.
- `token` (HIKG, 18 dec): ERC20 simples. `mint()` só pelo próprio Setup (inacessível).
- `flash`: pool com **10000e18 HIKG** parados. `flashLoan(uint256 amount, address receiver, bytes data)` (selector `0x2bd94e9c`): transfere o token pro receiver, chama o callback `0x79b2fae8(amount)`, e só valida que o saldo do pool voltou ao original. **Sem fee, sem controle de quem empresta.**
- `dao` (Governor): `propose(target,value,data)` (threshold 1000e18 `balanceOf`), `vote(id)` (**soma `balanceOf(msg.sender)` atual — sem snapshot**), `queue(id)` (quorum 5000e18 + janela de 3600s encerrada), `execute(id)` (após timelock 3600s, low-level call com `target/value/data`).
- `treasury.spend(address,uint256)` é `onlyDao` — único caminho de saque.
- Player tinha só 1e18 HIKG (< threshold). Sem o flash loan, não propõe nem atinge quorum.

## Vetor — flash-loan governance (sem snapshot de voto)

Não documentado no Arsenal; derivado do bytecode e confirmado por execução.

A ausência de snapshot em `vote()` + flash loan público do próprio governance token = poder de voto emprestado dentro de uma tx fica **gravado permanentemente** no storage mesmo após devolver o empréstimo.

**Numa única tx** (`Attacker.sol`, ver ao lado):
1. flash loan de 6000e18 HIKG → callback;
2. `propose(treasury, 0, spend(player, 50 ether))`;
3. `vote(id)` com peso 6000e18 (≥ quorum 5000e18 — fecha quorum);
4. devolver o empréstimo ao pool.

Fora da tx (RPC Anvil, `evm_increaseTime` habilitado; `anvil_mine` bloqueado mas não necessário):
5. avançar >3600s → `queue(id)`;
6. avançar >3600s → `execute(id)` → `treasury.spend(player, 50 ether)` zera a treasury.

`cast call Setup "isSolved()(bool)"` → `true`.

## Flag

- `proof = "0"` (padrão Night Deposit: valor que `isSolved` valida — `treasury.balance == 0`). Acertou de primeira.
- `GET /instance.json` (salva cookie `hik_team`) → `GET /ticket` (TTL 45s) → `token = sha256("<ticket>:0")` → `POST /flag {ticket,token}` com o cookie.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`

## Notas pro Arsenal (sugeridas)

- Nova entrada `web3-governance-flashloan-vote-weight-no-snapshot.md`: Governor sem snapshot + flash loan do governance token → drenar treasury via propose+vote na mesma tx, `evm_increaseTime` pra pular voting period + timelock.
- Launcher host segue `web3-NN` espelhando `rpc-NN` (confirmado: <HOST> → <HOST>; igual voucher-window <HOST> → <HOST>).
- Instância colada manualmente no prompt não tem cookie → sempre fazer o primeiro `GET /instance.json` real pra fixar a instância que conta pro `/flag`.
