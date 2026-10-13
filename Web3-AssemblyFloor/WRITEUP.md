<div align="center">

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=28&duration=700&pause=1000&color=7EF700&center=true&vCenter=true&repeat=false&width=300&height=35&lines=Assembly+Floor+" alt="Typing SVG" /></a>

<p><img src="/img/hackincariri.webp" alt="Hack in Cariri" height="600"></p>

</div>

# Assembly Floor — WEB3 · 400 pts · 🟡 MEDIUM

- **Status:** ✅ RESOLVIDO — flash loan do governance token + voto sem snapshot drena a treasury; `isSolved()` true.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`
- **Flag format:** `HIK_[texto]_[md5]`
- **Acesso:** chainId 31337 (Anvil) · RPC `https://<RPC>` · launcher `https://<HOST>`
- **Enunciado:** *"The treasury is behind a vote. You have a seat. Make `Setup.isSolved()` return true."*

CTF: Ekoparty BA 2026 / Hack in Cariri.

---

## 0. TL;DR

1. Sem source (decompile via heimdall): `Setup` + token `HIKG` + pool de flash loan + DAO Governor + treasury; `isSolved() == (treasury.balance == 0)`.
2. `vote()` soma o `balanceOf(msg.sender)` atual (sem snapshot) e o pool empresta o governance token sem fee -> poder de voto emprestado fica gravado no storage mesmo após devolver o empréstimo.
3. Flash loan -> `propose` -> `vote` -> devolve, na mesma tx; depois `evm_increaseTime` para `queue` e `execute` -> `treasury.spend(player, 50 ether)`. `proof = "0"`.

### Cadeia que fechou
1. `Attacker.attack(6000e18)` -> flash loan, callback faz `propose(treasury, 0, spend(player, 50 ether))` + `vote(id)` (6000e18 >= quorum 5000e18) + devolve o empréstimo.
2. `evm_increaseTime` >3600s -> `queue(id)`; de novo >3600s -> `execute(id)` -> treasury zerada.
3. `cast call Setup "isSolved()(bool)"` -> `true`.
4. `GET /instance.json` -> `GET /ticket` -> `POST /flag {ticket, token=sha256("<ticket>:0")}` -> flag.

---

## 1. Artefatos

- `Attacker.sol` — contrato atacante (flash loan + propose + vote numa tx).

Instância:
- Setup: `0xdbdee9d5f90b4250d120b10e0382ddfff1df58c2` (instância colada no prompt, playerId 2).
- **Gotcha:** a instância do prompt não tinha cookie `hik_team`. O primeiro `GET /instance.json` real rotacionou pra instância nova (playerId 15, setup `0x907680059a9f0755015ee07d03cd9f56fc27c4fa`). Resolvido nas duas; a nova (ligada ao cookie) é a que contou pro `/flag`.

## 2. Entrega / validação

- `proof = "0"` (padrão Night Deposit: valor que `isSolved` valida — `treasury.balance == 0`). Acertou de primeira.
- `GET /instance.json` (salva cookie `hik_team`) -> `GET /ticket` (TTL 45s) -> `token = sha256("<ticket>:0")` -> `POST /flag {ticket,token}` com o cookie.
- **Flag:** `HIK_WEB3_GOVERNANCE_15b08a0f18c1597b0a59df205b66dfc2`

## 3. Análise

### 3.1 Recon (sem source, decompile via heimdall)

`Setup` expõe `dao()`, `treasury()`, `token()`, `flash()`, `player()`.

- `isSolved() == (treasury.balance == 0)` -> objetivo: **drenar o ETH da treasury**.
- `token` (HIKG, 18 dec): ERC20 simples. `mint()` só pelo próprio Setup (inacessível).
- `flash`: pool com **10000e18 HIKG** parados. `flashLoan(uint256 amount, address receiver, bytes data)` (selector `0x2bd94e9c`): transfere o token pro receiver, chama o callback `0x79b2fae8(amount)`, e só valida que o saldo do pool voltou ao original. **Sem fee, sem controle de quem empresta.**
- `dao` (Governor): `propose(target,value,data)` (threshold 1000e18 `balanceOf`), `vote(id)` (**soma `balanceOf(msg.sender)` atual — sem snapshot**), `queue(id)` (quorum 5000e18 + janela de 3600s encerrada), `execute(id)` (após timelock 3600s, low-level call com `target/value/data`).
- `treasury.spend(address,uint256)` é `onlyDao` — único caminho de saque.
- Player tinha só 1e18 HIKG (< threshold). Sem o flash loan, não propõe nem atinge quorum.

### 3.2 Vetor — flash-loan governance (sem snapshot de voto)

Não documentado no Arsenal; derivado do bytecode e confirmado por execução.

A ausência de snapshot em `vote()` + flash loan público do próprio governance token = poder de voto emprestado dentro de uma tx fica **gravado permanentemente** no storage mesmo após devolver o empréstimo.

**Numa única tx** (`Attacker.sol`):
1. flash loan de 6000e18 HIKG -> callback;
2. `propose(treasury, 0, spend(player, 50 ether))`;
3. `vote(id)` com peso 6000e18 (>= quorum 5000e18 — fecha quorum);
4. devolver o empréstimo ao pool.

Fora da tx (RPC Anvil, `evm_increaseTime` habilitado; `anvil_mine` bloqueado mas não necessário):
5. avançar >3600s -> `queue(id)`;
6. avançar >3600s -> `execute(id)` -> `treasury.spend(player, 50 ether)` zera a treasury.

`cast call Setup "isSolved()(bool)"` -> `true`.

## 4. O que não funcionou

- `anvil_mine` bloqueado no RPC — não era necessário (`evm_increaseTime` bastou).
- Instância colada manualmente no prompt sem cookie `hik_team` não vale para o `/flag` (ver gotcha em 1).
- Sem tentativas falhas adicionais registradas.

## 5. Conclusão / próximos passos

Fechou porque `vote()` não faz snapshot e o flash loan do governance token é público e sem fee. Notas pro Arsenal (sugeridas):
- Nova entrada `web3-governance-flashloan-vote-weight-no-snapshot.md`: Governor sem snapshot + flash loan do governance token -> drenar treasury via propose+vote na mesma tx, `evm_increaseTime` pra pular voting period + timelock.
- Launcher host segue `web3-NN` espelhando `rpc-NN` (confirmado: `<HOST>` -> `<RPC>`; igual voucher-window).
- Instância colada manualmente no prompt não tem cookie -> sempre fazer o primeiro `GET /instance.json` real pra fixar a instância que conta pro `/flag`.

---

## Apêndice — ferramentas

- `Attacker.sol` — contrato com `attack(uint256 amount)` (só owner): chama `flash.call(0x2bd94e9c, amount, address(this), "")`; o `fallback()` (callback do flash loan) faz `dao.propose(treasury, 0, spend(player, 50 ether))`, `dao.vote(id)` e devolve todo o saldo de token ao pool. Construtor: `(token, dao, flash, treasury, player)`. Uso: `attack(6000e18)`.
