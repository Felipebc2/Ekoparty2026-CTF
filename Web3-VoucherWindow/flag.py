#!/usr/bin/env python3
# Voucher Window — varre candidatos de proof na MESMA sessao (cookie hik_team).
# proof web3 = valor CRU (lowercase hex, sem 0x). token = sha256(f"{ticket}:{proof}").
import sys, hashlib, requests
from Crypto.Hash import keccak

COOKIE = sys.argv[1] if len(sys.argv) > 1 else "hik_team=bdfa758e27a40f09"
BASE = "https://<HOST>"
HDR = {"Cookie": COOKIE}

def kec(b): h = keccak.new(digest_bits=256); h.update(b); return h.digest()

player = "a492885c4252f269dd133944684f0df09ceb2661"
signer = "fcab4519101a0da1e63965727cb77464e7fb3332"
r = bytes.fromhex("d0178c35673ee21cf6a435aff0e76845e255ae968e472e60c68e06581a09e81f")
s = bytes.fromhex("3f7b49722930f8bf5169a4d41a1d2ef9686a7c1a03ae8c20d886429624613d6e")
v = bytes([27])
DS = bytes.fromhex("fe2af1fe608945765d1589032c7b9bfc98138464e2a20759dec19349ca149458")
TH = bytes.fromhex("fa923a5dfcec4bc4269925fc2e7149ce9a18f4bf767c04de8334509bd57b82a8")
to = bytes(12) + bytes.fromhex(player)
amt100 = (100 * 10**18).to_bytes(32, "big")
nonce0 = (0).to_bytes(32, "big")

struct_hash = kec(TH + to + amt100 + nonce0)          # Claim(to,amount,nonce)
digest      = kec(b"\x19\x01" + DS + struct_hash)     # EIP-712 digest assinado

cands = [
    ("sig65_rsv",  (r + s + v).hex()),
    ("digest",     digest.hex()),
    ("structHash", struct_hash.hex()),
    ("sig_rs",     (r + s).hex()),
    ("r",          r.hex()),
    ("s",          s.hex()),
    ("signer",     signer),
    ("keccak_player", kec(bytes.fromhex(player)).hex()),
    ("domain",     DS.hex()),
    ("typehash",   TH.hex()),
]

for label, proof in cands:
    try:
        ticket = requests.get(f"{BASE}/ticket", headers=HDR, timeout=15).json()["ticket"]
    except Exception as e:
        print("ticket err:", e); continue
    token = hashlib.sha256(f"{ticket}:{proof}".encode()).hexdigest()
    resp = requests.post(f"{BASE}/flag", headers={**HDR, "Content-Type": "application/json"},
                         json={"ticket": ticket, "token": token}, timeout=15).text
    print(f"[{label}] proof={proof} -> {resp}")
    if "HIK_" in resp or '"flag"' in resp:
        print("### FLAG ###"); break
