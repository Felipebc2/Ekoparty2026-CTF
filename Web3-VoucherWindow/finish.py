#!/usr/bin/env python3
# Voucher Window — fecha a flag quando você tiver o PROOF da track README.
# Uso: python3 finish.py '<proof>'   (proof = valor hex lowercase, sem 0x p/ address)
import sys, hashlib, urllib.request, urllib.error, json
COOKIE = "hik_team=bdfa758e27a40f09"
BASE   = "https://<HOST>"
proof  = sys.argv[1]

def req(p, data=None):
    r = urllib.request.Request(BASE+p, data=data,
        headers={"Cookie": COOKIE, "Content-Type": "application/json"})
    try:
        return urllib.request.urlopen(r, timeout=20).read().decode()
    except urllib.error.HTTPError as e:
        return e.read().decode("utf-8", "replace")

ticket = json.loads(req("/ticket"))["ticket"]
token  = hashlib.sha256(f"{ticket}:{proof}".encode()).hexdigest()  # web3: proof CRU, sem sha256 extra
print(req("/flag", json.dumps({"ticket": ticket, "token": token}).encode()))
