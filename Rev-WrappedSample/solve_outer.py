#!/usr/bin/env python3
# Wrapped Sample - camada externa (VALIDADO, FNV match) + extracao do container CRPK de layer1.
# Uso: python3 -I solve_outer.py artifacts/sample.bin
# Produz layer1 (ELF checker) e extrai vm_bytecode / RCRS. Falta emular a VM p/ obter o SECRET.
import sys, struct
M64=(1<<64)-1; M32=(1<<32)-1
STEP=0x9e3779b97f4a7c15; MIX=0xbf58476d1ce4e5b9; END=0x08d12e6b76c84d11
rol=lambda x,r:((x<<r)|(x>>(64-r)))&M64
ror=lambda x,r:((x>>r)|(x<<(64-r)))&M64
rol32=lambda x,r:((x<<r)|(x>>(32-r)))&M32
IVS=[int.from_bytes(bytes.fromhex("46444b2d31434b48157c4a7fb979379e93fd5966b8fee8d6b9e5e41c6d4758bf")[i:i+8],'little') for i in range(0,32,8)]
def permute(s):
    s0,s1,s2,s3=s; c=STEP
    for _ in range(12):
        l=(s1+c)&M64; c=(c+STEP)&M64; A=(l+s0)&M64
        s0=(A+rol(s1,13))&M64; B=(s3*MIX+s2)&M64; s2=(B+ror(s3,27))&M64
        s1=(ror(s0,23)+B)&M64; s3=(s2+rol(A,23))&M64
    return [s0,s1,s2,s3]
def sponge(segs,dom,outlen):
    buf=bytearray(struct.pack('<Q',len(dom))+dom)
    for g in segs: buf+=struct.pack('<Q',len(g))+g
    buf+=struct.pack('<Q',len(segs)); cl=len(buf); tot=cl+1
    while tot%8: tot+=1
    buf+=b'\x00'*(tot-len(buf)); buf[cl]=0x80
    s=list(IVS)
    for o in range(0,tot,8):
        s[0]=(s[0]+int.from_bytes(buf[o:o+8],'little'))&M64; s=permute(s)   # LITTLE endian
    out=bytearray()
    while len(out)<outlen: out+=struct.pack('<Q',s[0]); s=permute(s)
    return bytes(out[:outlen])
def lz4(src,osz):
    out=bytearray(); ip=0; n=len(src)
    while ip<n:
        tok=src[ip]; ip+=1; ll=tok>>4
        if ll==0xf:
            while True:
                b=src[ip];ip+=1;ll+=b
                if b!=0xff:break
        out+=src[ip:ip+ll]; ip+=ll
        if ip>=n:break
        off=src[ip]|(src[ip+1]<<8); ip+=2
        ml=(tok&0xf)+4
        if (tok&0xf)==0xf:
            while True:
                b=src[ip];ip+=1;ml+=b
                if b!=0xff:break
        st=len(out)-off
        for i in range(ml): out.append(out[st+i])
    return bytes(out[:osz])
def fnv(d):
    h=0x811c9dc5
    for b in d: h=((h^b)*0x1000193)&M32
    return h
def unwrap_outer(data):
    t=data[-40:]; ver=t[5]
    assert bytes(c^((ver*17)&0xff) for c in t[0:4])==b'RAZI'
    poff,comp,raw=struct.unpack('<Q',t[8:16])[0],struct.unpack('<Q',t[16:24])[0],struct.unpack('<Q',t[24:32])[0]
    f20=struct.unpack('<I',t[0x20:0x24])[0]; fexp=struct.unpack('<I',t[0x24:0x28])[0]
    uv=struct.unpack('<I',sponge([data[:min(poff,0x1000)],bytes([8])],b'CPK-STUB',4))[0] or 0x43504b31
    seed=(f20^uv^0xf1bbcdc8)&M32
    dest=bytearray(data[poff:poff+comp]); u=seed
    for i in range(comp):
        u=((0x6d2b79f5+i)&M32)^u; u=(rol32(u,7)*0x27d4eb2d)&M32; dest[i]^=(u>>11)&0xff
    o=bytes(dest)
    for k in range(comp-1,0,-1): dest[k]=((-0xf-o[k-1])-k+o[k])&0xff
    out=lz4(bytes(dest),raw); assert fnv(out)==fexp, "FNV mismatch"
    return out
# ---- CRPK (layer1) codecs ----
def ksdec(d,s):
    k=s&0xff; out=bytearray(len(d))
    for i,x in enumerate(d): out[i]=x^k; k=(k*0x6d+0x39)&0xff
    return bytes(out)
def rle(src):
    out=bytearray(); i=0; n=len(src)
    while i<n:
        if src[i]!=0xfe: out.append(src[i]); i+=1
        else:
            if n-i<3: break
            out+=bytes([src[i+2]])*src[i+1]; i+=3
    return bytes(out)
def extract_crpk(layer1):
    pos=layer1.rfind(b'HIKB'); off=pos+8
    assert layer1[off:off+4]==b'CRPK'
    count=struct.unpack('<H',layer1[off+6:off+8])[0]; seed=struct.unpack('<I',layer1[off+8:off+12])[0]
    tbl=ksdec(layer1[off+16:off+16+count*13], seed^0xc4ac4a00); dr=off+16+count*13; cum=0; res={}
    for e in range(count):
        ent=tbl[e*13:e*13+13]; delta,clen=struct.unpack('<II',ent[0:8]); flag=ent[8]; cum+=delta
        r=rle(ksdec(layer1[dr+cum:dr+cum+clen],(seed+cum)&0xff))
        if flag==0xa7: res['vm']=rle(ksdec(r,0xe5))     # 487-byte VM bytecode -> gera o SECRET
        else: res['e%d'%e]=r                             # e1="RCRS" (reloc op->handler)
    return res
if __name__=='__main__':
    data=open(sys.argv[1],'rb').read()
    layer1=unwrap_outer(data); print("layer1 OK (FNV match):",len(layer1),"bytes, ELF=",layer1[:4]==bytes([127])+b'ELF')
    c=extract_crpk(layer1); print("CRPK:", {k:len(v) for k,v in c.items()})
    # TODO: emular a VM (c['vm']) com mapa de c['e1'] (RCRS) -> SECRET de 32 bytes ->
    # proof=sha256(secret.hex()) -> oracle /ticket,/flag.
