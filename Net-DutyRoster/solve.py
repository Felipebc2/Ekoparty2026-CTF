#!/usr/bin/env python3
# Duty Roster (Packet, 350pts) — RESOLVIDO por colega de equipe (09/out).
# Pedra de Roseta da família PACKET: o answer = os itens que o enunciado nomeia,
# juntados por ':', ESTRUTURAIS (metadados do stream que faz beacon), NÃO o payload.
# Duty Roster enunciado: "Identify who, where, which port, and how often."
#   who   = src IP do beacon
#   where = dst IP
#   port  = tcp dstport
#   how often = mediana do intervalo entre aberturas SYN (em segundos)
# Formato vencedor provável: who:where:port:interval  (sep ':', interval tipo "5s"/"5").
# proof = sha256_hex(sid + ":" + answer + ":" + sha256_hex(pcap_b64_texto_sem_ws))
# submit testado em 2 variantes de hash (texto b64 e bytes raw) na MESMA sessão TCP.
#
# NOTA: copiado do colega; underscores dunder reconstruídos (__file__, __name__/__main__)
# e regex do getpcap ajustada. Reaproveitar como harness pra Outbox/Lookup Desk/Background Noise.
import socket, time, re, hashlib, base64, os, subprocess, statistics

HOST, PORT = '<IP>', 16007
OUT = os.path.dirname(os.path.abspath(__file__))

def recv_until_prompt(s, timeout=25.0, idle=2.0):
    s.settimeout(0.4)
    data = b''; start=time.time(); last=time.time()
    while time.time()-start < timeout:
        try:
            c = s.recv(65536)
            if c:
                data += c; last=time.time()
                if data.rstrip().endswith(b'>'):
                    time.sleep(0.03)
                    try:
                        s.settimeout(0.2); extra=s.recv(65536)
                        if extra: data+=extra
                    except Exception: pass
                    break
            else:
                break
        except socket.timeout:
            if time.time()-last > idle and data: break
            continue
    return data

def send(s, line):
    s.sendall(line.encode()+b'\n')

def read_resp(s, timeout=3.0, idle=0.45):
    s.settimeout(0.25); data=b''; start=time.time(); last=time.time()
    while time.time()-start < timeout:
        try:
            c=s.recv(65536)
            if c:
                data+=c; last=time.time()
                if data.rstrip().endswith(b'>'):
                    break
            else:
                break
        except socket.timeout:
            if time.time()-last>idle and data: break
            continue
    return data

def derive_streams(pcap_path):
    out = subprocess.run(
        ['tshark','-r',pcap_path,'-Y','tcp.flags.syn==1 && tcp.flags.ack==0',
         '-T','fields','-e','frame.time_relative','-e','ip.src','-e','ip.dst','-e','tcp.dstport'],
        capture_output=True, text=True)
    streams = {}
    for line in out.stdout.splitlines():
        p=line.split('\t')
        if len(p)<4 or not p[0]: continue
        t=float(p[0]); key=(p[1],p[2],p[3])
        streams.setdefault(key,[]).append(t)
    out2 = subprocess.run(
        ['tshark','-r',pcap_path,'-Y','tcp.len>0',
         '-T','fields','-e','ip.src','-e','ip.dst','-e','tcp.dstport','-e','tcp.len'],
        capture_output=True, text=True)
    data_to_dst = {}
    for line in out2.stdout.splitlines():
        p=line.split('\t')
        if len(p)<4 or not p[0]: continue
        key=(p[0],p[1],p[2]); data_to_dst[key]=max(data_to_dst.get(key,0), int(p[3]))
    res=[]
    for key,times in streams.items():
        times.sort()
        if len(times)<2:
            interval=None
        else:
            deltas=[round(times[i+1]-times[i],3) for i in range(len(times)-1)]
            interval=statistics.median(deltas)
        res.append({'src':key[0],'dst':key[1],'dport':key[2],'count':len(times),
                    'interval':interval,'client_data':data_to_dst.get(key,0)})
    res.sort(key=lambda r:-r['count'])
    return res

def build_candidates(streams):
    cands=set()
    for st in streams:
        who, where, port = st['src'], st['dst'], st['dport']
        iv = st['interval']
        if iv is None: continue
        ivr = int(round(iv))
        iv_reps = [str(ivr), f'{ivr}s', f'{ivr}sec', f'{ivr}.0', f'{ivr}000ms',
                   f'every {ivr}s', f'{ivr} s', f'{ivr} sec', f'{ivr} seconds', f'{ivr}secs']
        seps = [':', ' ', ',', '>', '|', '/', '-']
        for sep in seps:
            cands.add(sep.join([who, where, port]))
            for ivv in iv_reps:
                cands.add(sep.join([who, where, port, ivv]))
        for sep in [':',' ',',','|']:
            cands.add(f'{who}{sep}{where}:{port}')
            for ivv in iv_reps:
                cands.add(f'{who}{sep}{where}:{port}{sep}{ivv}')
        for ivv in iv_reps:
            cands.add(f'{where}:{port}:{ivv}')
            cands.add(f'{where}:{port} {ivv}')
        cands.add(f'{where}:{port}')
        cands.add(who); cands.add(where); cands.add(f'{port}')
    return sorted(cands)

def main():
    s=socket.socket(); s.settimeout(12); s.connect((HOST,PORT))
    banner=recv_until_prompt(s)
    m=re.search(rb'sid\s+([0-9a-f]{32})',banner); sid=m.group(1).decode()
    print('SID',sid)
    send(s,'capture 30'); print('cap:',recv_until_prompt(s,timeout=50,idle=3).decode(errors='replace').strip()[:40])
    send(s,'getpcap'); pr=recv_until_prompt(s,timeout=30,idle=2.5).decode(errors='replace')
    mm=re.search(r'BEGIN PCAP\s*-*\s*(.*?)\s*-*\s*END PCAP',pr,re.S)
    if not mm:
        print('getpcap parse failed; raw head:',pr[:200]); s.close(); return
    b64=re.sub(r'\s+','',mm.group(1))
    raw=base64.b64decode(b64)
    h_b64=hashlib.sha256(b64.encode()).hexdigest()
    h_raw=hashlib.sha256(raw).hexdigest()
    pp=os.path.join(OUT,'solve.pcap'); open(pp,'wb').write(raw)
    print('pcap raw',len(raw),'h_b64',h_b64[:12],'h_raw',h_raw[:12])

    streams=derive_streams(pp)
    print('=== derived streams (repeating) ===')
    rep=[st for st in streams if st['count']>=3]
    for st in rep:
        print(st)
    if not rep: rep=streams[:3]

    cands=build_candidates(rep)
    print(f'{len(cands)} answer candidates x 2 hashes = {len(cands)*2} submits')

    def prio(c):
        score=0
        if c.count(':')>=3: score-=5
        if c.count(':')==2: score-=2
        if re.search(r':\d+$', c): score-=3
        return score
    cands.sort(key=prio)

    hit=None
    t0=time.time(); n=0; dead=0
    for hname,hpcap in [('b64',h_b64),('raw',h_raw)]:
        for ans in cands:
            if time.time()-t0 > 108:
                print('time budget reached at',n,'submits'); break
            proof=hashlib.sha256(f'{sid}:{ans}:{hpcap}'.encode()).hexdigest()
            try:
                send(s,f'submit {proof}')
            except Exception as e:
                print('send failed (session closed?)',e); break
            resp=read_resp(s).decode(errors='replace'); n+=1
            if not resp.strip():
                dead+=1
                if dead>5:
                    print('session seems dead after',n,'submits'); break
            else:
                dead=0
            if 'HIK' in resp:
                mflag=re.search(r'HIK_[A-Za-z0-9_]+', resp)
                hit=(ans,hname,mflag.group(0) if mflag else resp.strip())
                print('* HIT *', hit)
                break
        if hit or time.time()-t0>108: break
    print('total submits:',n)
    if not hit:
        print('NO HIT across all candidates')
    s.close()
    if hit:
        open(os.path.join(OUT,'FLAG.txt'),'w').write(f'{hit[2]}\nanswer={hit[0]}\nhash={hit[1]}\nsid={sid}\n')

if __name__ == '__main__':
    main()
