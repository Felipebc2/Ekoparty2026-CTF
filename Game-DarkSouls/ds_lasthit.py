#!/usr/bin/env python3
"""Dark Souls — DPS multi-conexão no boss + last-hitter.

Uso:
    ~/ds_venv/bin/python Challenges/DarkSouls/ds_lasthit.py <TOKEN> [TOKEN2 TOKEN3 ...]

- 1 token: abre NUM_CONN conexões reusando o mesmo token (cada conexão = um player atacando).
- vários tokens: abre 1 conexão por token (NUM_CONN é ignorado).

O boss é COMPARTILHADO => N players somam dano. O golpe final em QUALQUER um dos teus ids
dispara o frame `victory{data.flag}`. Minion não dá crédito (farm descartado).

Anti-flood do server: ~40-60 melee/s POR CONEXÃO é ok; muito acima ele fecha o WS.
Tune: NUM_CONN (quantos players) e MELEE_PER_SEC (por conexão).
"""
import asyncio, json, sys, math, time, collections
import websockets
from websockets.exceptions import ConnectionClosed

URL = "wss://<HOST>/ws?token={}"

NUM_CONN      = 1     # 1 token = 1 player (server amarra player ao token); p/ vários players passe vários tokens
MELEE_PER_SEC = 50    # por conexão
MOVE_PER_SEC  = 8

S = {"got_flag": False, "flag": None}

def dist(a, b):
    return math.hypot(a.get("x",0)-b.get("x",0), a.get("z",0)-b.get("z",0))

async def session(token, cid):
    me_id = {"v": None}
    state = {"d": None}
    recent = collections.deque(maxlen=30)
    prev_reset = False
    hb = {"n": 0}
    last_connect = 0.0
    fast = 0

    while not S["got_flag"]:
        try:
            async with websockets.connect(URL.format(token), max_size=None,
                                          ping_interval=20, ping_timeout=20) as ws:
                last_connect = time.time()
                async def send(o): await ws.send(json.dumps(o))

                async def act():
                    i = 0; melee_dt = 1.0/MELEE_PER_SEC
                    move_every = max(1, round(MELEE_PER_SEC/MOVE_PER_SEC))
                    try:
                        while not S["got_flag"]:
                            st = state["d"]
                            if st and me_id["v"]:
                                me = st.get("players", {}).get(me_id["v"])
                                if not me or me.get("hp",0) <= 0:
                                    await send({"type":"respawn"}); await asyncio.sleep(0.3); continue
                                mp = me.get("position",{}) or {}
                                tp = (st.get("boss",{}) or {}).get("position",{}) or {}
                                dx = tp.get("x",0)-mp.get("x",0); dz = tp.get("z",0)-mp.get("z",0)
                                rot = math.atan2(dx,dz); d = math.hypot(dx,dz)
                                if i % move_every == 0:
                                    sx,sz = (dx/d*2.0, dz/d*2.0) if d>0.1 else (0.0,0.0)
                                    await send({"type":"move","dx":sx,"dz":sz,"rotation":rot})
                                await send({"type":"melee","dx":dx,"dz":dz,"rotation":rot})
                                i += 1
                            await asyncio.sleep(melee_dt)
                    except ConnectionClosed:
                        return

                async def recv():
                    nonlocal prev_reset
                    try:
                        async for raw in ws:
                            low = raw.lower()
                            if S["got_flag"]: return
                            if "victory" in low or "hik_" in low or '"flag"' in low:
                                print(f"\n*** [c{cid}] FRAME DE INTERESSE ***\n", raw, "\n")
                            try: m = json.loads(raw)
                            except Exception: continue
                            t = m.get("type")
                            if t == "init":
                                me_id["v"] = m["data"]["id"]
                                print(f"[c{cid}] myId = {me_id['v']}")
                            elif t == "state":
                                st = m["data"]; state["d"] = st
                                recent.append(raw)
                                boss = st.get("boss",{}) or {}
                                reset = st.get("isResetting")
                                hb["n"] += 1
                                if cid == 0 and hb["n"] % 25 == 0:
                                    me = st.get("players",{}).get(me_id["v"],{})
                                    print(f"[hb] boss.hp={boss.get('hp')} lastHitter={boss.get('lastHitterId')!r} "
                                          f"c0.hp={me.get('hp')} reset={reset}")
                                if reset and not prev_reset:
                                    print(f"\n===== [c{cid}] RESET ===== lastHitter=%r myId=%r"
                                          % (boss.get("lastHitterId"), me_id["v"]))
                                    print("   sou o lastHitter? ->", boss.get("lastHitterId")==me_id["v"])
                                prev_reset = reset
                            elif t == "victory":
                                S["flag"] = m["data"].get("flag"); S["got_flag"] = True
                                print(f"\n[c{cid}] !!! VICTORY !!! flag = {S['flag']}\n"); return
                            elif t == "error":
                                print(f"[c{cid}] err:", m.get("message"))
                    except ConnectionClosed:
                        return

                tasks = [asyncio.create_task(recv()), asyncio.create_task(act())]
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for p in pending:
                    p.cancel()
                    try: await p
                    except BaseException: pass
                for dn in done:
                    try: dn.result()
                    except BaseException: pass
        except Exception:
            pass
        if S["got_flag"]: return
        up = time.time() - last_connect
        if up < 3:
            fast += 1
            if cid == 0 and fast >= 3:
                print(f"[DS] server derrubando rápido (durou {up:.1f}s). Baixe MELEE_PER_SEC/NUM_CONN ou pegue token novo.")
            await asyncio.sleep(4)
        else:
            fast = 0; await asyncio.sleep(0.8)

async def run(tokens):
    if len(tokens) == 1:
        conns = [(tokens[0], i) for i in range(NUM_CONN)]
    else:
        conns = [(t, i) for i, t in enumerate(tokens)]
    print(f"[DS] {len(conns)} conexões, {MELEE_PER_SEC} melee/s cada. Até victory/HIK_ ou Ctrl+C.\n")
    await asyncio.gather(*[session(tok, cid) for tok, cid in conns])
    print(f"\n[DS] FLAG = {S['flag']}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("uso: python3 ds_lasthit.py <TOKEN> [TOKEN2 ...]"); sys.exit(1)
    try:
        asyncio.run(run(sys.argv[1:]))
    except KeyboardInterrupt:
        print("\n[DS] parado pelo usuário")
