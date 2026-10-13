#!/usr/bin/env bash
# Voucher Window — pega a flag na MESMA sessão (cookie hik_team).
# Pré-req: já resolvido on-chain (isSolved()==true) para a instância deste cookie.
# Uso: COOKIE='hik_team=XXXX' bash flag.sh
set -u
BASE="https://<HOST>"
RPC="https://<HOST>"
: "${COOKIE:?defina COOKIE='hik_team=...' do navegador logado}"

j() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

INST=$(curl -s -H "Cookie: $COOKIE" "$BASE/instance.json")
echo "instance: $INST" | head -c 400; echo
PLAYER=$(printf '%s' "$INST" | j "['player']")
SETUP=$(printf '%s' "$INST" | j "['contracts']['setup']")
PID=$(printf '%s' "$INST" | j "['playerId']")
TOKEN=0x0a230d4233594a6Fad2628efC2b9684EEE0D2FD1
DROP=0x6301049349524cc57598f596cd6a335af4e60744

echo "isSolved=$(cast call $SETUP 'isSolved()(bool)' --rpc-url $RPC)  playerId=$PID"

try() {
  local LABEL="$1" PROOF="$2"
  local TICKET=$(curl -s -H "Cookie: $COOKIE" "$BASE/ticket" | j "['ticket']")
  local TOK=$(printf '%s' "${TICKET}:${PROOF}" | sha256sum | cut -d' ' -f1)
  local R=$(curl -s -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
       -d "{\"ticket\":\"$TICKET\",\"token\":\"$TOK\"}" "$BASE/flag")
  echo "[$LABEL] proof=$PROOF -> $R"
  case "$R" in *HIK_*|*'"flag"'*) echo "### FLAG ###"; exit 0;; esac
}

PL=${PLAYER:2}; SET=${SETUP:2}; TK=${TOKEN:2}; DR=${DROP:2}
try player     "${PL,,}"
try setup      "${SET,,}"
try drop       "${DR,,}"
try token      "${TK,,}"
try playerId   "$PID"
try amount_wei "1000000000000000000000"
echo "Nenhum bateu. Se deu 'bad token' em todos, instancia OK -> proof e outro valor. Se 'not solved' -> cookie/instancia errada."
