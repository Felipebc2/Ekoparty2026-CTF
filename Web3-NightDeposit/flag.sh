#!/usr/bin/env bash
# Night Deposit (<HOST>) — pega a flag via launcher ticket/token/proof.
# Pre: isSolved()==true JA confirmado nesta instancia (bank zerado).
# Uso:  HT=<seu hik_team> bash flag.sh
#   (pegue hik_team no navegador logado: DevTools -> Application -> Cookies -> <HOST>...)
set -u

BASE="https://<HOST>"
HT="${HT:?defina HT=<hik_team> antes de rodar}"
COOKIE="hik_team=$HT"

# valores desta instancia (lowercase, sem 0x -> spec: "no 0x for addresses")
PLAYER="3724438bb2223730590993c2ce62dc7b07ddf6f5"
BANK="343d86294388f892932d125452ac776b63bcbc98"
SETUP="050add181c9a1bb604a85a84ec099af04cd040fb"
TOKEN_C="6cc40abe6270a5c90265f437c6efe16bc2b514a6"   # Night Deposit Note

j() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

try_flag () {
  local LABEL="$1" PROOF="$2"
  local TICKET=$(curl -s -H "Cookie: $COOKIE" "$BASE/ticket" | j "['ticket']")
  local TOKEN=$(printf '%s' "${TICKET}:${PROOF}" | sha256sum | cut -d' ' -f1)
  local RESP=$(curl -s -H "Cookie: $COOKIE" -H 'Content-Type: application/json' \
       -d "{\"ticket\":\"$TICKET\",\"token\":\"$TOKEN\"}" "$BASE/flag")
  echo "[$LABEL] proof=$PROOF -> $RESP"
  case "$RESP" in *HIK_*) echo "*** FLAG ACIMA ***"; return 0;; esac
  return 1
}

# proof web3 = valor CRU (sem sha256 extra). token = sha256("ticket:proof").
# candidatos determinísticos (nao bruteforce): endereços-chave + o saldo zerado.
try_flag "bank"    "$BANK"    && exit 0
try_flag "player"  "$PLAYER"  && exit 0
try_flag "setup"   "$SETUP"   && exit 0
try_flag "token"   "$TOKEN_C" && exit 0
try_flag "zero"    "0"        && exit 0
echo "Nenhum candidato bateu. Se deu 'not solved' -> cookie/instancia errada. Se 'bad token' -> proof e outro valor (me diz o que apareceu)."
