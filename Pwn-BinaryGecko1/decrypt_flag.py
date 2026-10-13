#!/usr/bin/env python3
# Gecko 1 (Ekoparty 2026) - decrypt da flag.
# A gecko2026-module.dll guarda "FLAG: " + 60 bytes cifrados em .data (file-off 0xd020).
# fcn@0x1160 decifra com XOR de palavras de 32 bits contra uma chave de 4 bytes ([0xe368],
# vinda de fcn@0x1050). XOR e' involutivo -> recupero a chave por known-plaintext "HIK_".
import re, struct

d = open("module_dump.bin", "rb").read()
ct = d[0xd026:0xd026 + 60]                      # &blob + 6 (pula "FLAG: ")

# chave de 4 bytes recuperada: primeiros 4 bytes do plaintext sao "HIK_"
key = bytes(c ^ p for c, p in zip(ct[:4], b"HIK_"))   # == e1 3b ee 03
pt = bytes(ct[i] ^ key[i % 4] for i in range(len(ct)))
flag = pt.split(b"\xff")[0].decode("latin1").rstrip("\x00")

print("key (4B):", key.hex())
print("plaintext:", pt)
print("FLAG:", flag)
assert re.fullmatch(r"HIK_.+_[0-9a-f]{32}", flag), "formato invalido!"
print("formato HIK_<texto>_<md5 32hex>: OK")
