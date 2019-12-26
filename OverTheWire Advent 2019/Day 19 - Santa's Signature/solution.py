#!/usr/bin/env python3
from pwn import *
from Crypto.PublicKey import RSA
r = remote("3.93.128.89",1219)
r.recvuntil("-----BEGIN PUBLIC KEY-----")
raw_key = b"-----BEGIN PUBLIC KEY-----" + r.recvuntil("-----END PUBLIC KEY-----")
pub = RSA.importKey(raw_key)
r.sendline("0")
r.sendline("0")
r.sendline("1")
r.sendline("1")
r.sendline(hex(pub.n-1))
r.clean()
r.sendline(hex(pub.n-1))
r.stream()
