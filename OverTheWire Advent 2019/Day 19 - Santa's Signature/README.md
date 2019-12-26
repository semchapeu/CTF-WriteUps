# Santa's Signature

- Points: 174
- Solves: 77
- Author: semchapeu

Can you forge Santa's signature?

# Source

```Python
#!/usr/bin/env python3
import Crypto
from Crypto.PublicKey import RSA
import sys

try:
	with open("key",'r') as f:
		key = RSA.importKey(f.read())
except:
	rng = Crypto.Random.new().read
	key = RSA.generate(4096, rng)
	with open("key",'w') as f:
		f.write(key.exportKey().decode("utf-8"))

def h2i(h):
	try:
		return int(h,16)
	except Exception:
		print("Couldn't hex decode",flush=True)
		sys.exit()

header = \
"""Dear Santa,
Last christmas you gave me your public key,
to confirm it really is you please sign three
different messages with your private key.

Here is the public key you gave me:"""
print(header,flush=True)
print(key.publickey().exportKey().decode("utf-8"),flush=True)
ms = []

for i in range(1,4):
	m = h2i(input("Message %d you signed (hex encoded):" % i))
	if m in ms:
		print("I said different messages!",flush=True)
		sys.exit()
	s = [h2i(input("Signature %d:" % i))]
	if not key.verify(m,s):
		print("Looks like you aren't Santa after all!",flush=True)
		sys.exit()
	ms.append(m)

print("Hello Santa, here is your flag:",flush=True)
with open("flag",'r') as flag:
	print(flag.read(),flush=True)
```

# Solution

This challenge uses textbook RSA, which means there is no padding.

In textbook RSA the signature is calculated with: ![](https://latex.codecogs.com/png.latex?%24m%5Ed%20%3D%20s%20%28%5Cbmod%20n%29%24)
But we don't have *d*, we only have the public key, which consists of *n* and *e*.

We can abuse the following properties:

- ![](https://latex.codecogs.com/png.latex?%240%5Ed%20%3D%200%20%28%5Cbmod%20n%29%20%3D%200%24)
- ![](https://latex.codecogs.com/png.latex?%241%5Ed%20%3D%201%20%28%5Cbmod%20n%29%20%3D%201%24)
- ![](https://latex.codecogs.com/png.latex?%24n-1%5Ed%20%3D%20n-1%20%28%5Cbmod%20n%29%20%3D%20n-1%24)

Three cases where the message and the corresponding signature are identical. This is enough to solve the challenge.

```Python
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
```

However there is another way to forge textbook signatures. 
Instead of choosing a message we choose a random signature and generate a corresponding message:
![](https://latex.codecogs.com/png.latex?%24m%3Ds%5Ee%28%5Cbmod%20n%29%24)
