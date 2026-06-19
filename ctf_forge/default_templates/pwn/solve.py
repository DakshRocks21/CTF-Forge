#!/usr/bin/env python3
# %challname% (pwn solve script)

from pwn import *

debug = False

if debug:
    r = process("./binary")
    # gdb.attach(r, "b *main\nc")
else:
    r = remote("HOST", 1337)  # %connection_info%

# Example: basic buffer overflow
offset = 72
payload = b"A" * offset + p64(0xdeadbeef)
# r.sendline(payload)

r.interactive()
