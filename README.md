# openssh_user_bruteforce
OpenSSH 2.3 &lt; 7.4 - Username Enumeration Multithreaded Bruteforcer. Based on http://www.openwall.com/lists/oss-security/2018/08/15/5

# Usage
```
$ ./openssh_bruteforce.py -h
usage: openssh_bruteforce.py [-h] -host HOSTNAME [-p PORT] [-user USERNAME]
                             [-w WORDLIST]

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Target port. (Default 22)
  -user USERNAME, --username USERNAME
                        Check a single username.
  -w WORDLIST, --wordlist WORDLIST
                        Path to a usernames wordlist.

required arguments:
  -host HOSTNAME, --hostname HOSTNAME
                        The host you want to target.
```
example 
```
$ ./openssh_bruteforce.py -host pwnable.kr -user fd -p 2222
[+] User Exists!
```

# Note
You can find explanation of the technique used inside the script.


#### Credits
This script is heavily based on the POC found on exploit-db https://www.exploit-db.com/exploits/45210/
