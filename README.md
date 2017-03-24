# Pathzuzy

Python implementation of [Pathzuzu](https://github.com/ShotokanZH/Pa-th-zuzu)

Checks for PATH substitution vulnerabilities, logs the commands executed by the vulnerable executables and injects a reverse shell with the permissions of the owner of the process.

```
    _____      _   _                            __
   / / _ \__ _| |_| |__  _____   _ _____   _   / /
  / / /_)/ _` | __| '_ \|_  / | | |_  / | | | / /
 / / ___/ (_| | |_| | | |/ /| |_| |/ /| |_| |/ /
/_/\/    \__,_|\__|_| |_/___|\__,_/___|\__, /_/
                                       |___/   v0.1.3

usage: pathzuzy.py [-h] [-e CMD] [-r ADDR PORT] [-t SEC] [-g GRP] [-u USR]
                   [-v]
                   ARGV [ARGV ...]

positional arguments:
  ARGV                  binary to check for PATH substitution vulnerabilities
                        & (optional) arguments.

optional arguments:
  -h, --help            show this help message and exit
  -e CMD, --execute CMD
                        executes command CMD if target is vulnerable
  -r ADDR PORT, --reverse ADDR PORT
                        spawns reverse shell to ADDR:PORT
  -t SEC, --timeout SEC
                        timeout (seconds) kills TARGET after SEC seconds
                        (timeout)
  -g GRP, --gid GRP     runs command/shell only if the group is GRP (requires:
                        -r or -e)
  -u USR, --uid USR     runs command/shell only if the user is USR (requires:
                        -r or -e)
  -v, --verbose         verbose
[i] Cleaning up..
```

### How to make it work

- `git clone https://github.com/ShotokanZH/Pathzuzy`
- `cd Pathzuzy`
- `python pathzuzy.py`

### How to update

- `cd Pathzuzy`
- `git pull`

### How to check if everything is ok and [nothing strange happened](https://en.wikipedia.org/wiki/National_Security_Agency) to the file

- `curl https://keybase.io/shotokanzh/key.asc | gpg --import`
- `gpg --verify pathzuzy.py`
