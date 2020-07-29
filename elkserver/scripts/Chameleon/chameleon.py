import argparse
import sys
from datetime import datetime, timezone
from modules import *
import re


class Chameleon:

    def __init__(self):
        pass

    def validate_args(self):
        parser = argparse.ArgumentParser(description="")
        parser.add_argument("--proxy", metavar="<proxy>", dest="proxy", default=None,
                            help="Proxy type: a = all, b = bluecoat, m = mcafee, i = IBM Xforce")
        parser.add_argument("--check", action='store_true', help="Perform check on current category")
        parser.add_argument("--submit", action='store_true', help="Submit new category")
        parser.add_argument("--domain", metavar="<domain>", dest="domain", default=None, help="Domain to validate")
        parser.add_argument("--redelk", action='store_true', help="Enable RedELK integration")
        args = parser.parse_args()

        if not args.proxy:
            print("[-] Missing --proxy argument")
            sys.exit(-1)
        if not args.domain and not args.redelk:
            print("[-] Missing --domain argument")
            sys.exit(-1)
        if (not args.check and not args.submit) and not args.redelk:
            print("[-] Missing --check or --submit argument")
            sys.exit(-1)
        if args.redelk:
            try:
                # Validating we can open and write files
                filein=open("/etc/redelk/redteamdomains.conf","r")
                fileroguedomains=open("/etc/redelk/roguedomains.conf","r")
                fileout=open("/var/log/redelk/redteamdomaincheck.txt","a+")
                filein.close()
                fileroguedomains.close()
                fileout.close()
            except:
                print("Error opening infile or outfile")
                sys.exit(-1)
        return args

    def show_banner(self):
        with open('banner.txt', 'r') as f:
            data = f.read()
            print("\033[92m%s\033[0;0m" % data)

    def run(self, args):
        if args.redelk:
            fileout=open("/var/log/redelk/redteamdomaincheck.txt","a+")
            print("\033[1;34m[-] Checking local RedELK file /etc/redelk/roguedomains.conf\033[0;0m")
            fileroguedomains=open("/etc/redelk/roguedomains.conf","r")
            print("[-] Checking category for " + args.domain)
            for line in fileroguedomains:
                if re.search(args.domain, line):
                    words = re.split('#', line)
                    print("\033[1;31m[-] Known malware according to RedELK roguedomains.conf\033[0;0m")
                    fileout.write(datetime.now(timezone.utc).strftime("%Y/%m/%d, %H:%M:%S") + " Domain: " + args.domain  + " Source: RedELK wizardry Results: malware according to " + words[1].strip() + "\n")
        
        if args.proxy == 'm' or args.proxy == 'a':
            print("\033[1;34m[-] Targeting McAfee Trustedsource\033[0;0m")
            ts = trustedsource.TrustedSource(args.domain)
            if args.check:
                checkresults = ts.check_category(False).strip("- ")
                if args.redelk:
                    fileout.write(datetime.now(timezone.utc).strftime("%Y/%m/%d, %H:%M:%S") + " Domain: " + args.domain  + " Source: McAfee Trustedsource Results: " + checkresults + "\n")
            elif args.submit:
                ts.check_category(True)

        if args.proxy == 'b' or args.proxy == 'a':
            print("\033[1;34m[-] Targeting Bluecoat WebPulse\033[0;0m")
            if args.check:
                b = bluecoat.Bluecoat(args.domain, 'https://www.bankofamerica.com')
                checkresults = b.check_category()
                if args.redelk:
                    fileout.write(datetime.now(timezone.utc).strftime("%Y/%m/%d, %H:%M:%S") + " Domain: " + args.domain  + " Source: Bluecoat WebPulse Results: " + checkresults + "\n")
            elif args.submit:
                print(
                    "\033[1;31m[-] WARNING: This module must be run from the webserver you want to categorise\033[0;0m")
                print("\033[1;31m[-] Proceed: Y/N\033[0;0m")
                while True:
                    choice = input().lower()
                    if choice == 'Y' or choice == 'y':
                        b = bluecoat.Bluecoat(args.domain, 'https://www.bankofamerica.com')
                        b.run()
                        break
                    elif choice == 'N' or choice == 'n':
                        break

        if args.proxy == 'i' or args.proxy == 'a':
            print("\033[1;34m[-] Targeting IBM Xforce\033[0;0m")
            xf = ibmxforce.IBMXforce(args.domain)
            if args.check:
                checkresults = xf.checkIBMxForce()
                if args.redelk:
                    fileout.write(datetime.now(timezone.utc).strftime("%Y/%m/%d, %H:%M:%S") + " Domain: " + args.domain  + " Source: IBM Xforce Results: " + checkresults + "\n")
            elif args.submit:
                xf.submit_category()
        
        if args.redelk:
            fileout.close()


if __name__ == "__main__":
    c = Chameleon()
    c.show_banner()
    args = c.validate_args()
    if args.redelk:
        with open("/etc/redelk/redteamdomains.conf","r") as filein:
            for line in filein:
                if not line[0] == "#" and line.strip():
                    args.domain = line.rstrip()
                    args.check = True
                    c.run(args)
    else:
        c.run(args)
