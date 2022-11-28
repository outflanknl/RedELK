#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Part of RedELK
# Script to parse Cobalt Strike data in .bin files
#
# Author: Outflank B.V. / Marc Smeets
# Shameless copy-paste-modify from original script "export_TSv.py" from Alyssa @ramen0x3f (https://github.com/ramen0x3f/AggressorScripts/blob/master/export_TSv.py)
#

from argparse import ArgumentParser, RawTextHelpFormatter
from javaobj import loads
from os import path
from sys import argv
from pprint import pprint


def print_tsv(data_type, data, prefix):

    with open(prefix + "_" + data_type + ".tsv", "w") as output_file:

        ## Cred-it where it's due
        if data_type == "credentials":
            print("[+] Parsing credentials")
            print(
                "#User\tPassword/Hash\tExtracted from\tExtracted via", file=output_file
            )
            for d in data:
                print(
                    "{}\\{}\t{}\t{}\t{}".format(
                        d["realm"], d["user"], d["password"], d["host"], d["source"]
                    ),
                    file=output_file,
                )
            print("[+] Completed parsing credentials")

        ## Listen here, pal
        elif data_type == "listeners":
            print("[+] Parsing listeners")
            print(
                "#Listener name\tHost\tPort\tBeacons\tListener type\tPort bind\tC2 Profile\tProxy",
                file=output_file,
            )
            for d in data:
                name = d["name"] if "name" in d else ""
                host = d["host"] if "host" in d else ""
                port = d["port"] if "port" in d else ""
                beacons = d["beacons"] if "beacons" in d else ""
                payload = d["payload"] if "payload" in d else ""
                bindto = d["bindto"] if "bindto" in d else ""
                profile = d["profile"] if "profile" in d else ""
                proxy = d["proxy"] if "proxy" in d else ""
                print(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(
                        name, host, port, beacons, payload, bindto, profile, proxy
                    ),
                    file=output_file,
                )
            print("[+] Completed parsing listeners")

        ## (ob)Session. By Calvin Klein.
        elif data_type == "sessions":
            print("[+] Parsing sessions")
            print(
                "#Hostname\tInternal IP\tExternal IP\tUser (beacon running as)\tDate/Time session created\tOS Version\tNote",
                file=output_file,
            )
            for d in data:
                print(
                    "{}\t{}\t{}\t{}\t{}\t{} {}\t{}".format(
                        d["computer"],
                        d["host"],
                        d["external"],
                        d["user"],
                        d["opened"],
                        d["os"],
                        d["ver"],
                        d["note"],
                    ),
                    file=output_file,
                )
            print("[+] Completed parsing sessions")

        ## Better than Walmart
        elif data_type == "targets":
            print("[+] Parsing targets")
            print("#Hostname\tIP Address\tOS Version", file=output_file)
            for d in data:
                print(
                    "{}\t{}\t{} {}".format(
                        d["name"], d["address"], d["os"], d["version"]
                    ),
                    file=output_file,
                )
            print("[+] Completed parsing targets")

        ## Don't loose control
        elif data_type == "c2info":
            print("[+] Parsing c2info")
            print("#Beacon ID\tDomains\tPort\tProtocol", file=output_file)
            for d in data:
                bid = d["bid"] if "bid" in d else ""
                domains = d["domains"] if "domains" in d else ""
                port = d["port"] if "port" in d else ""
                proto = d["proto"] if "proto" in d else ""
                print(
                    "{}\t{}\t{}\t{}".format(bid, domains, port, proto), file=output_file
                )
            print("[+] Completed parsing c2info")

        ## If you fail this badly, I'm impressed.
        else:
            print("[!] Invalid data type chosen")


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Export TSVs of data from Teamserver data/*.bins"
    )

    ## For arguments sake
    parser.add_argument(
        "--credentials", type=str, help="Provide a credentials.bin file"
    )
    parser.add_argument("--listeners", type=str, help="Provide a listeners.bin file")
    parser.add_argument("--sessions", type=str, help="Provide a sessions.bin file")
    parser.add_argument("--targets", type=str, help="Provide a targets.bin file")
    parser.add_argument("--c2info", type=str, help="Provide a c2info.bin file")
    parser.add_argument(
        "--prefix", type=str, help='Prefix for TSV files. Default is "export".'
    )

    ## This script is like life. You get out of it what you put into it.
    if len(argv) == 1:
        parser.print_help()
        exit()

    ## Lazy people get lazy filenames
    args = parser.parse_args()
    prefix = args.prefix if args.prefix else "export"

    ## BINgo was his name-o
    try:
        print("[+] Export time!")
        if args.credentials and path.exists(args.credentials):
            print_tsv(
                "credentials",
                [d for k, d in loads(open(args.credentials, "rb").read()).items()],
                prefix,
            )
        if args.listeners and path.exists(args.listeners):
            print_tsv(
                "listeners",
                [d for k, d in loads(open(args.listeners, "rb").read()).items()],
                prefix,
            )
        if args.sessions and path.exists(args.sessions):
            print_tsv(
                "sessions",
                [d for k, d in loads(open(args.sessions, "rb").read()).items()],
                prefix,
            )
        if args.targets and path.exists(args.targets):
            print_tsv(
                "targets",
                [d for k, d in loads(open(args.targets, "rb").read()).items()],
                prefix,
            )
        if args.c2info and path.exists(args.c2info):
            print_tsv(
                "c2info",
                [d for k, d in loads(open(args.c2info, "rb").read()).items()],
                prefix,
            )
    except:
        print(
            "[!] Something went wrong, but I'm too lazy to put in more validation. Check your input files or whatever."
        )
