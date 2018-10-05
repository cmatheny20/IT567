README.md

Port scannning tool written in Python. This tool has capability to do TCP and ICMP scanning. It also is able to do a trace route. Traceroute and ICMP will only work on linux. The port scanning tool has the option to print some basic output to a pdf. fpdf must be installed for this to work. 

command: python portscanner.py -h

Help message:
usage: portscanner.py [-h] [-v] [-sS] [-p PORTS] [-tr] [-P] [-sI] [-t TARGETS]

portscanner.py - Replicates limited nmap functionality in python

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable this for full output
  -sS, --tcpscan        Enable this for TCP scans
  -p PORTS, --ports PORTS
                        The ports you want to scan (e.g. 21,22,80,443,445)
  -tr, --traceroute     Does a traceroute (only for linux)
  -P, --pdf             Out puts info to a pdf file
  -sI, --icmpscan       ICMP scan
  -t TARGETS, --targets TARGETS
                        The target(s) you want to scan (e.g. 192.168.0.1 or
                        target,target or 192.168.1.0/24 or target-target)
