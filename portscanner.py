#-------------------------------------------------------------------------------
# Name:             portscanner.py
# Purpose:          Replicates limited nmap functionality using python
# Author:           Cole Matheny
# Base Code Source: https://www.phillips321.co.uk/2014/08/12/python-port-scanner-nmap-py/
# Worked with:      Chandler Taylor and Tanar Wyatt
#-------------------------------------------------------------------------------

import socket
import argparse
import sys
import time
import subprocess
from fpdf import FPDF

def main():

    starttime=time.time()

    #creates pdf 
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font('Arial', 'B', 16)

    # Start Scanning
    results={}
    for target in targets:
        if args.traceroute:
            traceroute(target)
        if args.icmpscan:
            if ICMPscan(target) == 1:
                print target,"is up"
            else:
                print target,"is down"
        if args.tcpscan:
            results[target]= portscan(target,ports,args.tcpscan,args.verbose,pdf)
    printmsg(("Total scantime %.2f seconds") % (time.time()-starttime))

    #puts the pdf object to a pdf file
    if args.pdf :
        pdf.output('portscanner.pdf', 'F')

    
    

    return results

def portscan(target,ports,tcp,verbose,pdf):
    #target=IPaddr,ports=list of ports,tcp=true/false,udp=true/false,verbose=true/false
    tcpports=[]
    udpports=[]
    targetstarttime=time.time()
    if tcp:
        for portnum in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.01)
                s.connect((target, portnum))
            except Exception:
                failvar = 0
                
            else:
                if verbose: print "%d/tcp \topen"% (portnum),
                if portnum == 80:
                    grabHTTP(s)
                else:
                    grab(s, portnum)
                tcpports.append(portnum)
            s.close()
    
    printmsg(("Scanned %s in %.2f seconds - Open: %i TCP ports" % \
                (target,time.time()-targetstarttime,len(tcpports))))

    pdf.cell(40,10, ("Scanned %s in %.2f seconds - Open: %i TCP ports" % \
                (target,time.time()-targetstarttime,len(tcpports))), ln = 1)
    return tcpports

def errormsg(msg): print "[!] Error: %s" % (msg) ; sys.exit(1)
def printmsg(msg): print "[+] portscanner.py: %s" % (msg)

def iprange(addressrange): # converts a ip range into a list
    list=[]
    first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
    for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1].split('.')[3])+1):
        list.append(first3octets+str(i))
    return list

def ICMPscan(target):
    reply = 0
    try:
        icmp = subprocess.Popen(["ping", target, '-c', '1', '-W', '1'],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(icmp.stdout.readline,""):
            #print line
            if "1 received" in line:
                reply = 1

    except:
        pass
    return reply

#the next couple of functions help parse through ip ranges like CIDR, I got them from the source listed above
def ip2bin(ip):
    b = ""
    inQuads = ip.split(".")
    outQuads = 4
    for q in inQuads:
        if q != "": b += dec2bin(int(q),8); outQuads -= 1
    while outQuads > 0: b += "00000000"; outQuads -= 1
    return b

def dec2bin(n,d=None):
    s = ""
    while n>0:
        if n&1: s = "1"+s
        else: s = "0"+s
        n >>= 1
    if d is not None:
        while len(s)<d: s = "0"+s
    if s == "": s = "0"
    return s

def bin2ip(b):
    ip = ""
    for i in range(0,len(b),8):
        ip += str(int(b[i:i+8],2))+"."
    return ip[:-1]

def returnCIDR(c):
    parts = c.split("/")
    baseIP = ip2bin(parts[0])
    subnet = int(parts[1])
    ips=[]
    if subnet == 32: return bin2ip(baseIP)
    else:
        ipPrefix = baseIP[:-(32-subnet)]
        for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
        return ips

#gets banner from the port
def grab(conn, portnum):
    try:
        conn.send('Open up! FBI! \r\n')
        ret = conn.recv(1024)
        print '[+]' + str(ret)
        return
    except Exception, e:
        try:
            print '[+] ' + socket.getservbyport(portnum)
        except:
            pass
        return

#gets banner for HTTP port
def grabHTTP(conn):
    try:
        conn.send('GET HTTP/1.1 \r\n')
        ret = conn.recv(1024)
        print '[+]' + str(ret)
        return
    except Exception, e:
        print '[-] Unable to grab any information: ' + str(e)
        return

def traceroute(target):
    traceroute = subprocess.Popen(["traceroute", target],stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in iter(traceroute.stdout.readline,""):
        print line
    


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='portscanner.py - Replicates limited nmap functionality in python')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable this for full output')
    parser.add_argument('-sS', '--tcpscan', action='store_true', help='Enable this for TCP scans')
    parser.add_argument('-p', '--ports', default='1-1024', help='The ports you want to scan (e.g. 21,22,80,443,445)')
    parser.add_argument('-tr', '--traceroute', action='store_true', help='Does a traceroute (only for linux)')
    parser.add_argument('-P', '--pdf', action='store_true', help='Out puts info to a pdf file')
    parser.add_argument('-sI', '--icmpscan', action='store_true', help='ICMP scan')
    parser.add_argument('-t', '--targets', help='The target(s) you want to scan (e.g. 192.168.0.1 or target,target or 192.168.1.0/24 or target-target)')
    if len(sys.argv)==1: parser.print_help(); sys.exit(0)
    args = parser.parse_args()

    # Set target (and convert for FQDN)
    targets=[]
    if args.targets:
        if '/' in args.targets: #found cidr target
            targets = returnCIDR(args.targets)
        elif '-' in args.targets:
            targets = iprange(args.targets)
        elif ',' in args.targets:
            targets = args.targets.split(',')
        else:
            try: targets.append(socket.gethostbyname(args.targets)) # get IP from FQDN
            except: errormsg("Failed to translate hostname to IP address")
    else: parser.print_help(); errormsg("You need to set a hostname")

    # Set ports
    if args.ports == '-': args.ports = '1-65535'
    ranges = (x.split("-") for x in args.ports.split(","))
    ports = [i for r in ranges for i in range(int(r[0]), int(r[-1]) + 1)]


    main()