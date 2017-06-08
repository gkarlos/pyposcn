import argparse
import os
import sys
from Networking import PortScanner, IpChecker

ip = port_start = port_end = file_out = 0

SYN_SCAN = PortScanner.TYPE_SCAN_SYN
CONNECT_SCAN = PortScanner.TYPE_SCAN_SYN


def sudo_check():
    if os.getuid() != 0:
        print >> sys.stderr, 'You need root permissions!'
    sys.exit(1)

def arg_parse():
    parser = argparse.ArgumentParser(description="Pyposcn port scanner")
    parser.add_argument('-ip', nargs=1, metavar='addr', type=str, help='target ip address')
    parser.add_argument('-r',  nargs=2, metavar='port', type=int, help='port range')
    parser.add_argument('-f',  nargs=1, metavar='filename', type=str, help='fine name')

    args = parser.parse_args()
    global ip, port_start, port_end, file_out
    ip = args.ip[0]
    port_start = 1110
    port_end = 1120

def scan(ip, ports):
    print ["Scanning", ip, ports]


def create_scanner_input() :
    return { ip: range(10000, 11000) }


def scan_ports(ip, start, end, file=None):
    if not IpChecker(ip).up():
        print 'Remote host is down. Exiting...'
        return

    scanner = PortScanner(create_scanner_input(), PortScanner.TYPE_SCAN_SYN, PortScanner.TYPE_SCANNER_PAR)
    scanner.start() # blocking call
    res = scanner.results()

    print res






sudo_check()
arg_parse()
scan_ports(ip, 1111, 1111)
