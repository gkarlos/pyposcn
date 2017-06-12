import argparse
from api.networking import KnownPorts
import os
import sys
from utils import Parser

from api.networking import PortScanner, IpChecker

ip = port_start = port_end = file_out = verbose = 0

SYN_SCAN = PortScanner.TYPE_SCAN_SYN
CONNECT_SCAN = PortScanner.TYPE_SCAN_CONNECT
DEFAULT_PORTS = range(1024, 65536)


def sudo_check():
    if os.getuid() != 0:
        print >> sys.stderr, 'You need root permissions!'
        sys.exit(1)


def ip_check(ip):
    # type: (object) -> object
    if not IpChecker(ip).valid():
        print >> sys.stderr, 'Invalid IP address %s' % ip
        return False
    return True


def arg_parse():
    parser = argparse.ArgumentParser(description="Pyposcn port scanner")

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-H', nargs=1, metavar='ip', type=str, help='target ip address')
    input_group.add_argument('-F', nargs='+', metavar='filename', help='input file')

    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('-pr', nargs=2, metavar='port', type=int, help='port range')
    port_group.add_argument('-ps', nargs='+', metavar='port', type=str, help='space separated list of ports')
    port_group.add_argument('-pa', action='store_true', help='all ports (1024 - 65536)')
    port_group.add_argument('-pc', action='store_true', help='most common ports')

    parser.add_argument('-f',  nargs=1, metavar='filename', type=str, help='file name')

    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument('-v', action='store_true', help='verbose output level 1')  #verbose level 1
    verbose_group.add_argument('-vv', action='store_true', help='verbose output level 2') #verbose level 2

    timeout_group = parser.add_mutually_exclusive_group()
    timeout_group.add_argument('-te', nargs=1, metavar='timeout', type=float, help='timeout between attempts')
    timeout_group.add_argument('-trand', '--trand', action='store_true', help='randomized timeout')

    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument('-syn', '--syn', action='store_true', help='SYN scan')
    scan_type_group.add_argument('-connect', '--connect', action='store_true', help='Full TCP    handshake scan')
    scan_type_group.add_argument('-fin', '--fin', action='store_true', help='FIN scan')

    scanner_type_group = parser.add_mutually_exclusive_group()
    scanner_type_group.add_argument('-seq', '--seq', action='store_true', help='Sequential scanning')
    scanner_type_group.add_argument('-par', '--par', action='store_true', help='Parallel scanning')



    parser.add_argument('--version', '-version', action='version', version='Pyposcn (version 0.1 dev)')
    args = parser.parse_args()
    #ip_check(args.H)
    global ip, port_start, port_end, file_out
    ip = '192.168.1.1'#args.ip[0]
    port_start = 1110
    port_end = 1120
    return args

def scan(ip, ports):
    print ["Scanning", ip, ports]


def create_scanner_input() :
    return { ip: range(80, 1080) }


def scan_ports(ip, start, end, file=None):
    if not IpChecker(ip).up():
        print 'Remote host is down. Exiting...'
        return

    scanner = PortScanner(create_scanner_input(), PortScanner.TYPE_SCAN_SYN, PortScanner.TYPE_SCANNER_PAR)
    scanner.start() # blocking call
    res = scanner.results()

    print res


def scan_single(args):
    print 'Single IP scan'

def scan_bulk(args):
    print 'Bulk scan. Input files: ', args.F
    workload = Parser(args.F).get()
    print workload

def start(args):
    if args.H:
        scan_single(args)
    elif args.F:
        scan_bulk(args)



if __name__ == '__main__':
    sudo_check()
    #KnownPorts.pretty_print()
    start(arg_parse())



#scan_ports(ip, 1111, 1111)
