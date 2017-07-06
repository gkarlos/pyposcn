import argparse
from api.networking import KnownPorts
import os
import sys
from utils import *

from api.networking import PortScanner, IpChecker

ip = port_start = port_end = file_out = verbose = 0

SYN_SCAN = PortScanner.SCAN_TYPE_SYN
CONNECT_SCAN = PortScanner.SCAN_TYPE_CONNECT
FIN_SCAN = PortScanner.SCAN_TYPE_FIN
DEFAULT_PORTS = range(1024, 65536)


def sudo_check_and_exit():
    if os.getuid() != 0:
        print >> sys.stderr, 'You need root permissions!'
        sys.exit(1)

def is_sudo():
    return os.getuid() == 0

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
    input_group.add_argument('-F', nargs='+', metavar='filename', help='input file(s)')

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
    if args.syn:
        args.scan_type = 'syn'
    elif args.fin:
        args.scan_type = 'fin'
    elif args.connect:
        args.scan_type = 'connect'
    else:
        args.scan_type = None

    port_start = 1110
    port_end = 1120
    return args



def create_scanner_input(ip, start, end) :
    return {ip: range(start, end + 1) }


def scan_ports(ip, start, end, type, file=None):
    if not IpChecker(ip).up():
        print 'Remote host is down. Exiting...'
        return

    scanner = PortScanner(create_scanner_input(ip, start, end), type, PortScanner.SCANNER_TYPE_PAR)
    scanner.start()#blocking call
    res = scanner.results()

    print res

def exit_with_message(msg):
    print msg
    sys.exit(1)


def single_address_input(args):
    workload = {}

    if args.pr:
        port_range_start = args.pr[0]
        port_range_end = args.pr[1]
        if port_range_start > port_range_end:
            exit_with_message("Invalid port range")
        if port_range_start < 1:
            if query("Invalid start port: %s. Change to 1?" % port_range_start):
                port_range_start = 1
            else:
                sys.exit(1)
        if port_range_end > 65535:
            if query("Invalid end port: %s. Change to 65535?" % port_range_end):
                port_range_end = 65535
            else:
                sys.exit(1)
        workload = {args.H[0]: range(int(port_range_start), int(port_range_end) + 1) }
    elif args.ps:
        print "its port specific: "
        try:
            ports = map(int, args.ps)
        except ValueError, msg:
            print "Invalid port %s" % str(msg).split(":")[1]
            sys.exit(1)

        for port in ports:
            if port < 1 or port > 65535:
                if not query("Invalid port %d. Scan only valid ports? " % port):
                    sys.exit(1)
                break

        workload = {args.H[0]: list(set([port for port in ports if 0 < port < 65536]))}
    elif args.pa:
        workload = {args.H[0]: DEFAULT_PORTS}
    elif args.pc:
        workload = {args.H[0]: sorted(KnownPorts.COMMON.keys())}

    return workload

def scan(args):
    ##print 'Bulk scan. Input files: ', args.F
    scan_type = PortScanner.SCAN_TYPE_SYN if args.syn else \
        (PortScanner.SCAN_TYPE_CONNECT if args.connect else PortScanner.SCAN_TYPE_FIN)
    scanner_type = PortScanner.SCANNER_TYPE_PAR if args.par else PortScanner.SCANNER_TYPE_SEQ
    workload = Parser(args.F).get() if args.F else single_address_input(args)
    scanner = PortScanner(workload, scan_type, scanner_type)

def start(args):
    if not (args.syn or args.fin or args.connect):
        if query("No scan type set. Do a SYN scan?"):
            if is_sudo():
                args.syn = True
            else:
                if query("Need root permissions. Do a connect() scan instead?"):
                    args.connect = True;
                else:
                    sys.exit(1)
        else:
            sys.exit(1)
    scan(args)

if __name__ == '__main__':
    start(arg_parse())



#scan_ports(ip, 1111, 1111)
