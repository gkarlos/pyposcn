import argparse
import os
from api.networking import KnownPorts
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

    port_group = parser.add_mutually_exclusive_group(required='-H' in sys.argv)
    port_group.add_argument('-pr', nargs=2, metavar='port', type=int, help='port range')
    port_group.add_argument('-ps', nargs='+', metavar='port', type=str, help='space separated list of ports')
    port_group.add_argument('-pa', action='store_true', help='all ports (1024 - 65536)')
    port_group.add_argument('-pc', action='store_true', help='most common ports')

    parser.add_argument('-f',  nargs=1, metavar='filename', type=str, help='file name')

    verbose_group = parser.add_mutually_exclusive_group()
    verbose_group.add_argument('-v', action='store_true', help='verbose output level 1')  #verbose level 1
    verbose_group.add_argument('-vv', action='store_true', help='verbose output level 2') #verbose level 2

    # Amount of time to wait for response in ms
    timeout_group = parser.add_mutually_exclusive_group()
    timeout_group.add_argument('-te', nargs=1, metavar='timeout', type=int, help='ms to for response')
    timeout_group.add_argument('-trand', '--trand', action='store_true', help='randomized timeout waiting for response')

    # Amount of time to wait before sending a new request for a different port to the same host
    # This is a per-thread wait and requests from multiple threads will overlap!
    wait_group = parser.add_mutually_exclusive_group()
    wait_group.add_argument('-we', nargs=1, metavar='wait_time', type=int, help='wait time between attempts to the same host')
    wait_group.add_argument('-wrand', '--wrand', action='store_true', help='randomized wait time')

    # Maximum number of ports per thread
    parser.add_argument('-ppt', metavar='num_ports', nargs=1, type=int, help="ports per thread")

    scan_type_group = parser.add_mutually_exclusive_group()
    scan_type_group.add_argument('-syn', '--syn', action='store_true', help='SYN scan')
    scan_type_group.add_argument('-connect', '--connect', action='store_true', help='Full TCP    handshake scan')
    scan_type_group.add_argument('-fin', '--fin', action='store_true', help='FIN scan')

    scanner_type_group = parser.add_mutually_exclusive_group()
    scanner_type_group.add_argument('-seq', '--seq', action='store_true', help='Sequential scanning')
    scanner_type_group.add_argument('-par', '--par', action='store_true', help='Parallel scanning')

    parser.add_argument('--version', '-version', action='version', version='Pyposcn (version 0.1 dev)')
    args = parser.parse_args()

    if args.syn:
        args.scan_type = 'syn'
    elif args.fin:
        args.scan_type = 'fin'
    elif args.connect:
        args.scan_type = 'connect'
    else:
        args.scan_type = None
    return args


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
    scan_type = PortScanner.SCAN_TYPE_SYN if args.syn else \
        (PortScanner.SCAN_TYPE_CONNECT if args.connect else PortScanner.SCAN_TYPE_FIN)
    scanner_type = PortScanner.SCANNER_TYPE_PAR if args.par else PortScanner.SCANNER_TYPE_SEQ
    workload = Parser(args.F).get() if args.F else single_address_input(args)
    scanner = PortScanner(workload, scan_type, scanner_type)
    scanner.start()
    print scanner.results()


def start(args):
    if args.connect:
        pass
    elif args.syn or args.fin:
        if not is_sudo():
            if query("Need root permissions. Do a connect() scan instead?"):
                args.connect = True
                args.syn = False
                args.fin = False
            else:
                sys.exit(1)
    else:
        if query("No scan type set. Do a SYN scan?"):
            if is_sudo():
                args.syn = True
            else:
                if query("Need root permissions. Do a connect() scan instead?"):
                    args.connect = True
                else:
                    sys.exit(1)
        else:
            sys.exit(1)

    scan(args)


if __name__ == '__main__':
    start(arg_parse())
