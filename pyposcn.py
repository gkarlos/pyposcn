import argparse
import threading
from Networking import PortScanner, IpChecker

ip = port_start = port_end = file_out = 0

SYN_SCAN = 0
CONNECT_SCAN = 1

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


def scan_ports(ip, start, end, file=None):
    #start threads ranges of ports
    if not IpChecker(ip).up():
        print 'Remote host is down!'
    else:
        print 'Remote host is up'
    lock = threading.Lock()

    thread1 = PortScanner(ip, 80, 1122, SYN_SCAN, lock)
    #thread2 = PortScanner(ip, 1123, 1133, SYN_SCAN, lock)

    #print "unable to start threads"

    thread1.start()
    #thread2.start()




arg_parse()
scan_ports(ip, 1111, 1111)
