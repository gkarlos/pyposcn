import argparse
import threading
from scapy.all import *

ip = port_start = port_end = file_out = 0

SYN_SCAN = 0
CONNECT_SCAN = 1

class PortScanner(threading.Thread):

    def __init__(self, ip, start_port, end_port, scan_type, lock):
        threading.Thread.__init__(self)
        self.thread_id = "thread " + str(start_port) + " - " + str(end_port)
        self.ip = ip
        self.start_port = start_port
        self.end_port = end_port
        self.lock = lock
        self.scan_type = scan_type

    def run(self):
        self.lock.acquire()
        print self.thread_id + " SYN_SCAN" if self.scan_type == 0 else " CONNECT_SCAN"
        self.lock.release()


def arg_parse():
    parser = argparse.ArgumentParser(description="Pyposc port scanner")
    parser.add_argument('-ip', nargs= 1, metavar='addr', type=str, help='target ip address')
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
    lock = threading.Lock()

    thread1 = PortScanner(ip, 1111, 1122, SYN_SCAN, lock)
    thread2 = PortScanner(ip, 1123, 1133, SYN_SCAN, lock)

    #print "unable to start threads"

    thread1.start()
    thread2.start()




arg_parse()
scan_ports(ip, 1111, 1111)
