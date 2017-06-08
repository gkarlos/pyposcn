import threading
import os
import socket
from scapy.layers.inet import IP, TCP, random, sr1, ICMP, sr

if os.name != "nt":
    import fcntl
    import struct

    def get_interface_ip(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                                ifname[:15]))[20:24])


def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    return ip

LOCAL_ADDR = get_lan_ip()

class IpChecker():
    def __init__ (self, remote_addr):
        self.remote_addr = remote_addr

    def up(self):
        try:
            ping = sr1(IP(dst=self.remote_addr)/ICMP(), timeout=10, verbose=0)
            if ping == None:
                return False
            return True
        except:
            return False

class PortScanner(threading.Thread):

    def __init__(self, ip_addr, start_port, end_port, scan_type, lock):
        threading.Thread.__init__(self)
        self.thread_id = "thread " + str(start_port) + " - " + str(end_port)
        self.REMOTE_ADDR = ip_addr
        self.start_port = 80
        self.end_port = 90
        self.ports = range(self.start_port, self.end_port + 1)
        self.lock = lock
        self.scan_type = scan_type
        self.open = []
        self.closed = []

        from scapy.layers.inet import IP, TCP

        self.ip = IP(dst=self.REMOTE_ADDR)

    def init_net(self):
        pass

    def syn_scan(self):
        pass

    def run(self):
        print self.ports
        for port in self.ports:
            sport = random.randint(1024, 65535)
            syn = TCP(sport=sport, dport=port, flags='S', seq=1000)
            res = sr1(IP(dst=self.REMOTE_ADDR) / syn, timeout=1)
            if str(type(res)) == "<type 'NoneType'>":
                print "port %d is closed" % port
                self.closed.append(port)
            elif res.haslayer(TCP):
                if res.getlayer(TCP).flags == 0x12:
                    rst = sr(IP(dst=self.REMOTE_ADDR)/TCP(sport=sport, dport=port, flags='AR'), timeout=1)
                    print "port %d is open" % port
                    self.open.append(port)

                elif res.getlayer(TCP).flags == 0x14:
                    print "port %d is closed"
                    self.closed.append(port)




        self.lock.acquire()
        print self.thread_id + " SYN_SCAN" if self.scan_type == 0 else " CONNECT_SCAN"
        print "OPEN: ", self.open
        print "CLOSED: ", self.closed
        self.lock.release()

class PortScannerWorker():
    pass


class API():
    pass