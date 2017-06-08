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

# noinspection PyBroadException
class IpChecker():
    def __init__ (self, remote_addr):
        self.remote_addr = remote_addr
        self.lock = threading.Lock()

    def up(self):
        self.lock.acquire()
        try:
            ping = sr1(IP(dst=self.remote_addr)/ICMP(), timeout=10, verbose=0)
            if str(type(ping)) == "<type 'NoneType'>":
                return False
            return True
        except:
            return False
        finally:
            self.lock.release()


'''
A sequentianl PortScanner will do work in the same thread that called start()

A parallel PortScanner will spawn workers!
'''
class PortScanner(object):

    TYPE_SCAN_SYN = 0
    TYPE_SCAN_CONNECT = 1
    TYPE_SCANNER_SEQ = 2
    TYPE_SCANNER_PAR = 3


    WORKER_JOB_THRESH = 10

    def init_seq(self):
        pass

    def init_par(self):
        self.workers = []
        for ip in self.workload:
            self.worker_results[ip] = {'open' : [], 'closed' : []}
            print ip
            ports = self.workload[ip]
            nworkers = len(ports) / 10 if len(ports) / 10 == 0 else len(ports) / 10 + 1
            print 'Requested %s: %s. Will spawn %d workers' % (ip, str(ports), nworkers)

            chunk = len(ports) / nworkers
            left = len(ports) % nworkers
            for i in range(nworkers):
                worker_load = ports[i * chunk: (i + 1) * chunk]
                if left != 0:
                    worker_load.append(ports[len(ports) - left])
                    left = left - 1
                self.workers.append(_PortScannerWorker(ip, self.scan_type, worker_load, self))

    def __init__(self, workload, scan_type, scanner_type):
        self.start_port = 80
        self.end_port = 90
        self.ports = range(self.start_port, self.end_port + 1)

        self.scan_type = scan_type
        self.scanner_type = scanner_type
        self.workload = workload
        self.worker_results = {}

        self.lock = threading.Lock()

        if self.scanner_type == PortScanner.TYPE_SCANNER_SEQ:
            self.init_seq()
        elif self.scanner_type == PortScanner.TYPE_SCANNER_PAR:
            self.init_par()
        else:
            raise ValueError('Got scan_type = %d. Expected PortScanner.TYPE_SCANNER_SEQ(2) | PortScanner.TYPE_SCANNER_PAR(3)' % self.scan_type)

        #self.ip = IP(dst=self.REMOTE_ADDR)

    # Thread-safe method for updating the total results dict
    # To be used by each worker
    # @ip - Ip key to the global dictionary
    # @open - A list of open ports
    # @closed - A list of closed ports
    def update_results(self, ip, open, closed):
        self.lock.acquire()
        if len(open) > 0:
            self.worker_results[ip]['open'] = self.worker_results[ip]['open'] + open
        if len(closed) > 0:
            self.worker_results[ip]['closed'] = self.worker_results[ip]['closed'] + closed
        self.lock.release()

    def results(self):
        return self.worker_results

    def start_seq(self):
        pass

    def start_par(self):
        for worker in self.workers:
            print 'Worker Started: ' + str(worker.ip_addr) + ':' + str(worker.ports) + (' SYN' if worker.scan_type == PortScanner.TYPE_SCAN_SYN else ' CONNECT')

            worker.start()
        for worker in self.workers:
            worker.join()

    def start(self):
        if self.scanner_type == PortScanner.TYPE_SCANNER_PAR:
            self.start_par()
        else:
            self.start_seq()

        #print self.worker_results

    def init_net(self):
        pass

    def connect_scan(self):
        pass

    def run(self):
        if self.scan_type == PortScanner.TYPE_SCAN_SYN:
            self.syn_scan()
        elif self.scan_type == PortScanner.TYPE_SCAN_CONNECT:
            self.connect_scan()
        else:
            print "Invalid Scan Type: %s" % self.scan_type



class _PortScannerWorker(threading.Thread):
    def __init__(self, ip_addr, scan_type, ports, parent):
        threading.Thread.__init__(self)
        self.scan_type = scan_type
        self.ip_addr = ip_addr
        self.ports = ports
        self.parent = parent
        self.open = []
        self.closed = []


    # def run(self):
    #     print 'Worker Started: ' + str(self.ip_addr) + (' SYN' if self.scan_type == PortScanner.TYPE_SCAN_SYN else ' CONNECT')


    def syn_scan(self):
        for port in self.ports:
            sport = random.randint(1024, 65535)
            syn = TCP(sport=sport, dport=port, flags='S', seq=1000)
            res = sr1(IP(dst=self.ip_addr) / syn, timeout=1, verbose=0)
            if str(type(res)) == "<type 'NoneType'>":
                self.closed.append(port)
            elif res.haslayer(TCP):
                if res.getlayer(TCP).flags == 0x12:
                    rst = sr(IP(dst=self.ip_addr) / TCP(sport=sport, dport=port, flags='AR'), timeout=1, verbose=0)
                    self.open.append(port)

                elif res.getlayer(TCP).flags == 0x14:
                    self.closed.append(port)
        self.parent.update_results(self.ip_addr, self.open, self.closed)

    def connect_scan(self):
        pass

    def run(self):
        self.syn_scan()


class API():
    pass