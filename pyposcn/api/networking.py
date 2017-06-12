import threading
import os
import socket
import time
from scapy.layers.inet import IP, TCP, random, sr1, ICMP, sr

class KnownPorts(object):
    COMMON = {
        7: 'Echo',
        18: 'MSP',
        20: 'FTP-data',
        21: 'FTP-control',
        22: 'SSH',
        23: 'TELNET',
        25: 'SMTP',
        37: 'Time Protocol',
        38: 'Route Access Protocol (RAP)',
        43: 'WHOIS',
        53: 'DNS',
        69: 'TFTP',
        70: 'Gopher',
        79: 'Finger',
        80: 'HTTP',
        88: 'Kerberos',
        103: 'X.400',
        109: 'POP2',
        110: 'POP3',
        115: 'SFTP',
        119: 'NNTP',
        123: 'NTP',
        137: 'NETBIOS-NS',
        138: 'NETBIOS-DGM',
        139: 'NETBIOS-SSN',
        143: 'IMAP',
        152: 'BFTP',
        153: 'SGMP',
        156: 'SQL-SERVER',
        158: 'DMSP',
        161: 'SNMP',
        162: 'SNMP Trap',
        179: 'BGP',
        194: 'IRC',
        199: 'SMUX',
        213: 'IPX',
        220: 'IMAP3',
        264: 'BGMP',
        318: 'TSP',
        389: 'LDAP',
        427: 'SLP',
        443: 'HTTPS',
        444: 'SNPP',
        445: 'MS-DS Active Directory/SMB',
        464: 'Kerberos Change/Set password',
        500: 'ISAKMP/IKE',
        512: 'Rexec',
        520: 'RIP',
        521: 'RIPNG',
        524: 'NCP',
        530: 'RPC',
        543: 'Kerberos Login',
        544: 'Kerberos Remote Shell',
        546: 'DHCP-CLIENT',
        547: 'DHCP-SERVER',
        548: 'Apple Filing Protocol (AFP)',
        593: 'HTTP RPC',
        631: 'Internet Printing Protocol (IPP)',
        636: 'LDAPS',
        639: 'MSDP',
        749: 'Kerberos Administration',
        750: 'Kerberos v4',
        830: 'NETCONF-SSH',
        831: 'NETCONF-BEEP',
        832: 'NETCONF-HTTPS for SOAP',
        833: 'NETCONF-BEEP for SOAP',
        853: 'DNS over TLS',
        873: 'rsync',
        989: 'FTPS-data',
        990: 'FTPS-control',
        992: 'TELNET-TLS/SSL',
        993: 'IMAPS',
        995: 'POP3-SSL',
        993: 'IMAP-SSL',
        2082: 'CPANEL',
        2083: 'CPANEL',
        2086: 'WHM/CPANEL',
        2087: 'WHM/CPANEL',
        3306: 'MYSQL',
        8444: 'PLESK',
        10000: 'VIRTUALMIN/WEBMIN'
    }

    REGISTERED = {
        1029: 'MS-DCOM',
        1080: 'SOCKS',
        1119: 'Blizzard Battle.net chat',
        1167: 'Cisco IP SLA',
        1194: 'OpenVPN',
        1220: 'Quicktime Streaming Service',
        1414: 'IBM WebSphere MQ',
        1723: 'PPTP',
        1755: 'MMS/MS-STREAMING',
        1801: 'Microsoft Message Queueing',
        1900: "SSDP"
              """
                TODO: Add more ports!
              """
    }

    @staticmethod
    def check(p):
        port = int(p)
        if str(port) in KnownPorts.COMMON:
            return KnownPorts.COMMON[str(port)]
        else:
            return ''

    @staticmethod
    def get_common():
        return KnownPorts.COMMON

    @staticmethod
    def pretty_print():
        from tabulate import tabulate
        #sorted_common_ports = sorted(KnownPorts.COMMON_PORTS)
        data = [[key, KnownPorts.COMMON[key]] for key in sorted(KnownPorts.COMMON)]
        #data = map(list, KnownPorts.COMMON_PORTS.items())
        print tabulate(data, headers=['#', 'Port', 'Service'], tablefmt='orgtbl', showindex='always')



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
    ADDR_TYPE_IPV4 = 0
    ADDR_TYPE_IPV6 = 1

    def __init__ (self, remote_addr):
        self.remote_addr = remote_addr
        self.lock = threading.Lock()
        self.type = None

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

    def valid(self):
        if self.type is None:
            return self._is_valid_ipv4_address(self.remote_addr) or self._is_valid_ipv6_address(self.remote_addr)
        return True

    def _is_valid_ipv4_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET, address)
        except AttributeError:  # no inet_pton here, sorry
            try:
                socket.inet_aton(address)
            except socket.error:
                return False
            return address.count('.') == 3
        except socket.error:  # not a valid address
            return False
        self.type = IpChecker.ADDR_TYPE_IPV4
        return True



    def _is_valid_ipv6_address(self, address):
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:  # not a valid address
            return False
        self.type = IpChecker.ADDR_TYPE_IPV6
        return True

    def _find_type(self):
        if self._is_valid_ipv4_address(self.remote_addr):
            self.type = IpChecker.ADDR_TYPE_IPV4
        elif self._is_valid_ipv6_address(self.remote_addr):
            self.type = IpChecker.ADDR_TYPE_IPV6

    def is_ipv4(self):
        if self.type is None:
            self._find_type()
        return self.type == IpChecker.ADDR_TYPE_IPV4

    def is_ipv6(self):
        if self.type is None:
            self._find_type()
        return self.type == IpChecker.ADDR_TYPE_IPV6

    # Not legal


'''
A sequentianl PortScanner will do work in the same thread that called start()

A parallel PortScanner will spawn workers!
'''
class PortScanner(object):

    TYPE_SCAN_SYN = 0
    TYPE_SCAN_CONNECT = 1
    TYPE_SCAN_FIN = 2
    TIMEOUT_FIXED = 3
    TIMEOUT_RANDOM = 4
    TYPE_SCANNER_SEQ = 5
    TYPE_SCANNER_PAR = 6

    _WORKER_JOB_THRESH = 10

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
            time.sleep(0.2)
        self.parent.update_results(self.ip_addr, self.open, self.closed)

    def connect_scan(self):
        for port in self.ports:
            sport = random.randint(1024, 65535)
            sock = socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect(self.ip_addr, port)
                self.open.append(port)
                sock.close()
            except:
                self.closed.append(port)

            time.sleep(0.2)
        self.parent.update_results(self.ip_addr, self.open, self.closed)

    def _next_timeout(self):
        """
        Check timeout strategy and return an appropriate value
        :return:
        """
        return 0.1

    def run(self):
        if self.scan_type == PortScanner.TYPE_SCAN_SYN:
            self.syn_scan()
        elif self.scan_type == PortScanner.TYPE_SCAN_CONNECT:
            self.connect_scan()
        else:
            raise ValueError('Requested Invalid scan type: %d' % self.scan_type )


class API():
    pass