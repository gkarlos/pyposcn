from api.networking import IpChecker
import sys


def query(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

class Parser(object):

    def __init__(self, input_files):
        self.input_files = input_files
        self.ignored_lines = 0


    def _parse_ip(self, ip_str):
        ip_str = ip_str.strip()
        # print ip_str, len(ip_str)
        return ip_str if IpChecker(ip_str).valid() else None

    def _parse_ports(self, ports_str, line_number):

        try:  # parse a port range
            if ',' not in ports_str:
                raise ValueError

            port_range = map(int, map(str.strip, ports_str.split(',')))

            valid_range = range(1, 65535)
            if len(port_range) != 2:
                print 'Invalid port range at line %d. Too many arguments.'
                return None

            if (port_range[0] not in valid_range) or (port_range[1] not in valid_range):
                print 'Invalid port range bounds at line %d. Must be in [1, 65536]' % (line_number + 1)
                return None

            return range(port_range[0], port_range[1] + 1)
        except ValueError:  # parse a port list
            port_list = map(int, map(str.strip, ports_str.split()))
            if len(port_list) == 0:
                print 'Invalid Ports list at line %d' % (line_number + 1)
                return None
            return port_list

    def _parse_line(self, line, line_number):
        line = line.split('#')
        lhs = line[0].split(':')

        ip = self._parse_ip(lhs[0])
        ports = self._parse_ports(lhs[1].strip(), line_number)

        if ip and ports:
            return ip, ports

        return None

    def _workload_from_file(self, f):
        result = {}
        for i, line in enumerate(f):
            l = self._parse_line(line, i)
            if l:
                result[l[0]] = list(set(result[l[0]] + l[1])) if l[0] in result else l[1]
            else:  # Something went wrong with that line
                self.ignored_lines += 1
        return result

    def get(self):
        result = {}
        for f in self.input_files:
            temp = self._workload_from_file(open(f))
            for ip in temp:
                result[ip] = list(set(result[ip] + temp[ip])) if ip in result else temp[ip]

        if len(result.items()) > 0:
            if self.ignored_lines > 0:

                continue_anyway = query('%d line%s ha%s been ignored. Continue anyway?' %
                    (self.ignored_lines, ('s' if self.ignored_lines > 1 else ''), ('ve' if self.ignored_lines > 1 else 's')))

                if not continue_anyway:
                    sys.exit(1)

            return result
        else:
            if self.ignored_lines > 0:  # Input file had something but everything was wrong
                print 'Bad input file. %d lines ignored. Nothing left to scan. Exiting...' % self.ignored_lines
            else:
                print 'Input file is empty. Exiting...'
            return None
        return result