import argparse

parser = argparse.ArgumentParser(description="Pyposc port scanner");
parser.add_argument('-ip', metavar="<addr>", type=str, help='target ip address')
parser.add_argument('-r', metavar="<start> <end> ", type=int, help='port range')


args = parser.parse_args()

print args