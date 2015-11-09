from scapy.all import *
from time import sleep

'''
  Test suite for port knocking application
'''

AUTH_PORT = 1332
DEFAULT_SEQ = [1489, 32345, 41405, 52081]
SERVER = '10.0.0.2'
KNOCK_FILE = 'test_keys.txt'
keys = []

def load_knocks():
    with open(KNOCK_FILE, 'r') as infile:
        for line in infile:
            keys.append(map(int, line.split(',')))

def send_auth(knock_seq):
    """ Sends auth_init packet as current host """
    timeout = 1
    send(IP(dst=SERVER)/TCP(dport=AUTH_PORT))
    sleep(1)
    return sr(IP(dst=SERVER)/TCP(dport=knock_seq),timeout=timeout)

# arguments to select knock to use?
load_knocks()
ans,unans = send_auth(keys[1])

print ('answered %d' % len(ans))
print ('unanswered %d' % len(unans))
