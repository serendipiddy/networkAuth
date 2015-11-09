from scapy.all import *
from time import sleep

'''
  Test suite for port knocking application
      -auth full  # complete auth
      -auth init  # only send init port 
      -auth first # only send init and first knock 
      -auth last  # send all except last knock
          (more custom, send it manually)
      -ping tcp | udp | icmp | arp
      -dst  ip or mac of destination (check regex matches IP/MAC)
      -port port to ping (if IP)
'''

AUTH_PORT = 1332
DEFAULT_SEQ = [1489, 32345, 41405, 52081]
SERVER = '10.0.0.2'
KNOCK_FILE = 'test_keys.txt'
keys = []
hosts = ['h1','h3','h4','h5','h6','h7','h8']
server = 'h2'

def load_knocks():
    with open(KNOCK_FILE, 'r') as infile:
        for line in infile:
            keys.append(map(int, line.split(',')))

def send_auth(knock_seq, host):
    """ Sends auth_init packet as host """
    timeout = 1
    send(IP(dst=SERVER)/TCP(dport=AUTH_PORT))
    sleep(1)
    return sr(IP(dst=SERVER)/TCP(dport=knock_seq),timeout=timeout)

# arguments to select knock to use?
load_knocks()
ans,unans = send_auth(keys[1], hosts[0])

print ('answered %d' % len(ans))
print ('unanswered %d' % len(unans))

def main(argv):
    try:
      opts, args = getopt.getopt(argv,"ht:n:s:",[]) # pulls out the specified options, ":" means followed by an argument
    except getopt.GetoptError:
      print help
      sys.exit(2)
      
    nodes = 3
    type = 'tree' # type = 'linear'
    split = 2
      
    for opt, arg in opts:
      if opt == '-h':
        print help
        sys.exit()
      elif opt == ':

if __name__ == "__main__":
  main(sys.argv[1:])
