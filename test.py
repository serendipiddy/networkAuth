import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress IPv6 error
from scapy.all import *
from time import sleep
import getopt, sys

help = '''
  Test suite for port knocking application
      -auth full  # complete auth
      -auth init  # only send init port 
      -auth noid  # all but first
      -auth first # only send init and first knock 
      -auth last  # send all except last knock
      -auth rev   # reverses auth sequence (attempts n times)
          (more custom, send it manually)
          
      -ping tcp | udp | icmp | arp
      
      -dst  ip or mac of destination (check regex matches IP/MAC)
      -port port to ping (if IP)
      -knock id   # id of knock pattern (0-9)
      -n          # number of times to perform action
      
      -ans        # expected number of ans
      -unans      # expected number of unans
'''

AUTH_PORT = 1332
DEFAULT_SEQ = [1489, 32345, 41405, 52081]
SERVER = '10.0.0.2'
SERVER_MAC = '00:00:00:00:00:02'
KNOCK_FILE = 'test_keys.txt'
INVALID_KNOCK= [7119, 21393, 36101, 59835]
keys = []
# keys 0-9 are correct, key 10 is incorrect
server = 'h2'
timeout = 1

def load_knocks():
    with open(KNOCK_FILE, 'r') as infile:
        for line in infile:
            keys.append(map(int, line.split(',')))

def send_auth(knock_seq, stop=0,init=True):
    """ Sends 'stop' packets as of auth sequence to 'host' """
    if (init): send_init(SERVER)
    if stop == 0:
        return sr(IP(dst=SERVER)/TCP(dport=knock_seq),timeout=timeout,verbose=False)
    return sr(IP(dst=SERVER)/TCP(dport=knock_seq[0:stop]),timeout=timeout,verbose=False)
    
def send_init(host):
    """ Sends the initialising auth packet """
    a = sr(IP(dst=SERVER)/TCP(dport=AUTH_PORT), timeout=timeout, verbose=False)
    sleep(1)  # wait for flow to install
    return a

def ping(protocol, host, port, retry=0, inter=0):
    hosts = []
    for i in range(10): hosts.append(host)
    if protocol == 'tcp': 
        return sr(IP(dst=hosts)/TCP(dport=port),inter=inter,timeout=timeout,retry=retry,verbose=False)
    elif protocol == 'udp': 
        return sr(IP(dst=hosts)/UDP(dport=port),inter=inter,timeout=timeout,retry=retry,verbose=False)
    elif protocol == 'icmp': 
        return sr(IP(dst=hosts)/ICMP(),inter=inter,timeout=timeout,retry=retry,verbose=False)
    elif protocol == 'arp': 
        return arping(hosts,inter=inter,timeout=timeout,retry=retry,verbose=False)
    
def test_send():
    # arguments to select knock to use?
    ans,unans = send_auth(keys[1], hosts[0])

    print ('answered %d' % len(ans))
    print ('unanswered %d' % len(unans))

OPTS = 'aqt:p:k:d:hn' # auth|ping,type, port, knock, dest, help, n
OPTS_LONG = ['auth','ping','type=','dst=','port=','knock=','ans=','unans=']

def main(argv):
    try:
        opts, args = getopt.getopt(argv,OPTS,OPTS_LONG) 
    except getopt.GetoptError:
        print help
        sys.exit(2)
    
    load_knocks()
    
    action = ''
    type = ''
    oo = {}  
    opt_count = 0
    req_opts = {'auth':2,'ping':2}
    answered = 0
    unanswered = 0
    
    for o, a in opts:
        if o == '-h':
            print help
            sys.exit()
        elif o in ('-a','--auth'):
            action = 'auth'
            opt_count += 1
        elif o in ('-q','--ping'):
            action = 'ping'
            opt_count += 1
        elif o in ('-t','--type'):
            type = a
            opt_count += 1
        elif o in ('-d','--dst'):
            oo['dst'] = a
            opt_count += 1
        elif o in ('-p','--port'):
            oo['port'] = map(int,eval(a))
            opt_count += 1
        elif o in ('-k','--knock'):
            i = int(a)
            if i >= 0:
                oo['knock'] = keys[int(a)]
            else:
                print('  selecting invalid knock')
                oo['knock'] = INVALID_KNOCK
            opt_count += 1
        elif o in ('--ans'):
            answered = int(a)
        elif o in ('--unans'):
            unanswered = int(a)
            
    if opt_count < req_opts[action]:
        print('not enough args given (%s-%s) - %d/%d' % (action,type,opt_count,req_opts[action]))
        sys.exit(0)
    
    if 'dst' not in oo:
        oo['dst'] = SERVER
        
    if 'port' not in oo:
        oo['port'] = [0]
    
    if action == 'ping':
        ans,unans = ping(type, oo['dst'], oo['port'])
    elif action == 'auth':
        print('  knock: %s' % ','.join(map(str,oo['knock'])))
        if type == 'full':  
            ans,unans = send_auth(oo['knock'])
        elif type == 'init':  
            ans,unans = send_init(oo['dst'])
        elif type == 'first': 
            ans,unans = send_auth(oo['knock'], 1)
        elif type == 'last':  
            ans,unans = send_auth(oo['knock'], len(oo['knock'])-1)
        elif type == 'noid':
            seq = oo['knock'][1:]
            print('  knock (missing ID): %s' % ','.join(map(str,seq)))
            ans,unans = send_auth(seq, len(seq))
        elif type == 'no_init':   
            ans,unans = send_auth(oo['knock'], len(oo['knock']), init=False)
        elif type == 'rev':   
            seq = []
            seq.append(oo['knock'][0])
            seq.extend(reversed(oo['knock'][1:]))
            print('  knock (out of order): %s' % ','.join(map(str,seq)))
            ans,unans = send_auth(seq)
    else:
        sys.exit(0)
        
    if oo['port'] == [0]:
        ports = ''
    else:
        ports =  ','.join(map(str,oo['port']))
        
    print('  %s %s %s %s' % (action, type, oo['dst'],ports))
    print('  * answered:   %4d  --  %s'%(len(ans),len(ans) == answered))
    print('  * unanswered: %4d  --  %s'%(len(unans),len(unans) == unanswered))
if __name__ == "__main__":
  main(sys.argv[1:])
