import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress IPv6 error
from subprocess import call
from scapy.all import *
from time import sleep

mininet_call = '/home/mininet/mininet/util/m'
directory = '~/networkAuth/'
test_file = 'test.py'

rest_server = 'http://localhost:8080/portknock'
inform_pattern = '/info'
create_pattern = '/create_key'
delete_pattern = '/host/'

def rest_call(fn,aux=''):
    if fn == 'inform': 
        call(['curl',rest_server+inform_pattern])
    elif fn == 'create': 
        call(['curl',rest_server+create_pattern])
    elif fn == 'delete': 
        call(['curl','-X','DELETE',rest_server+delete_pattern+aux])
    
def call_host(host, action, type, *args):
    cmd = [mininet_call, host]
    cmd.extend(('sudo', 'python', test_file))
    cmd.extend((action, '-t', type))
    cmd.extend(args)
    # print(cmd)
    call(cmd)
    
def restart_network():
    call(['sudo','killall','runryu']) 
    call(['sudo','ovs-ofctl','del-flows','s1','-O','OpenFlow13'])
    call(['./runryu'])
    sleep(5)
    
def test0():
    print('=== test #0 -- no access to server, except ARP ===')
    print('h1 icmp, tcp, arp')
    call_host('h1', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h1', '--ping', 'tcp', '-p', '[80,22,100]','--ans','0','--unans','30')
    call_host('h1', '--ping', 'arp','--ans','10','--unans','0')
    print('h3 icmp, tcp, arp')
    call_host('h3', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h3', '--ping', 'tcp', '-p', '[80,22,100]','--ans','0','--unans','30')
    call_host('h3', '--ping', 'arp','--ans','10','--unans','0')
    print('h4 icmp, tcp, arp')
    call_host('h4', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h4', '--ping', 'tcp', '-p', '[80,22,100]','--ans','0','--unans','30')
    call_host('h4', '--ping', 'arp','--ans','10','--unans','0')
    print('h5 icmp, tcp, arp')
    call_host('h5', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h5', '--ping', 'tcp', '-p', '[80,22,100]','--ans','0','--unans','30')
    call_host('h5', '--ping', 'arp','--ans','10','--unans','0')
    
def test1():
    print('=== test #1 -- hosts can communicate ===')
    print('h1 <-> h3')
    call_host('h1', '--ping', 'icmp','--ans','10','--unans','0','-d','10.0.0.3')
    call_host('h1', '--ping', 'tcp', '-p', '[80,22,100]','--ans','30','--unans','0','-d','10.0.0.3')
    print('h4 <-> h5')
    call_host('h4', '--ping', 'icmp','--ans','10','--unans','0','-d','10.0.0.5')
    call_host('h4', '--ping', 'tcp', '-p', '[80,22,100]','--ans','30','--unans','0','-d','10.0.0.5')
    
def test2():
    print('=== test #2 -- h1 knocking ===')
    call_host('h1', '--auth', 'full', '-k', '4','--ans','0','--unans','4')
    call_host('h1', '--ping', 'icmp','--ans','10','--unans','0')
    
def test3():
    print('=== test #3 -- h3 no-auth-yes ===')
    print('h3 no access:')
    call_host('h3', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h3', '--ping', 'tcp', '-p', '[80,22]','--ans','0','--unans','20')
    print('h3 auth:')
    call_host('h3', '--auth', 'full', '-k', '1','--ans','0','--unans','4')
    print('h3 full access:')
    call_host('h3', '--ping', 'icmp','--ans','10','--unans','0')
    call_host('h3', '--ping', 'tcp', '-p', '[80,22]','--ans','20','--unans','0')
    
def test4():
    print('=== test #4 -- h1 delete ===')
    call_host('h1', '--ping', 'icmp','--ans','10','--unans','0')
    print('deleting 10.0.0.1 (h1) from authorised')
    rest_call('delete','10.0.0.1')
    print('h1 no access to server')
    call_host('h1', '--ping', 'icmp','--ans','0','--unans','10')
    print('h3 still access server')
    call_host('h3', '--ping', 'icmp','--ans','10','--unans','0')
    
def main(argv):
    print('=== ## beginning tests ## ===')
    test0()
    test1()
    test2()
    test3()
    test4()



if __name__ == "__main__":
  main(sys.argv[1:])