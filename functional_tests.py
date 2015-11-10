import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # suppress IPv6 error
from subprocess import call, Popen, PIPE
from scapy.all import *
from time import sleep
import urllib2, json

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
    
def test5():
    print('=== test #5 -- h4 auth, packet loss ===')
    print('h4 no access to server')
    call_host('h4', '--ping', 'icmp','--ans','0','--unans','10')
    
    print('h4 attempted auth #1 (init lost)')
    call_host('h4', '--auth', 'no_init', '-k', '2','--ans','0','--unans','4')
    print('h4 no access')
    call_host('h4', '--ping', 'icmp','--ans','0','--unans','10')
    
    print('h4 attempted auth #2 (no key id)')
    call_host('h4', '--auth', 'noid', '-k', '2','--ans','0','--unans','3')
    print('h4 no access')
    call_host('h4', '--ping', 'icmp','--ans','0','--unans','10')
    
    try:
        response = urllib2.urlopen(rest_server+inform_pattern).read()
        print('h4 is partially authd: %s' % json.loads(response)['hosts']['authenticating_hosts'])
    except urllib2.HTTPError:
        print('error')
    
    print('h4 attempted auth #3 (all but last)')
    call_host('h4', '--auth', 'last', '-k', '2','--ans','0','--unans','3')
    print('h4 no access')
    call_host('h4', '--ping', 'icmp','--ans','0','--unans','10')

    print('h4 attempted auth #4')
    call_host('h4', '--auth', 'full', '-k', '2','--ans','0','--unans','4')
    print('h4 no access')
    call_host('h4', '--ping', 'icmp','--ans','10','--unans','0')
    
def test6():
    print('=== test #6 -- h5 auth, packets out of order ===')
    print('h5 no access to server')
    call_host('h5', '--ping', 'icmp','--ans','0','--unans','10')
    print('h5 auth')
    call_host('h5', '--auth', 'rev', '-k', '3','--ans','0','--unans','4')
    print('h5 access')
    call_host('h5', '--ping', 'icmp','--ans','10','--unans','0')
    
def test7():
    print('=== test #7 -- h6 auth, key incorrect (no auth) ===')
    print('h6 no access:')
    call_host('h6', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h6', '--ping', 'tcp', '-p', '[80,22]','--ans','0','--unans','20')
    print('h6 auth:')
    call_host('h6', '--auth', 'full', '-k', '-1','--ans','0','--unans','4')
    print('h6 still no access:')
    call_host('h6', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h6', '--ping', 'tcp', '-p', '[80,22]','--ans','0','--unans','20')
    
def test8():
    print('=== test #8 -- only authorised can access ===')
    print('h1 icmp, tcp, arp')
    call_host('h1', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h1', '--ping', 'tcp', '-p', '[80,22,100]','--ans','0','--unans','30')
    call_host('h1', '--ping', 'arp','--ans','10','--unans','0')
    print('h3 icmp, tcp, arp')
    call_host('h3', '--ping', 'icmp','--ans','10','--unans','0')
    call_host('h3', '--ping', 'tcp', '-p', '[80,22,100]','--ans','30','--unans','0')
    call_host('h3', '--ping', 'arp','--ans','10','--unans','0')
    print('h4 icmp, tcp, arp')
    call_host('h4', '--ping', 'icmp','--ans','10','--unans','0')
    call_host('h4', '--ping', 'tcp', '-p', '[80,22,100]','--ans','30','--unans','0')
    call_host('h4', '--ping', 'arp','--ans','10','--unans','0')
    print('h5 icmp, tcp, arp')
    call_host('h5', '--ping', 'icmp','--ans','10','--unans','0')
    call_host('h5', '--ping', 'tcp', '-p', '[80,22,100]','--ans','30','--unans','0')
    call_host('h5', '--ping', 'arp','--ans','10','--unans','0')
    print('h6 icmp, tcp, arp')
    call_host('h6', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h6', '--ping', 'tcp', '-p', '[80,22,100]','--ans','0','--unans','30')
    call_host('h6', '--ping', 'arp','--ans','10','--unans','0')
    
def test9():
    print('=== test #9 -- h1 auth len key 256 ===')
    print('h1 no access:')
    call_host('h1', '--ping', 'icmp','--ans','0','--unans','10')
    call_host('h1', '--ping', 'tcp', '-p', '[80,22]','--ans','0','--unans','20')
    print('h1 auth:')
    call_host('h3', '--auth', 'full', '-k', '10','--ans','0','--unans','256')
    print('h1 full access:')
    call_host('h1', '--ping', 'icmp','--ans','10','--unans','0')
    call_host('h1', '--ping', 'tcp', '-p', '[80,22]','--ans','20','--unans','0')
    
    
def main(argv):
    print('=== ## beginning tests ## ===')
    test0()
    test1()
    test2()
    test3()
    test4()
    test5()
    test6()
    test7()
    test8()
    # test9()



if __name__ == "__main__":
  main(sys.argv[1:])