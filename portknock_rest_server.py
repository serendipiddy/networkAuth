from ryu.app.wsgi import ControllerBase, route 
from webob import Response
import json, random, binascii

''' 
    Companion server to port knocking, 
    Used for: 
      * Looking at authorised hosts 
      * Editing active keys
'''

# GET    /portknock/authenticated_hosts
# POST   /portknock/add_key
# DELETE /portknock/host/<host_ip>

restpath = '/portknock'


class Portknock_Server(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(Portknock_Server, self).__init__(req, link, data, **config)
        self.port_knocking = data['port_knocking']
        self.key_length = self.port_knocking.key_length
        self.seq_size = self.port_knocking.seq_size
    
    def get_portknocking_info(self):
        """ information on the current state of the port knocking server """
        rv = {}
        
        server = {}
        server['ipv4'] = str(self.port_knocking.server_ipv4_address)
        server['ipv6'] = str(self.port_knocking.server_ipv6_address)
        rv['server'] = server
        
        hosts = {}
        hosts['authenticated_hosts'] = self.port_knocking.authenticated_hosts
        hosts['authenticating_hosts'] = self.port_knocking.authing_hosts
        hosts['blocked_hosts'] = self.port_knocking.blocked_hosts
        rv['hosts'] = hosts
        
        keys = {}
        keys['auth_port'] = self.port_knocking.auth_port
        keys['active_keys'] = self.port_knocking.active_keys
        keys['key_length'] = self.port_knocking.key_length
        keys['seq_size'] = self.port_knocking.seq_size
        rv['keys'] = keys
        
        return rv
    
    def create_key(self):
        data = generate_key(self.key_length, self.seq_size)
        
        while not self.port_knocking.add_auth_key(data['keys']):
            data = generate_key(self.key_length, self.seq_size)
        
        return data
      
    def get_page(self, page):
        try:
            fd = open(page,'r')
        except IOError:
            return '<head><title>Error</title></head><body><p>cannot open %s</p></body></html>' % page
          
        page_file = fd.read()
        fd.close()
        return page_file
        
    def remove_authed_host(self, host):
        """ Removes IP address from authenticated hosts """
        if self.port_knocking.remove_host_access(host):
            return '204 OK'
        return '404 Not Found'
        
    @route("portknock", restpath, methods=["GET"])
    def get_index(self, req, **kwargs):
        body = self.get_page('html/index.html')
        return Response(content_type="text/html", body=body)
      
    @route("portknock", restpath+'/info', methods=["GET"])
    def get_portknock_info(self, req, **kwargs):
        body = json.dumps(self.get_portknocking_info())
        return Response(content_type="application/json", body=body)
    
    @route("portknock", restpath+'/create_key', methods=["POST"])
    def create_portknock_key(self, req, **kwargs):
        keys = self.create_key()
        
        body = json.dumps(keys['ports'])
        return Response(content_type="application/json", body=body)
    
    @route("portknock", restpath+'/host/{host:.*?}', methods=["DELETE"])
    def delete_host(self, req, **kwargs):
        if 'host' not in kwargs:
          return Response(body='Error, missing host IP')
        
        res = Response()
        res.status = self.remove_authed_host(kwargs['host'])
        
        return res


def generate_key(num_digits, seq_size):
    """ generates a key for authorising 
          seq_size <= 8
          num_digits  < 2**seq_size """
    key_len = 16 - seq_size
    if num_digits > 2**seq_size: 
        print('(KEYGEN-error) length (%d) too long for max seq (%d)' % (num_digits, 2**seq_size)) 
        return
    
    key_seq = list()
    port_seq = list()
    
    for i in range(num_digits):
        port = []
        if key_len > 8:
            a = bytearray(random.getrandbits(key_len-8) for x in range(1))
            port.append(binascii.b2a_hex(a))
        else:
            a = 0
        b = bytearray(random.getrandbits(8) for x in range(1))
        port.append(binascii.b2a_hex(b))
          
        key = int(''.join(port), 16)
        
        pnum = (i << key_len) + key
        # print('seq: %3d, key: %5d, port: %d' % (i, key,pnum))
        # print('seq  {0:0>16b}'.format(i << key_len))
        # print('key  {0:0>16b}'.format(key))
        # print('port {0:0>16b}'.format(pnum))
        key_seq.append({'seq': i, 'value': key, 'port': pnum})
        port_seq.append(pnum)
    
    return {'ports': port_seq, 'keys': key_seq}
    