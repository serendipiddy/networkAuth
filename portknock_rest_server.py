from ryu.app.wsgi import ControllerBase, route 
from webob import Response
import json, random, binascii

''' 
    Companion server to port knocking, 
    Used for: 
      * Looking at authorised hosts 
      * Editing active keys
'''

# GET  /portknock/authenticated_hosts
# POST /portknock/add_key
# DELETE /portknock/host/<host_ip>

restpath = '/portknock'
class Portknock_Server(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(Portknock_Server, self).__init__(req, link, data, **config)
        self.port_knocking = data['port_knocking']
        self.key_length = self.port_knocking.key_length
        self.seq_size = self.port_knocking.seq_size
        
        print('key_length %d' % self.key_length)
    
    def create_key(self):
        print('create key')
        key = generate_key(self.key_length, self.seq_size)
        
        self.add_key(key)
        body = json.dumps({'key':key})
        return Response(content_type='application/json', body=body)
        
    def add_key(self, key):
        self.port_knocking
    
    # @route("portknock", self.path+"/", methods=["GET"])
    @route("portknock", restpath, methods=["GET"])
    def get_switch_list(self, req, **kwargs):
        body = json.dumps(self.create_key(self))
        return Response(content_type="application/json", body=body)

    def generate_key(num_digits, seq_size):
        ''' generates a key for authorising 
              seq_size <= 8
              num_digits  < 2**seq_size '''
        key_len = 16 - seq_size
        if num_digits > 2**seq_size: 
            print('(KEYGEN-error) length (%d) too long for max seq (%d)' % (num_digits, 2**seq_size)) 
            return
        
        port_seq = list()
        print(key_len)
        for i in range(num_digits):
            port = []
            if (key_len > 8):
              a = bytearray(random.getrandbits(key_len-8) for x in range(1))
              port.append(binascii.b2a_hex(a))
            else:
              a = 0
            b = bytearray(random.getrandbits(8) for x in range(1))
            port.append(binascii.b2a_hex(b))
              
            key = int(''.join(port),16)
            
            pnum = (i << key_len) + key
            # print('seq: %3d, key: %5d, port: %d' % (i, key,pnum))
            # print('seq  {0:0>16b}'.format(i << key_len))
            # print('key  {0:0>16b}'.format(key))
            # print('port {0:0>16b}'.format(pnum))
            
            port_seq.append(pnum)
        
        return port_seq