from ryu.app.wsgi import ControllerBase, WSGIApplication
from webob import Response
import json

''' 
    Companion server to port knocking, 
    Used for: 
      * Looking at authorised hosts 
      * Editing active keys
'''

# GET  /portknock/authenticated_hosts
# POST /portknock/add_key
# DELETE /portknock/host/<host_ip>

class Portknock_Server(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(Portknock_Server, self).__init__(req, link, data, **config)
        self.keylength = data['key_length']
        self.path = '/portknock'
    
    def create_key(self):
        key = 'A04E35'
        self.add_key(key)
        body = json.dumps({'key':key})
        return Response(content_type='application/json', body=body)
        
    def add_key(self, key):
        
    
     def __init__(self, *args, **kwargs):
        super(RestPkApi, self).__init__(*args, **kwargs)
        
        
    @route("portknock", url+"/switches", methods=["GET"])
    def get_switch_list(self, req, **kwargs):
        body = json.dumps(self.acl_switch_inst.get_switches())
        return Response(content_type="application/json", body=body)

        
    def generate_key(length):
        new_mac = list()
        
        while (not new_mac) or (new_mac in existing_macs):
            new_mac = list()
            for i in range(6):
                a = bytearray(random.getrandbits(8) for i in range(1))
                new_mac.append(binascii.b2a_hex(a))
            
            new_mac = ':'.join(new_mac)
        
        return new_mac