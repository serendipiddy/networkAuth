# networkAuth
Uses port knocking in an OpenFlow network to authenticate access to a server host. 

Knocking is performed with a one-time-knock.
New knock sequences can be generated.

Knocks occur using TCP requests to ports on the server, these are intercepted by the controller and matched against known keys.
Port numbers include sequence information for matching out-of-order packets.

Includes a restful interface for viewing the auth-state, creating new knocks and removing access for authenticated hosts.
