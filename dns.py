import struct
from udp import UDP_header
from tcp import TCP_header

class DNS_header(UDP_header, TCP_header) :
    ...
