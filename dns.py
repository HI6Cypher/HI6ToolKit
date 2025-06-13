import struct
from udp import UDP_header
from tcp import TCP_header

class DNS_header(UDP_header, TCP_header) :
    def __init__(
            self,
            header : memoryview | bytes,
            transport_header : memoryview | bytes,
            network_header : memoryview | bytes,
            ethernet_header : memoryview | bytes
            ) -> None :
        super().__init__(transport_header, network_header, ethernet_header)
        self.payload = header
        self.struct_pattern = "!HHHHHH"

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    
