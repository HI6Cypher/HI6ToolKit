import struct
from ipv4 import IPv4_header
from ipv6 import IPv6_header

class UDP_header(IPv4_header, IPv6_header) :
    def __init__(self, raw_header : memoryview | bytes, network_raw_header) -> None :
        super().__init__(network_raw_header)
        self.payload = raw_header
        self.struct_pattern = "!HHHH"
        self.header_length = 8

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "UDP Segment\n\t"
        msg += f"Source Port : {self.source_port}\n\t"
        msg += f"Destination Port : {self.destination_port}"
        return msg

    async def parse_UDP_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            raise RuntimeError(msg)
        else :
            self.source_port = payload[0]
            self.destination_port = payload[1]
            self.length = payload[2]
            self.checksum = payload[3]
        return

    async def format_parsed_UDP_header_verboss(self) -> str :
        await self.parse_UDP_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        self.formatted_header_verboss += f"UDP Segment :{t}Source Port : {self.source_port}  Destination Port : {self.destination_port}"
        self.formatted_header_verboss += f"{t}Length : {self.length}{t}Checksum : {hex(self.checksum)}"
        return self.formatted_header_verboss

    async def format_parsed_UDP_header(self) -> str :
        await self.parse_UDP_header()
        self.formatted_header = str()
        self.formatted_header += f"UDP : Src:{self.source_port}|Dst:{self.destination_port}"
        return self.formatted_header
