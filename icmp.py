import struct
from ipv4 import IPv4_header
from ipv6 import IPv6_header

class ICMP_header(IPv4_header, IPv6_header) :
    def __init__(
            self,
            header : memoryview | bytes,
            network_header : memoryview | bytes,
            ethernet_header : memoryview | bytes
            ) -> None :
        super().__init__(network_header, ethernet_header)
        self.payload = header
        self.struct_pattern = "!BBH"
        self.header_length = 8
        self.failure = False

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "ICMP Datagram\n\t"
        msg += f"Type : {self.type}\n\t"
        msg += f"Code : {self.code}"
        return msg

    async def parse_ICMP_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            Constant.LOG(msg)
            self.failure = True
        else :
            self.type = payload[0]
            self.code = payload[1]
            self.checksum = payload[2]
        return

    async def format_parsed_ICMP_header_verboss(self) -> str :
        await self.parse_ICMP_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += f"ICMP Datagram :{t}Type : {self.type}  Code : {self.code}"
            self.formatted_header_verboss += f"{t}Checksum : {hex(self.checksum)}"
        return self.formatted_header_verboss

    async def format_parsed_ICMP_header(self) -> str :
        await self.parse_ICMP_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"ICMP : Type:{self.type}|Code:{self.code}"
        return self.formatted_header
