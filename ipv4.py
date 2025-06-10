import struct
from eth import Ethernet_header


class IPv4_header(Ethernet_header) :
    def __init__(self, raw_header : memoryview | bytes, datalink_raw_header : memoryview | bytes) -> None :
        super().__init__(datalink_raw_header)
        self.payload = raw_header
        self.struct_pattern = "!BBHHHBBH4s4s"
        self.header_length = (raw_header[0] & 0x00001111) << 2

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "IPv4 Datagram\n\t"
        msg += f"Identification : {self.identification}\n\t"
        msg += f"Source IPv4 Address : {self.src_ip_addr}\n\t"
        msg += f"Destination IPv4 Address : {self.dst_ip_addr}\n\t"
        msg += f"Internet Header Length : {self.ihl}\n\t"
        msg += f"Time to Live : {self.ttl}\n\t"
        msg += f"Protocol : {self.protocol}"
        return msg

    @staticmethod
    def get_IPv4_protocols() -> dict :
        protos = {
            0x01 : "ICMP",
            0x02 : "IGMP",
            0x06 : "TCP",
            0x11 : "UDP",
            0x38 : "TLS",
            0x59 : "OSPF",
            0x84 : "SCTP",
            0x88 : "UDPLite"
            }

    @staticmethod
    async def match_IPv4_protocol(value : int) -> str :
        return self.get_IPv4_protocols().get(value, "unknown")

    async def parse_IPv4_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            raise RuntimeError(msg)
        else :
            self.version = payload[0] >> 4
            self.ihl = (payload[0] & 0xf) * 4
            self.dscp = payload[1] >> 2
            self.ecn = payload[1] & 0x00000011
            self.total_length = payload[2]
            self.identification = payload[3]
            self.flags = bin(payload[4] >> 13)
            self.fragment_offset = payload[4] & 0x1fff
            self.ttl = payload[5]
            self.protocol = await self.match_IPv4_protocol(payload[6])
            self.checksum = payload[7]
            self.src_ip_addr = socket.inet_ntop(socket.AF_INET, payload[8])
            self.dst_ip_addr = socket.inet_ntop(socket.AF_INET, payload[9])
        return

    async def format_parsed_IPv4_header_verboss(self) -> str :
        await self.parse_IPv4_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        self.formatted_header_verboss += f"IPv4 Datagram :{t}Version : {self.version}  Header Length : {self.ihl}"
        self.formatted_header_verboss += f"{t}DSCP : {self.dscp}  ECN : {self.ecn}  Total Length : {self.total_length}"
        self.formatted_header_verboss += f"{t}Identification : {self.identification}  Flags : {self.flags}"
        self.formatted_header_verboss += f"{t}Fragment Offset : {self.fragment_offset}  TTL : {self.ttl}"
        self.formatted_header_verboss += f"{t}Protocol : {self.protocol}  Chechsum : {hex(self.checksum)}"
        self.formatted_header_verboss += f"{t}Source : {self.src_ip_addr}  Destination : {self.dst_ip_addr}"
        return header

    async def format_parsed_IPv4_header(self) -> str :
        await self.parse_IPv4_header()
        self.formatted_header = str()
        self.formatted_header += f"IPv4 : Ver:{self.version}|Ident:{self.identification}|Proto:{self.protocol}|"
        self.formatted_header += f"Src:{self.src_ip_addr}|Dst:{self.dst_ip_addr}|TTL:{self.ttl}"
        return self.formatted_header
