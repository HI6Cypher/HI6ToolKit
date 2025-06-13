import struct
from eth import Ethernet_header

class IPv6_header(Ethernet_header) :
    def __init__(
            self,
            header : memoryview | bytes,
            datalink_header : memoryview | bytes
            ) -> None :
        super().__init__(datalink_header)
        self.payload = header
        self.struct_pattern = "!lHBB16s16s"
        self.header_length = 40
        self.failure = False

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "IPv6 Datagram\n\t"
        msg += f"Source IPv6 Address : {self.src_ip_addr}\n\t"
        msg += f"Destination IPv6 Address : {self.dst_ip_addr}\n\t"
        msg += f"Next Header : {self.next_header}\n\t"
        msg += f"Hop Limit : {self.hop_limit}"
        return msg

    @staticmethod
    def get_IPv6_protocols() -> dict :
        protos = {
            0x00 : "HOPOPT",
            0x3a : "ICMP",
            0x06 : "TCP",
            0x11 : "UDP",
            0x38 : "TLS",
            0x59 : "OSPF",
            0x84 : "SCTP",
            0x88 : "UDPLite"
            }
        return protos

    @staticmethod
    async def match_IPv6_protocol(value : int) -> str :
        return self.get_IPv6_protocols().get(value, "unknown")

    async def parse_IPv6_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            Constant.LOG(msg)
            self.failure = True
        else :
            self.version = payload[0] >> 28
            self.traffic_class = (payload[0] >> 20) & 0xff
            self.flow_label = payload[0] & 0xfffff
            self.payload_length = payload[1]
            self.next_header = await self.match_IPv6_protocol(payload[2])
            self.hop_limit = payload[3]
            self.src_ip_addr = socket.inet_ntop(socket.AF_INET6, payload[4])
            self.dst_ip_addr = socket.inet_ntop(socket.AF_INET6, payload[5])
        return

    async def format_parsed_IPv6_header_verboss(self) -> str :
        await self.parse_IPv6_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += f"IPv6 Datagram :{t}Version : {self.version}  Traffic Class : {self.traffic_class}"
            self.formatted_header_verboss += f"{t}Flow Lable : {self.flow_label}  Payload Length : {self.payload_length}"
            self.formatted_header_verboss += f"{t}Next Header : {self.next_header}  Hop Limit : {self.hop_limit}"
            self.formatted_header_verboss += f"{t}Source : {self.src_ip_addr}"
            self.formatted_header_verboss += f"{t}Destination : {self.dst_ip_addr}"
        return self.formatted_header_verboss

    async def format_parsed_IPv6_header(self) -> str :
        await self.parse_IPv6_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"IPv6 : Ver:{self.version}|Src:{self.src_ip_addr}|Dst:{self.dst_ip_addr}\n\t"
            self.formatted_header += f"Flow:{self.flow_label}|Next:{self.next_header}|Hop:{self.hop_limit}"
        return self.formtted_header
