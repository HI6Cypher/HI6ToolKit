import struct

class Ethernet_header :
    def __init__(self, raw_data : memoryview | bytes) -> None :
        self.payload = raw_data
        self.struct_pattern = "!6s6sH"
        self.header_length = 14

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "Ethernet Frame\n\t"
        msg += f"Destination MAC Address : {self.dst_mac_addr}\n\t"
        msg += f"Source MAC Address : {self.src_mac_addr}\n\t"
        msg += f"EtherType : {self.eth_type}"
        return msg

    @staticmethod
    def get_ethernet_types() -> dict :
        types = {
            0x0800 : "IPv4",
            0x86dd : "IPv6",
            0x0806 : "Arp"
            }
        return types

    @staticmethod
    async def match_ethernet_type(value : int) -> str :
        return self.get_ethernet_types().get(value, "unknown")

    @staticmethod
    async def standardize_mac_addr(mac_addr : memoryview | bytes) -> str :
        return ":".join([f"{sec:02x}" for sec in mac_addr])

    async def parse_ethernet_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            raise RuntimeError(msg)
        else :
            self.dst_mac_addr = self.standardize_mac_addr(payload[0])
            self.src_mac_addr = self.standardize_mac_addr(payload[1])
            self.eth_type = await self.match_ethernet_type(payload[2])
        return

    async def format_parsed_ethernet_header_verboss(self) -> str :
        await self.parse_ethernet_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        self.formatted_header_verboss += f"Ethernet Frame :{t}"
        self.formatted_header_verboss += f"Source MAC : {self.src_mac_addr}{t}"
        self.formatted_header_verboss += f"Destination MAC : {self.dst_mac_addr}{t}"
        self.formatted_header_verboss += f"EtherType : {self.eth_type}"
        return self.formatted_header_verboss

    async def format_parsed_ethernet_header(self) -> str :
        await self.parse_ethernet_header()
        self.formatted_header = str()
        self.formatted_header += f"Ethernet : "
        self.formatted_header += f"Dst:{self.dst_mac_addr}|"
        self.formatted_header += f"Src:{self.src_mac_addr}|"
        self.formatted_header += f"Type:{self.eth_type}"
        return self.formatted_header
