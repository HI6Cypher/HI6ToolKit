import struct

class Arp_header :
    def __init__(self, raw_data : memoryview | bytes) -> None :
        self.payload = raw_data
        self.struct_pattern = "!HHBBH6s4s6s4s"
        self.header_length = 28

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = str()
        msg += "Arp Datagram\n\t"
        msg += f"Operation : {self.operation}\n\t"
        msg += f"Sender Hardware Address : {self.sender_hardware_addr}\n\t"
        msg += f"Sender Protocol Address : {self.sender_protocol_addr}\n\t"
        msg += f"Target Hardware Address : {self.target_hardware_addr}\n\t"
        msg += f"Target Protocol Address : {self.target_protocol_addr}\n\t"
        return msg

    @staticmethod
    def get_hardware_types() -> dict :
        types = {
            0x0800 : "IPv4",
            0x86dd : "IPv6"
            }
        return types

    @staticmethod
    def get_Arp_operations() -> dict :
        opcodes = {
            0x0001 : "ARP REQ",
            0x0002 : "ARP REP"
            }
        return opcodes

    @staticmethod
    async def standardize_mac_addr(mac_addr : memoryview | bytes) -> str :
        return ":".join([f"{sec:02x}" for sec in mac_addr])

    async def match_hardware_type(value : int) -> str :
        return self.get_hardware_types().get(value, "unknown")

    async def match_Arp_operation(value : int) -> str :
        return self.get_Arp_operations().get(value, "unknown")

    async def parse_Arp_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            raise RuntimeError(msg)
        else :
            self.hardware_type = payload[0]
            self.protocol_type = await self.match_hardware_type(payload[1])
            self.hardware_length = payload[2]
            self.protocol_length = payload[3]
            self.operation = await self.match_Arp_operation(payload[4])
            self.sender_hardware_addr = self.standardize_mac_addr(payload[5])
            self.sender_protocol_addr = socket.inet_ntop(socket.AF_INET, payload[6])
            self.target_hardware_addr = self.standardize_mac_addr(payload[7])
            self.target_protocol_addr = socket.inet_ntop(socket.AF_INET, payload[8])
        return

    async def format_parsed_Arp_header_verboss(self) -> str :
        await self.parse_Arp_header()
        formatted_header_verboss = str()
        t = "\n\t\t"
        formatted_header_verboss += f"Arp Datagram :{t}Hardware Type : {self.hardware_type}{t}Protocol Type : {self.protocol_type}"
        formatted_header_verboss += f"{t}Hardware Length : {self.hardware_length}  Protocol Length : {self.protocol_length}  Operation : {self.operation}"
        formatted_header_verboss += f"{t}Sender Hardware Address : {self.sender_hardware_addr}"
        formatted_header_verboss += f"{t}Sender Protocol Address : {self.sender_protocol_addr}"
        formatted_header_verboss += f"{t}Target Hardware Address : {self.target_hardware_addr}"
        formatted_header_verboss += f"{t}Target Protocol Address : {self.target_protocol_addr}"
        return formatted_header_verboss

    async def format_parsed_Arp_header(self) -> str :
        await self.parse_Arp_header()
        formatted_header = str()
        formatted_header += f"Arp : SrcMac:{self.sender_hardware_addr}|SrcIP:{self.sender_protocol_addr}|"
        formatted_header += f"DstMac:{self.target_hardware_addr}|DstIP:{self.target_protocol_addr}"
        return formatted_header
