import struct
from ipv4 import IPv4_header
from ipv6 import IPv6_header

class TCP_header(IPv4_header, IPv6_header) :
    def __init__(
            self,
            header : memoryview | bytes,
            network_header : memoryview | bytes,
            ethernet_header : memoryview | bytes
            ) -> None :
        super().__init__(network_header)
        self.payload = header
        self.struct_pattern = "!HHLLBBHHH"
        self.header_length = (header[13] >> 4) * 4
        self.failure = False

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "TCP Segment\n\t"
        msg += f"Source Port : {self.source_port}\n\t"
        msg += f"Destination Port : {self.destination_port}\n\t"
        msg += f"Sequence Number : {self.sequence_number}\n\t"
        msg += f"Acknowledgement Number : {self.acknowledgement_number}"
        return msg

    async def parse_TCP_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the Segment below failed" + "\n" + repr(self.__repr__)
            Constant.LOG(msg)
            self.failure = True
        else :
            self.source_port = payload[0]
            self.destination_port = payload[1]
            self.sequence_number = payload[2]
            self.acknowledgement_number = payload[3]
            self.data_offset = (payload[4] >> 4) * 4
            self.flags = payload[5]
            self.cwr = (self.flags & 0b10000000) >> 7
            self.ece = (self.flags & 0b01000000) >> 6
            self.urg = (self.flags & 0b00100000) >> 5
            self.ack = (self.flags & 0b00010000) >> 4
            self.psh = (self.flags & 0b00001000) >> 3
            self.rst = (self.flags & 0b00000100) >> 2
            self.syn = (self.flags & 0b00000010) >> 1
            self.fin = (self.flags & 0b00000001)
            self.window = payload[6]
            self.checksum = payload[7]
            self.urgent_pointer = payload[8]
        return

    async def format_parsed_TCP_header_verboss(self) -> str :
        await self.parse_TCP_header()
        formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            formatted_header_verboss += f"TCP Segment :{t}Source Port : {self.source_port}  Destination Port : {self.destination_port}"
            formatted_header_verboss += f"{t}Sequence Number : {self.sequence_number}  Acknowledgment Number : {self.acknowledgement_number}"
            formatted_header_verboss += f"{t}Data Offset : {self.data_offset}  Flags :{t}\t"
            formatted_header_verboss += f"CWR:{self.cwr}  ECE:{self.ece}  URG:{self.urg}  ACK:{self.ack}{t}\tPSH:{self.psh}  RST:{self.rst}  SYN:{self.syn}  FIN:{self.fin}"
            formatted_header_verboss += f"{t}Window : {self.window}  Checksum : {hex(self.checksum)}  Urgent Pointer : {self.urgent_pointer}"
        return formatted_header_verboss

    async def format_parsed_TCP_header(self) -> str :
        await self.parse_TCP_header()
        formatted_header = str()
        if not self.failure :
            formatted_header += f"TCP : Src:{self.source_port}|Dst:{self.destination_port}|"
            formatted_header += f"Seq:{self.sequence_number}|Acn:{self.acknowledgement_number}\n\t"
            formatted_header += f"Flags : CWR:{self.cwr} ECE:{self.ece} URG:{self.urg} ACK:{self.ack} "
            formatted_header += f"PSH:{self.psg} RST:{self.rst} SYN:{self.syn} FIN:{self.fin}"
        return formatted_header
