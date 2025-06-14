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
        self.header_length = 12
        self.failure = False

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "DNS Packet\n\t"
        msg += f"Transaction ID : {self.tid}\n\t"
        msg += f"QR : {self.qr}\n\t"
        msg += f"Name : {self.name}"
        return msg

    def _parse_DNS_question_section(self) -> None :
        ...

    async def parse_DNS_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the packet below failed" + "\n" + repr(self.__repr)
            Constant.LOG(msg)
            self.failure = True
        else :
            self.tid = payload[0]
            self.flags = payload[1]
            self.qr = (self.flags & 0b1000000000000000) >> 15
            self.op = (self.flags & 0b0111100000000000) >> 11
            self.aa = (self.flags & 0b0000010000000000) >> 10
            self.tc = (self.flags & 0b0000001000000000) >> 9
            self.rd = (self.flags & 0b0000000100000000) >> 8
            self.ra = (self.flags & 0b0000000010000000) >> 7
            self.zz = (self.flags & 0b0000000001000000) >> 6
            self.ad = (self.flags & 0b0000000000100000) >> 5
            self.cd = (self.flags & 0b0000000000010000) >> 4
            self.rc = (self.flags & 0b0000000000001111) >> 0
            self.number_of_questions = payload[2]
            self.number_of_answers = payload[3]
            self.number_of_authority_RRs = payload[4]
            self.number_of_additional_RRs = payload[5]
