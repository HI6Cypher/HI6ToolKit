import socket
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

    @staticmethod
    def get_DNS_types() -> dict :
        types = {
            0x01 : "A",
            0x02 : "NS",
            0x05 : "CNAME",
            0x0c : "PTR",
            0x0f : "MX",
            0x1c : "AAAA"
            }
        return types

    @staticmethod
    def get_DNS_classes() -> dict :
        classes = {
            0x01: "IN",
            0x02: "CS",
            0x03: "CH",
            0x04: "HS"
            }
        return classes

    async def match_DNS_type(self, value : int) -> str :
        return self.get_DNS_types().get(value, "unknown")

    async def match_DNS_class(self, value : int) -> str :
        return self.get_DNS_classes().get(value, "unknown")

    async def _get_proper_rdata(self, rdata : memoryview | bytes, type_ : str) -> str | tuple[int, str] :
        match type_ :
            case "A" :
                value = socket.inet_ntop(socket.AF_INET, rdata)
            case "NS" | "CNAME" | "PTR" :
                value, _ = await self._parse_DNS_name(rdata)
            case "MX" :
                value = ((rdata[0] << 8) + rdata[1]), await self._parse_DNS_name(rdata[2:])
            case "AAAA" :
                value = socket.inet_ntop(socket.AF_INET6, rdata)
            case _ :
                value = "unknown"
        return value

    async def _parse_DNS_name(self, payload : memoryview | bytes) -> tuple[str, int] :
        name = list()
        index = 0
        while length := payload[index] :
            index += 1
            name.append(bytes(payload[index:index + length]).decode())
            index += length
        else :
            index += 1
            return (".".join(name), index)

    async def _parse_DNS_question_section(self, payload : memoryview | bytes) -> tuple[str, str, str, int] :
        name, index = await self._parse_DNS_name(payload)
        payload = struct.unpack("!HH", payload[index:index + 4])
        type_ = await self.match_DNS_type(payload[0])
        class_ = await self.match_DNS_class(payload[1])
        length = index + 4
        return (name, type_, class_, length)

    async def _parse_DNS_question_sections(self, payload : memoryview | bytes) -> int :
        self.questions = list()
        index = 0
        for _ in range(self.number_of_questions) :
            question_section = await self._parse_DNS_question_section(payload[index:])
            self.questions.append(question_section)
            index += question_section[-1]
        else :
            return index

    async def _parse_DNS_answer_section(self, payload : memoryview | bytes) -> tuple[str, str, str, int, int, str, int] :
        name, index = await self._parse_DNS_name(payload)
        payload = struct.unpack("!HHIH", payload[index:index + 10])
        type_ = await self.match_DNS_type(payload[0])
        class_ = await self.match_DNS_class(payload[1])
        ttl = payload[2]
        rdlength = payload[3]
        rdata = await self._get_proper_rdata(payload[index + 10:index + 10 + rdlength], type_)
        return (name, type_, class_, ttl, rdlength, rdata, index + 10 + rdlength)

    async def _parse_DNS_answer_sections(self, payload : memoryview | bytes) -> int :
        self.answers = list()
        index = 0
        for _ in range(self.number_of_answers) :
            answer_section = await self._parse_DNS_answer_section(payload[index:])
            self.answers.append(answer_section)
            index += answer_section[-1]
        else :
            return index

    async def _parse_DNS_authority_sections(self, payload : memoryview | bytes) -> tuple[str, str, str, int, int, str, int] :
        self.authorities = list()
        index = 0
        for _ in range(self.number_of_authorities) :
            authority_section = await self._parse_DNS_answer_section(payload[index:])
            self.authorities.append(authority_section)
            index += authority_section[-1]
        else :
            return index

    async def _parse_DNS_additional_sections(self, payload : memoryview | bytes) -> tuple[str, str, str, int, int, str, int] :
        self.additionals = list()
        index = 0
        for _ in range(self.number_of_additionals) :
            additional_section = await self._parse_DNS_answer_section(payload[index:])
            self.additionals.append(additional_section)
            index += additional_section[-1]
        else :
            return index

    async def _parse_DNS_sections(self) -> None :
        index = self.header_length
        question_sections_length = await self._parse_DNS_question_sections()
        index += question_sections_length
        if self.number_of_answers > 0 :
            self.answers = list()
            length = await self._parse_DNS_answer_sections(self.payload[index:])
            index += length

        if self.number_of_authorities > 0 :
            self.authorities = list()
            length = await self._parse_DNS_authority_sections(self.payload[index:])
            index += length

        if self.number_of_additionals > 0 :
            self.additionals = list()
            length = await self._parse_DNS_additional_sections(self.payload[index:])
            index += length

        return

    async def parse_DNS_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern, self.payload[:self.header_length])
        except struct.error :
            msg = "unpacking the packet below failed" + "\n" + self.__repr__()
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
            self.number_of_authorities = payload[4]
            self.number_of_additionals = payload[5]
            await self._parse_DNS_sections()
            return
