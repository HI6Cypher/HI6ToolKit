import struct
import socket
from ipv4 import IPv4_header
from ipv6 import IPv6_header

class IGMP_header(IPv4_header, IPv6_header) :
    def __init__(
            self,
            header : memoryview | bytes,
            network_header : memoryview | bytes,
            ethernet_header : memoryview | bytes
            ) -> None :
        super().__init__(network_header, ethernet_header)
        self.payload = header
        self.igmp_type = header[0]
        self.failure = False

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        msg = "IGMP Datagram\n\t"
        msg += f"Type : {self.type}\n\t"
        msg += f"Max Response Time : {self.max_response_time}\n\t"
        msg += f"Group Addess : {self.group_addr}"
        return msg

    @staticmethod
    def float_decode(value : int) -> int :
        if (value < 128) :
                decoded = value
        if (code >= 128) :
            exp = (value >> 4) & 0b111
            mant = value & 0b1111
            decoded = (mant | 0x10) << (exp + 3)
        return decoded

    @staticmethod
    def struct_pattern(igmp_type : int) -> str | tuple[str, str] :
        match igmp_type :
            case 0x12 | 0x16 | 0x17 :
                return "!BBH4s"
            case 0x11 :
                return "!BBH4sBBH"
            case 0x22 :
                return ("!BxHxxH", "!BBH4s")

    @staticmethod
    def get_record_types() -> dict :
        types = {
            1 : "MODE_IS_INCLUDE",
            2 : "MODE_IS_EXCLUDE",
            3 : "CHANGE_TO_INCLUDE_MODE",
            4 : "CHANGE_TO_EXCLUDE_MODE",
            5 : "ALLOW_NEW_SOURCES",
            6 : "BLOCK_OLD_SOURCES"
            }
        return types

    @staticmethod
    async def match_record_type(value : int) -> str :
        return self.get_record_types().get(value, "unknown")

    async def parse_IGMPv1_memship_report_header(self) -> None :
        try :
            payload = struct.unpack(self.struct_pattern(0x12), self.payload[:8])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            Constant.LOG(msg)
            self.failure = True
        else :
            self.type = payload[0]
            self.max_response_time = payload[1]
            self.checksum = payload[2]
            self.group_addr = socket.inet_ntop(socket.AF_INET, payload[3])
        return

    async def parse_IGMPv2_memship_report_header(self) -> None :
        await self.parse_IGMPv1_memship_report_header()
        return

    async def parse_IGMP_leave_group_header(self) -> None :
        await self.parse_IGMPv1_memship_report_header()
        return

    async def parse_IGMP_memship_query_header(self) -> None :
        try :
            payload_before_src_addrs = struct.unpack(self.struct_pattern(0x11), self.payload[:12])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            Constant.LOG(msg)
            self.failure = True
        else :
            payload = payload_before_src_addrs
            self.type = payload[0]
            self.max_response_time = payload[1]
            self.checksum = payload[2]
            self.group_addr = socket.inet_ntop(socket.AF_INET, payload[3])
            self.s = payload[4] >> 3
            self.qrv = payload[4] & 0b111
            self.qqic = payload[5]
            self.number_of_sources = payload[6]
            payload_after_src_addrs = struct.unpack("!" + self.number_of_sources * "4s", raw_payload[12:12 + self.number_of_sources * 4])
            self.source_addrs = [socket.inet_ntop(socket.AF_INET, src) for src in payload_after_src_addrs]
        return

    async def parse_IGMPv3_memship_report_header(self) -> None :
        try :
            payload_before_group_records = struct.unpack(self.struct_pattern(0x22)[0], self.payload[:8])
        except struct.error :
            msg = "unpacking the Datagram below failed" + "\n" + repr(self.__repr__)
            Constant.LOG(msg)
            self.failure = True
        else :
            payload = payload_before_group_records
            self.type = payload[0]
            self.checksum = payload[1]
            self.number_of_group_records = payload[2]
            self.group_records = list()
            index = 8
            for _ in range(self.number_of_group_records) :
                payload_group_record_before_src_addrs = struct.unpack(self.struct_pattern(0x22)[1], self.payload[index:index + 8])
                index += 8
                payload = payload_group_record_before_src_addrs
                record_type = payload[0]
                aux_data_length = payload[1]
                number_of_sources = payload[2]
                multicast_addr = socket.inet_ntop(socket.AF_INET, payload[3])
                payload_group_record_after_src_addrs = struct.unpack("!" + number_of_sources * "4s", self.payload[index:index + number_of_souces * 4])
                index += number_of_sources * 4
                group_record_source_addrs = [socket.inet_ntop(socket.AF_INET, src) for src in payload_group_record_after_src_addrs]
                auxiliary_data = raw_payload[index:index + aux_data_length * 4]
                index += aux_data_length * 4
                self.group_records.append(
                        (
                            record_type,
                            aux_data_length,
                            number_of_sources,
                            multicase_addr,
                            group_record_src_addrs,
                            auxiliary_data
                            )
                    )
            return

    async def _format_parsed_IGMPv1_memship_report_header_verboss(self) -> None :
        await self.parse_IGMPv1_memship_report_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += "IGMPv1 Memship Report Datagram :"
            self.formatted_header_verboss += f"{t}Type : {hex(self.type)}  Max Response Time : {self.float_decode(self.max_response_time)}"
            self.formatted_header_verboss += f"Checksum : {hex(self.checksum)}  Group Address : {self.group_addr}"
        return

    async def _format_parsed_IGMPv1_memship_report_header(self) -> None :
        await self.parse_IGMPv1_memship_report_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"IGMPv1 Memship Report : Type:{hex(self.type)}|Group:{self.group_addr}"
        return

    async def _format_parsed_IGMPv2_memship_report_header_verboss(self) -> None :
        await self.parse_IGMPv2_memship_report_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += "IGMPv2 Memship Report Datagram :"
            self.formatted_header_verboss += f"{t}Type : {hex(self.type)}  Max Response Time : {self.float_decode(self.max_response_time)}"
            self.formatted_header_verboss += f"Checksum : {hex(self.checksum)}  Group Address : {self.group_addr}"
        return

    async def _format_parsed_IGMPv2_memship_report_header(self) -> None :
        await self.parse_IGMPv2_memship_report_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"IGMPv2 Memship Report : Type:{hex(self.type)}|Group:{self.group_addr}"
        return

    async def _format_parsed_IGMP_leave_group_header_verboss(self) -> None :
        await self.parse_IGMP_leave_group_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += "IGMP Leave Group Datagram :"
            self.formatted_header_verboss += f"{t}Type : {hex(self.type)}  Max Response Time : {self.float_decode(self.max_response_time)}"
            self.formatted_header_verboss += f"{t}Checksum : {hex(self.checksum)}  Group Address : {self.group_addr}"
        return

    async def _format_parsed_IGMP_leave_group_header(self) -> None :
        await self.parse_IGMP_leave_group_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"IGMP Leave Group : Type:{hex(self.type)}|Group:{self.group_addr}"
        return

    async def _format_parsed_IGMP_memship_query_header_verboss(self) -> None :
        await self.parse_IGMP_memship_query_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += "IGMP Memship Query Datagram :"
            self.formatted_header_verboss += f"{t}Type : {hex(self.type)}  Max Response Time : {self.float_decode(self.max_response_time)}"
            self.formatted_header_verboss += f"{t}Checksum : {hex(self.checksum)}  Group Address : {self.group_addr}"
            self.formatted_header_verboss += f"S-Flag : {self.s}  QRV : {self.qrv}  QQIC : {self.qqic}  Number of Sources : {self.number_of_sources}"
            self.formatted_header_verboss += f"{t}Source Addresses{t}\t"
            self.formatted_header_verboss += (t + "\t").join(self.source_addrs)
        return

    async def _format_parsed_IGMP_memship_query_header(self) -> None :
        await self.parse_IGMP_memship_query_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"IGMP Memship Query : Type:{hex(self.type)}|Group:{self.group_addr}|Number:{self.number_of_sources}"
        return

    async def _format_parsed_IGMPv3_memship_report_header_verboss(self) -> None :
        await self.parse_IGMPv3_memship_report_header()
        self.formatted_header_verboss = str()
        t = "\n\t\t"
        if not self.failure :
            self.formatted_header_verboss += f"IGMPv3 Memship Report Datagram :{t}Type : {hex(self.type)}"
            self.formatted_header_verboss += f"{t}Checksum : {hex(self.checksum)}{t}Number of Group Records : {self.number_of_group_records}"
            self.formatted_header_verboss += "{t}Group Records :{t}\t"
            for index, group in enumerate(self.group_records, start = 1) :
                record_type, aux_data_length, number_of_sources, multicast_addr, source_addrs, auxiliary_data = group
                self.formatted_header_verboss += f"Group_record[{index}] :{t}\t\tRecord Type : {await match_record_type(record_type)}({record_type})"
                self.formatted_header_verboss += f"{t}\t\tAux Data Length : {aux_data_length}  Number of Sources : {number_of_sources}"
                self.formatted_header_verboss += f"{t}\t\tMulticast Address : {multicast_addr}  Source Addresses :{t}\t\t\t"
                self.formatted_header_verboss += (t + "\t\t\t").join(source_addrs)
        return

    async def _format_parsed_IGMPv3_memship_report_header(self) -> None :
        await self.parse_IGMPv3_memship_report_header()
        self.formatted_header = str()
        if not self.failure :
            self.formatted_header += f"IGMPv3 Memship Report : Type:{hex(self.type)}|Number:{self.number_of_group_records}"
        return

    async def format_parsed_IGMP_header_verboss(self) -> str :
        match self.igmp_type :
            case 0x12 :
                await self._format_parsed_IGMPv1_memship_report_header_verboss()
                return self.formatted_header_verboss
            case 0x16 :
                await self._format_parsed_IGMPv2_memship_report_header_verboss()
                return self.formatted_header_verboss
            case 0x17 :
                await self._format_parsed_IGMP_leave_group_header_veboss()
                return self.formatted_header_verboss
            case 0x11 :
                await self._format_parsed_IGMP_memship_query_header_verboss()
                return self.formatted_header_verboss
            case 0x22 :
                await self._format_parsed_IGMPv3_memship_report_header_verboss()
                return self.formatted_header_verboss
            case _ :
                return str()

    async def format_parsed_IGMP_header(self) -> str :
        match self.igmp_type :
            case 0x12 :
                await self._format_parsed_IGMPv1_memship_report_header()
                return self.formatted_header
            case 0x16 :
                await self._format_parsed_IGMPv2_memship_report_header()
                return self.formatted_header
            case 0x17 :
                await self._format_parsed_IGMP_leave_group_header()
                return self.formatted_header
            case 0x11 :
                await self._format_parsed_IGMP_memship_query_header()
                return self.formatted_header
            case 0x22 :
                await self._format_parsed_IGMPv3_memship_report_header()
                return self.formatted_header
            case _ :
                return str()

