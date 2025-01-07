#!/usr/bin/python3
import asyncio
import socket
from hi6toolkit import DoS_SYN as dos
from hi6toolkit import Sniff
import random

class Scan(dos) :
    def __init__(self, host : str, event_loop : "async_event_loop", port, rate) -> "Scan_class" :
        super().__init__(host, port, rate)
        self.loop = event_loop
        self.source = "192.168.129.207"
        self.ipv4_static_header = self.ipv4_header()
        self.opens = list()

    def ipv4_header(self) -> bytes :
        src = socket.inet_pton(socket.AF_INET, self.source)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        randidn = random.randint(1024, 65535)
        header = self.ip_header(src = src, dst = dst, idn = randidn)
        checksum_ip_header = self.checksum(header)
        header = self.ip_header(src = src, dst = dst, idn = randidn, csm = checksum_ip_header)
        return header

    def tcpip_header(self, port : int) -> bytes :
        src = socket.inet_pton(socket.AF_INET, self.source)
        dst = socket.inet_pton(socket.AF_INET, self.host)
        srp = random.randint(1024, 65535)
        dsp = port
        randseq = random.randint(0, 65535)
        header = self.tcp_header(srp = srp, dsp = dsp, seq = randseq, syn = 1)
        pseudo_header = self.pseudo_header(src = src, dst = dst, pln = len(header))
        checksum_tcp_header = self.checksum(header + pseudo_header)
        header = self.tcp_header(srp = srp, dsp = dsp, seq = randseq, syn = 1, csm = checksum_tcp_header)
        return header

    async def package(self, port : int) -> bytes :
        ip_header = self.ipv4_static_header
        tcp_header = self.tcpip_header(port)
        payload = ip_header + tcp_header
        return payload

    async def send(self, port : int) -> None :
        payload = await self.package(port)
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as scan :
            scan.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            await self.loop.sock_sendto(scan, payload, (self.source, port))
            while True :
                rsp = await self.loop.sock_recv(scan, 1024)
                s = Sniff("wlo1", False, False, None, None)
                if Sniff.ip_header(rsp[:20])[-1] == self.source and \
                    Sniff.ip_header(rsp[:20])[-2] == self.host :
                    return rsp

    def is_open_port(self, tcp_header : bytes) -> bool :
         flags = tcp_header[13:14]
         ack_syn = bytes(flags).hex() == "12"
         return True if ack_syn else False

    async def scan(self, port : int) -> bool :
        response = await self.send(port)
        tcp_header = response[20:]
        is_open = self.is_open_port(tcp_header)
        if is_open :
            print(str(port) + " is open")
            self.opens.append(is_open)
            return True
        else : return False


async def main() -> None :
    loop = asyncio.get_event_loop()
    scan = Scan("127.0.0.1", loop, 555, None)
    tasks = list()
    for i in range(2048, 2049) :
        tasks.append(loop.create_task(scan.scan(i)))
    else :
        await asyncio.gather(*tasks)
    return scan.opens

asyncio.run(main())
