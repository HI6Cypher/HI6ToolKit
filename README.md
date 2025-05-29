# HI6ToolKit
hi6toolkit.py is a script which include several useful network tools
I've developed it for personal use, but it can be used everywhere by anybody
most advanced tools of hi6toolkit is it's sniffer

## Classes
``` python
from hi6toolkit import Sniff, Scan, Trace, DoS_Arp, DoS_SYN, HTTP_Request, Tunnel
```

## Usage
- raw code :
    [hi6toolkit.py](https://raw.githubusercontent.com/HI6Cypher/HI6ToolKit/main/hi6toolkit.py)

- To lunch ARP Request flood attack(it downs local gateway) :
    ``` bash
    ./hi6toolkit.py dos arp -if [interface] -g [gateway ip] -s [source ip] -sm [mac address]
    ```
    - source ip :
        - can be specific like 10.10.45.81
        - can be range of ip addresses with using wildcard char like 192.168.\*.\* for random IPs

- To Trace(traceroute) :
    ``` bash
    ./hi6toolkit.py trace -x [host]
    ```

- To Scan ports :
    ``` bash
    ./hi6toolkit.py scan -x [host] -p [port range like 0-443]
    ```

- To Sniff packets :
    ``` bash
    python hi6toolkit.py sniff -if [interface(like wlo1, eth0 etc.)] -t [to store in file]
    ```

- Example of a Ethernet frame with arp type(with -v option) :
    ``` text
        [+][DATALINK]________________1726738881________________

        Ethernet Frame :
                Source MAC : 55:c7:42:f7:aa:d3
                Destination MAC : ee:5d:47:fe:ab:11
                Ethernet Type : ARP

        Arp Datagram :
                Hardware Type : Ethernet(1)
                Protocol Type : IPv4
                Hardware Length : 6
                Protocol Length : 4
                Opcode : ARP REQ
                Sender Hardware Address : 55:c7:42:f7:aa:d3
                Sender Protocol Address : 192.168.53.1
                Target Hardware Address : 00:00:00:00:00:00
                Target Protocol Address : 192.168.53.240


    ```

- Example of a Ethernet frame with IPv4 type and tcp protocol(with -v option) :
    ``` text
        [+][DATALINK]________________1726751606________________

        Ethernet Frame :
                Source MAC : cc:47:40:fc:7b:05
                Destination MAC : 74:a5:28:cd:d5:d3
                Ethernet Type : IPv4

        IPv4 Datagram :
                Version : 4  Header Length : 20  Time of Service : 0
                Total Length : 389  Identification : 59656  Flags : 2
                Fragment Offset : 0  TTL : 64  Protocol : TCP
                Checksum : 0x6f49  Source : 192.168.53.240  Destination : 54.171.166.213

        TCP Segment :
                Source Port : 35448
                Destination Port : 80
                Sequence : 1270847567
                Acknowledgment : 1039940062
                Data Offset : 32
                Flags :
                    URG:0  ACK:1  PSH:1
                    RST:0  SYN:0  FIN:0
                Window : 502
                Checksum : 0x8e62
                Urgent Pointer : 0
                Raw Data :
                    GET / HTTP/1.1\r\nHost: skip.com\r\nUser-Agent: Mozilla/5.0
                     (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0\r\nA
                    ccept: text/html,application/xhtml+xml,application/xml;q=0.9,ima
                    ge/avif,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\
                    r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nU
                    pgrade-Insecure-Requests: 1\r\n\r\n
    ```

- Example of Ethernet frame with IPv4 and TCP(without -v option)
    ```
    [48][DATALINK_FRAME]________________1747149132________________
    Ethernet : Src:a2:50:9b:9f:d7:9b|Dst:cc:47:40:fc:7b:05|Type:IPv4
    IPv4 : Ver:4|Ident:47072|Proto:TCP|Src:185.15.59.240|Dst:192.168.12.207|TTL:51
    TCP : Src:443|Dst:34214|Seq:160349168|Acn:3746320966
        Flags : URG:0 ACK:1 PSH:1 RST:0 SYN:0 FIN:0

    [49][DATALINK_FRAME]________________1747149132________________
    Ethernet : Src:cc:47:40:fc:7b:05|Dst:a2:50:9b:9f:d7:9b|Type:IPv4
    IPv4 : Ver:4|Ident:36423|Proto:TCP|Src:192.168.12.207|Dst:185.15.59.224|TTL:64
    TCP : Src:47988|Dst:443|Seq:1219226806|Acn:3990511773
        Flags : URG:0 ACK:1 PSH:0 RST:0 SYN:0 FIN:0
    ```

- To launch a DoS attack(SYN FLOOD) :
    ``` bash
    python hi6toolkit.py dos syn -x [host] -p [port] -r [rate]
    ```

- To sending HTTP request :
    ``` bash
    python hi6toolkit.py http -x [host] -e [endpoint/default="/"]
    ```

- To sending HTTPs request :
    ``` bash
    python hi6toolkit.py http -x [host] -p 443 -e [endpoint/default="/"] -s
    ```

- To print some information :
    ``` bash
    python hi6toolkit.py info
    ```

- Note :  
HI6ToolKit is a script, but it can use as module
    ``` python
    from hi6toolkit import HTTP_Request

    serv = "www.example.com"

    http = HTTP_Request(host = serv, port = 80, method = "GET", header = None, end = "/", https = False)
    http.request() # Note that this class doesn't implement appropriate data parsing algorithm!!!!!!, it is useful for RESTful APIs
    # Note that you can deploy your custom http-header in header argument

    print(http.request_header, http.response_header, "\n\n", http.response)
    ```

    ``` html
    GET / HTTP/1.1
    Host: www.example.com
    User-Agent: HI6ToolKit
    Accept: */*
    Connection: close

    HTTP/1.1 200 OK
    Accept-Ranges: bytes
    Age: 315458
    Cache-Control: max-age=604800
    Content-Type: text/html; charset=UTF-8
    Date: Mon, 03 Jun 2024 10:19:22 GMT
    Etag: "3147526947+gzip"
    Expires: Mon, 10 Jun 2024 10:19:22 GMT
    Last-Modified: Thu, 17 Oct 2019 07:18:26 GMT
    Server: ECAcc (dcd/7D4F)
    Vary: Accept-Encoding
    X-Cache: HIT
    Content-Length: 1256
    Connection: close

    <!doctype html>
    <html>
        ...
    </html>
    ```

## Exceptions
- To send TCP/IP packet we need raw socket with `socket.IPPROTO_TCP` protocol which
we have limitations :poker_face: on raw socket in some Windows versions(7, XP, Vista, ,...)
to more information visit <https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2>
so because of many incompatibility I limited hi6toolkit.py to use non-windows OS
hi6toolkit has been tested on Linux(not tested on unix-based)
- Note that this class doesn't implement appropriate data parsing algorithm!!!!!!, it is useful for simple RESTful APIs

## Contact
Emails :  
- [hotmail](mailto:huaweisclu31@hotmail.com)  
- [gmail](mailto:swhwap.net@gmail.com)

<span style="color:#002b36;font-size:140">;)</span>
