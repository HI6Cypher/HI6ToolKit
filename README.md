# HI6ToolKit :|


## Classes :
``` python
from hi6toolkit import Sniff, Scan, Trace, DoS_SYN, HTTP_Request, Tunnel
```

## Usage :
- raw code :

    [https://raw.githubusercontent.com/HI6Cypher/HI6ToolKit/main/hi6toolkit.py](https://raw.githubusercontent.com/HI6Cypher/HI6ToolKit/main/hi6toolkit.py)

- To Trace(traceroute) :
    ``` bash
    ./hi6toolkit.py trace -s [source(local) ip like 192.168.*.*] -x [host]
    ```

- To Scan ports :
    ``` bash
    ./hi6toolkit.py scan -s [source(local) ip like 192.168.*.*] -x [host] -p [port range like 0-443]
    ```

- To Sniff packets :
    ``` bash
    python hi6toolkit.py sniff -if [interface(like wlo1, eth0 etc.)] -t [to tmp in file]
    ```

- Example of a Ethernet frame with arp type
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

- Example of a Ethernet frame with IPv4 type and tcp protocol
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

- To launch a DoS attack(SYN FLOOD) :
    ``` bash
    python hi6toolkit.py dos -x [host] -p [port] -r [rate]
    ```

- Example of SYN flood to (127.0.0.1) :

    command
    ``` bash
    hi6@hi6cypher : ~/Net/HI6ToolKit $ ./hi6toolkit.py dos -x localhost -p 1337 -r 4096
    ```

    output
    ``` bash


            [System] : [LINUX, Thu Aug 29 21:31:07 2024]
            [Hostname] : [hi6cypher]
            [Python] : [Cpython 3.11]

            [GitHub] : [github.com/HI6Cypher]
            [Email] : [huaweisclu31@hotmail.com]



    Press ENTER to continue...

    [+] //////////////////////////////// [4096/4096]
    [+] all SYN segments have sent
    [+] 0.71s

    ```

- To sending HTTP request :
    ``` bash
    python hi6toolkit.py http -x [host] -p [port/default=80] -e [endpoint/default="/"] -s(for https/be sure u change port(changing default value))
    ```

- To receiving file(Tunnel) : u can use `curl` or whatever u want to upload file(note that the request http header must indicate **Content-Length** value)
    ``` bash
    python hi6toolkit.py tunnel -x [host/default=0.0.0.0] -p [port/default=80] -t [timeout/default=60] -b [buffer/default=2048]
    ```

- To print some information :
    ``` bash
    python hi6toolkit.py info
    ```

- Note : HI6ToolKit is a script, but it can use as module
    ``` python
    from hi6toolkit import HTTP_Request

    serv = "www.example.com"

    http = HTTP_Request(host = serv, port = 80, method = "GET", header = None, end = "/", https = False)
    http.request() # Note that this class doesn't implement appropriate data parsing algorithm!!!!!!, it is useful for RESTful APIs
    # Note that you can deploy your custom http-header in header argument

    print(http.request_header, http.response_header, "\n\n", http.response)
    ```
    ``` html
    #output

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
    <head>
        <title>Example Domain</title>

        <meta charset="utf-8" />
        <meta http-equiv="Content-type" content="text/html; charset=utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style type="text/css">
        body {
            background-color: #f0f0f2;
            margin: 0;
            padding: 0;
            font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;

        }
        div {
            width: 600px;
            margin: 5em auto;
            padding: 2em;
            background-color: #fdfdff;
            border-radius: 0.5em;
            box-shadow: 2px 3px 7px 2px rgba(0,0,0,0.02);
        }
        a:link, a:visited {
            color: #38488f;
            text-decoration: none;
        }
        @media (max-width: 700px) {
            div {
                margin: 0 auto;
                width: auto;
            }
        }
        </style>
    </head>

    <body>
    <div>
        <h1>Example Domain</h1>
        <p>This domain is for use in illustrative examples in documents. You may use this
        domain in literature without prior coordination or asking for permission.</p>
        <p><a href="https://www.iana.org/domains/example">More information...</a></p>
    </div>
    </body>
    </html>
    ```

- Exception :

    HTTP_Request : Note that this class doesn't implement appropriate data parsing algorithm!!!!!!, it is useful for simple RESTful APIs

    To send TCP/IP packet we need raw socket with `socket.IPPROTO_TCP` that
    we have limitations :\ on raw socket in some Windows versions(7, XP, Vista, ,...)
    to more information visit [Site](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2)

    so because of many incompatibility I limited hi6toolkit.py to use non-windows OS
    hi6toolkit has been tested on Linux & Unix(unix-based like darwin)

    <span style="color:red">for Sniff, DoS_SYN and Tunnel u have to have root access:)</span>.

GitHub : [github.com/HI6Cypher](https://github.com/HI6Cypher)

Email : [huaweisclu31@hotmail.com](mailto:huaweisclu31@hotmail.com)
Email : [swhwap.net@gmail.com](mailto:swhwap.net@gmail.com)

<span style="color:cyan;font-size:140">;)</span>
