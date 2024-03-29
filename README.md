# HI6ToolKit :|


## Classes :
- Sniff : Represents a Packet sniffing
- DoS_SYN : Represents a SYN flooding attack
- SendEmail : Represents a mass email sender
- Listen : Represents a network listener

## Usage :
- Download :
    ```bash
    git clone https://github.com/HI6Cypher/HI6ToolKit.git
    ```
    or download directly
    ```bash
    https://github.com/HI6Cypher/HI6ToolKit/archive/refs/heads/master.zip
    ```
    even raw code
    ```bash
    https://raw.githubusercontent.com/HI6Cypher/HI6ToolKit/master/hi6toolkit.py
    ```


- To Sniff packets :
    ```bash
    python hi6toolkit.py SNIFF -x [host/DEFAULT] -m [TCP/UDP/ICMP/ALL]
    ```

- Example of a sniffed packet from [CyG33k](https://github.com/HI6Cypher/CyGeek)
    ```text
    [*][66] Connection________[20230903190719]________

	IPv4 Packet :
		Version : 4  Header Length : 20  Time of Service : 0
		Total Length : 171  Identification : 3500  Flags : 2
		Fragment Offset : 0  TTL : 128  Protocol : TCP
		Checksum : 0x0  Source : 127.0.0.1  Destination : 127.0.0.1
	TCP Segment :
		Source Port : 1202
		Destination Port : 60321
		Sequence : 2046406544
		Ackknowledgement : 2596328933
		Data Offset : 20
		Flags :
			URG:0  ACK:1  PSH:1
			RST:0  SYN:0  FIN:0
		Window : 2048
		Checksum : 0x24c9
		Urgent Pointer : 0
		Raw Data :
			b'\x04\xb2\xeb\xa1y\xf9\xaf\x90\x9a\xc0\xd5
			\xe5P\x18\x08\x00$\xc9\x00\x00{"time": "09/03/
            2023--19:07:19", "sender": "127.0.0.1", "hostname":
            "HI6Cypher", "host": "127.0.0.1", "message": "H3ll0 W0r1d"}'\

    ```

- To launch a DoS attack(SYN FLOOD) :
    ```bash
    python hi6toolkit.py DOS -m [SYN] -x [host] -p [port] -r [rate]
    ```

- Example of SYN flood (127.0.0.1) :
    ```

        █ [System] : [fuckOS]
        █ [Hostname] : [HI6Cypher]
        █ [Python] : [CPython 3.6.0]

        █ [GitHub] : [github.com/HI6Cypher]
        █ [Email] : [huaweisclu31@hotmail.com]


    Press anykey to continue...

    [+] ████████████████████████████████  100032 packets sent
    [+] All packets have sent
    [-] 39.73s
    ```

- To sending HTTP request (decode output) :
    ```bash
    python hi6toolkit.py HTTP -x [host] -p [port/default=80] -e [endpoint] -d
    ```
- To sending HTTP request (encode output) :
    ```bash
    python hi6toolkit.py HTTP -x [host] -p [port/default=80] -e [endpoint]
    ```
- To sending HTTPS request (decode output) :
    ```bash
    python hi6toolkit.py HTTPS -x [host] -p [port/default=443] -e [endpoint] -d
    ```
- To sending HTTPS request (encode output) :
    ```bash
    python hi6toolkit.py HTTPS -x [host] -p [port/default=443] -e [endpoint]
    ```
- To Send mass email :
    ```bash
    python hi6toolkit.py EMAIL --sender=[sender email] --key=[sender password] --rcptpath=[path of recipients file] --subject=[subject] --textpath=[path of message file]
    ```
- Note : in recipients file, emails should saperate with space like this
    ```
    email@hotmail.com email@outlook.com email@gmail.com ...
    ```

- To start the network listener :
    ```bash
    python hi6toolkit.py LISTEN -m [TCP/UDP] -x [host] -p [port] -t [timeout]
    ```

- To print information :
    ```bash
    python hi6toolkit.py INFO
    ```
- Note : HI6ToolKit is a script, but it can use modular
    ```python
    from hi6toolkit import Sniff, DoS_SYN, HTTP_Request, SendEmail, Listen
    ```

- Exception :
    To send TCP/IP packet we need raw socket with `socket.IPPROTO_TCP` that 
    we have limitations :\ on raw socket in some Windows versions(7, XP, Vista, ,...)
    to more information visit [Site](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2).

    so DoS_SYN and just-tcp packetsniffer are limited to use non-windows(fuck microsoft) :\

GitHub : [github.com/HI6Cypher](https://github.com/HI6Cypher) :)

Email : huaweisclu31@hotmail.com :)
