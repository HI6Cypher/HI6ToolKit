# HI6ToolKit :|
This script provides PacketSniffer that captures and analyzes the incoming packets(ICMP, IGMP, TCP, UDP).
The sniffed data can be saved to a file for further analysis. it provides functionality for launching DoS attacks, it supports SYN flood(Exception*) and UDP and The DoS attacks can be customized with parameters such as the target host, port, rate, and packet size.
it provides emailing tools like send email to list of targets(mass emailing)
The network listener allows you to monitor and log incoming data from network connections

## Classes :
- Sniff : Represents a Packet sniffing
- DoS_SYN : Represents a SYN flooding attack
- DoS_UDP : Represents a UDP flooding attack
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
    python hi6toolkit.py SNIFF -x [host] -m [protocol/ALL]
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

- To launch a DoS attack :
    ```bash
    python hi6toolkit.py DOS -m [UDP] -x [host] -p [port] -r [rate] -s [packet_size]
    ```
    and
    ```bash
    python hi6toolkit.py DOS -m [SYN] -x [host] -p [port] -r [rate]
    ```

- Example of UDP flood (127.0.0.1) :
    ```
                        :::!~!!!!!:.
                    .xUHWH!! !!?M88WHX:.
                    .X*#M@$!!  !X!M$$$$$$WWx:.
                :!!!!!!?H! :!$!$$$$$$$$$$8X:
                !!~  ~:~!! :~!$!#$$$$$$$$$$8X:
                :!~::!H!<   ~.U$X!?R$$$$$$$$MM!
                ~!~!!!!~~ .:XW$$$U!!?$$$$$$RMM!
                !:~~~ .:!M"T#$$$$WX??#MRRMMM!
                ~?WuxiW*`   `"#$$$$8!!!!??!!!
                :X- M$$$$       `"T#$T~!8$WUXU~
                :%`  ~#$$$m:        ~!~ ?$$$$$$
            :!`.-   ~T$$$$8xx.  .xWW- ~""##*"
    .....   -~~:<` !    ~?T#$$@@W@*?$$      /`
    W$@@M!!! .!~~ !!     .:XUW$W!~ `"~:    :
    #"~~`.:x%`!!  !H:   !WM$$$$Ti.: .!WUn+!`
    :::~:!!`:X~ .: ?H.!u "$$$B$$$!W:U!T$$M~
    .~~   :X@!.-~   ?@WTWo("*$$$W$TH$! `
    Wi.~!X$?!-~  : : ?$$$B$Wu("**$RM!
    $R@i.~~ !  :  :   ~$$$$$B$$en:``
    ?MXT@Wx.~-~-~:     ~"##*$$$$M~


     _    _  _____    __  _______              _  _  __ _  _
    | |  | ||_   _|  / / |__   __|            | || |/ /(_)| |
    | |__| |  | |   / /_    | |    __    ___  | || ' /  _ | |_
    |  __  |  | |  |  _ \   | |  / _ \  / _ \ | ||  <  | || __|
    | |  | | _| |_ | (_) |  | | | (_) || (_) || || . \ | || |_
    |_|  |_||_____| \___/   |_|  \___/  \___/ |_||_|\_\|_| \__|


    HI6ToolKit Copyright (C) 2023 HI6Cypher

    System: [os info] [Intel64 Family 6 Model 15 Stepping 13, GenuineIntel]
    Hostname: [hostname]
    Python: [CPython 3.6.0]

    GitHub: [github.com/HI6Cypher]
    Email: [huaweisclu31@hotmail.com]


    Press anykey to continue...

    [+] ████████████████████████████████  100032 packets sent
    [+] All packets have sent
    [-] 13.73s
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
- Note : in recpfile, emails should saperate with space like this
    ```
    email@hotmail.com email@outlook.com email@gmail.com ...
    ```

- To start the network listener :
    ```bash
    python hi6toolkit.py LISTEN -m [TCP/UDP] -x [host] -p [port] -t [time-out]
    ```

- To see some information of os,.. and ascii art :
    ```bash
    python hi6toolkit.py ART
    ```
- Note : HI6ToolKit is a script, but it can use modular(set module argument, True)
    ```python
    from hi6toolkit import Sniff, DoS_SYN, DoS_UDP, HTTP_Request, SendEmail, Listen
    ```

- Exception :
    To send TCP/IP packet we need raw socket with `socket.IPPROTO_TCP` that 
    we have limitations :\ on raw socket in some Windows versions(XP, Vista, 7,...)
    to more information visit [Site](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2).

    so for this feature(DoS_SYN) limited to use non-windows(fuck microsoft :|) :\
## License

This project is licensed under the [GPL v3.0 License](https://www.gnu.org/licenses/gpl-3.0.html)

GitHub : [github.com/HI6Cypher](https://github.com/HI6Cypher) :)

Email : huaweisclu31@hotmail.com :)
