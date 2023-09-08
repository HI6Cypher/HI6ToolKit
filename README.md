# HI6ToolKit :|
This script provides PacketSniffer that captures and analyzes the incoming packets(ICMP, IGMP, TCP, UDP).
The sniffed data can be saved to a file for further analysis. it provides functionality for launching DoS attacks and listening for incoming network connections. It supports SYN flood(Exception*), HTTP, UDP and The DoS attacks can be customized with parameters such as the target host, port, rate, and packet size.
it provides emailing tools like send email to list of targets(mass emailing)
The network listener allows you to monitor and log incoming data from network connections

## Classes :
- PacketSniff : Represents a Packet sniffing
- DoS_SYN : Represents a SYN flooding attack
- DoS_UDP : Represents a UDP flooding attack
- DoS_HTTP : Represents a HTTP flooding attack
- SendEmail : Represents a mass email sender
- Listen : Represents a network listener

## Usage :
- Download :
    ```bash
    git clone https://github.com/HI6Cypher/NetStatus.git
    ```
    or download directly
    ```bash
    https://github.com/HI6Cypher/NetStatus/archive/refs/heads/master.zip
    ```
    even raw code
    ```bash
    https://raw.githubusercontent.com/HI6Cypher/NetStatus/master/hi6toolkit.py
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
			xe5P\x18\x08\x00$\xc9\x00\x00{"time": "09/03/
            2023--19:07:19", "sender": "127.0.0.1", "hostname":
            "HI6Cypher", "host": "127.0.0.1", "message": "H3ll0 W0r1d"}'\

    ```

- To launch a DoS attack :
    ```bash
    python hi6toolkit.py DOS -m [UDP] -x [host] -p [port] -r [rate] -s [packet_size]
    ```
    and
    ```bash
    python hi6toolkit.py DOS -m [SYN/HTTP] -x [host] -p [port] -r [rate]
    ```
- Example of UDP flood :
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


    System: [os info] [Intel64 Family 6 Model 15 Stepping 13, GenuineIntel]
    Hostname: [a name]
    Python: [CPython 3.6.0]

    GitHub: [github.com/HI6Cypher]
    Email: [huaweisclu31@hotmail.com]


    Press anykey to continue...

    [+] ████████████████████████████████  100032 packets sent
    [+] All packets have sent
    [-] 13.73s
    ```

- To Send mass email :
    ```bash
    python hi6toolkit.py EMAIL --sender=[sender email] --key=[sender password] --rcptpath=[path of recipients file] --subject=[subject] --textpath=[path of message file]
    ```

- To start the network listener :
    ```bash
    python hi6toolkit.py LISTEN -x [host] -p [port] -t [time-out]
    ```
- Note : what's recipients file look like? (saperate with space)
    ```text
    email1@hotmail.com email2@gmail.com email3@outlook.com...
    ```
- Note : HI6ToolKit is a script, but it can use modular
    ```python
    from hi6toolkit import PacketSniff, DoS_SYN, DoS_UDP, DoS_HTTP, SendEmail, Listen
    ```
- Note : in KEYSfile, passwords must saperate with space like this
    ```text
    examplepassword helloworld unknownpass pass12345 12345admin...
    ```
- Exception :
    To send TCP/IP packet we need raw socket with `socket.IPPROTO_TCP` that 
    we have limitations :\ on raw socket in some Windows versions(XP, Vista, 7,...)
    to more information visit [Site](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2).

    so for this feature u have to use non-windows :\
## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT)

GitHub : [github.com/HI6Cypher](https://github.com/HI6Cypher) :)

Email : huaweisclu31@hotmail.com :)
