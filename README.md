# HI6ToolKit :|


## Classes :
``` python
from hi6toolkit import Sniff, DoS_SYN, HTTP_Request, Tunnel
```

## Usage :
- raw code :

    [https://raw.githubusercontent.com/HI6Cypher/HI6ToolKit/master/hi6toolkit.py](https://raw.githubusercontent.com/HI6Cypher/HI6ToolKit/master/hi6toolkit.py)


- To Sniff packets :
    ``` bash
    python hi6toolkit.py sniff -i [interface(like wlo1, eth0 etc.)]
    ```

- Example of a sniffed packet from [CyG33k](https://github.com/HI6Cypher/CyGeek)
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
                Sender Protocol Address : 192.168.43.1
                Target Hardware Address : 00:00:00:00:00:00
                Target Protocol Address : 192.168.53.240


    ```

- To launch a DoS attack(SYN FLOOD) :
    ``` bash
    python hi6toolkit.py DOS -m [SYN] -x [host] -p [port] -r [rate]
    ```

- Example of SYN flood to (127.0.0.1) :
    ```


            [System] : [LINUX, Thu Aug 29 21:31:07 2024]
            [Hostname] : [hi6cypher]
            [Python] : [Cpython 3.11]

            [GitHub] : [github.com/HI6Cypher]
            [Email] : [huaweisclu31@hotmail.com]



    Press ENTER to continue...

    [+] //////////////////////////////// [4096/4096]
    [+] all SYN segments have sent
    [+] 0.71s

    ┌──[hi6@hi6cypher : ~/Hack/HI6ToolKit]
    └─$
    ```

- To sending HTTP request :
    ``` bash
    python hi6toolkit.py HTTP -x [host] -p [port/default=80] -e [endpoint] -s(for https/be sure u change port(changing default value))
    ```

- To receiving file(Tunnel) :
    ``` bash
    python hi6toolkit.py TUNNEL -x [host] -p [port] -t [timeout] -b [buffer]
    ```

- To print information :
    ``` bash
    python hi6toolkit.py INFO
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

    HTTP_Request : Note that this class doesn't implement appropriate data parsing algorithm!!!!!!, it is useful for RESTful APIs

    To send TCP/IP packet we need raw socket with `socket.IPPROTO_TCP` that
    we have limitations :\ on raw socket in some Windows versions(7, XP, Vista, ,...)
    to more information visit [Site](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2)

    so because of many incompatibility i limited hi6toolkit.py to use non-windows OS
    hi6toolkit has been tested on Linux & Unix(unix-based like darwin)

    <span style="color:red">Another case is also noticeable here, and that is `hi6toolkit.Sniff` can't work properly! unless u put python in firewall-allowlist :)</span>.
- Error :
    ``` bash
    ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self signed certificat
    ```
    this error occurs for `ssl` in `HTTP_Request` when user use `-s` or `--secure` and it can related to two things, "OS" or "Python Implementation"

    for "OS" stuff, is better to search around `cert.pem` etc.
    but about "Python Implementation", user should use latest python implementations(>=3.6) because paradigm of `ssl` module varies in each python
    implementation

GitHub : [github.com/HI6Cypher](https://github.com/HI6Cypher) :)

Email : [huaweisclu31@hotmail.com](mailto:huaweisclu31@hotmail.com) :)
