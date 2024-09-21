import socket
import threading
import json
import re
import os
import datetime, time

text = """
  _____  _  _               _     _____                                
 / ____|| |(_)             | |   / ____|                               
| |     | | _   ___  _ __  | |_ | (___    ___  _ __ __   __  ___  _ __ 
| |     | || | / _ \| '_ \ | __| \___ \  / _ \| '__|\ \ / / / _ \| '__|
| |____ | || ||  __/| | | || |_  ____) ||  __/| |    \ V / |  __/| |   
 \_____||_||_| \___||_| |_| \__||_____/  \___||_|     \_/   \___||_|  CyG33k
"""
options = """
1.Post
2.Inbox
3.Sent
"""
class ClientServer :
    def __init__(self) :
        self.text = text
        self.options = options
        self.clean = os.system("cls || clear")
        self.path_Inbox = f"{os.getcwd()}/Inbox.json"
        self.path_Sent = f"{os.getcwd()}/Sent.json"
        self.path_server_info = f"{os.getcwd()}/server_info.json"

    def main(self) :
        try :
            self.clean
            print(self.text)
            if not os.path.exists(self.path_Inbox) :
                with open(self.path_Inbox, "x") as file :
                    json.dump([], file, indent = 4)
            task_0 = threading.Thread(target = self.handshake)
            task_0.start()
            task_0.join()
            task_1 = threading.Thread(target = self.listen)
            task_1.start()
            while True :
                print(self.options)
                choice = input("-> ")
                if choice == "1" :
                    self.clean
                    hostname_input = input("Hostname: ")
                    message_input = input("Message: ")
                    time.sleep(1)
                    task_2 = threading.Thread(target = self.post, args = (hostname_input, message_input))
                    task_2.start()
                    task_2.join()
                elif choice == "2" :
                    self.clean
                    counter = 1
                    with open(self.path_Inbox, "r") as file :
                        for i in json.load(file) :
                            text = "\n[%s]-----------------------\nTime: %s\nSender: %s\nHostname: %s\nHost: %s\nMessage: %s\n--------------------------" \
                                % (counter, i["time"], i["sender"], i["hostname"], i["host"], i["message"])
                            counter += 1
                            print(text)
                elif choice == "3" :
                    self.clean
                    counter = 1
                    with open(self.path_Sent, "r") as file :
                        for i in json.load(file) :
                            text = "\n[%s]-----------------------\nTime: %s\nSender: %s\nHostname: %s\nHost: %s\nMessage: %s\n--------------------------" \
                                % (counter, i["time"], i["sender"], i["hostname"], i["host"], i["message"])
                            counter += 1
                            print(text)
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[MAIN] Error!--> {error}")
        except Exception as error :
            print(f"[MAIN] Error!--> {error}")

    def handshake(self) :
        try :
            server = dict()
            payload = socket.gethostbyname(socket.gethostname())
            start_time = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as handshake :
                handshake.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                while True :
                    try :
                        handshake.settimeout(2)
                        handshake.sendto(payload.encode(), ("255.255.255.255", 50321))
                        data = handshake.recvfrom(1024)
                        print(f"[*] the server found {data[1]}".upper())
                    except :
                        print("[!] cant find the server".upper(), flush = True)
                        print("[!] trying again... ".upper(), end = "\r", flush = True)
                        if time.time() - start_time > 60 :
                            time.sleep(1)
                            print("[!] server not found".upper())
                            break
                    else :
                        if "CyGeek" in data[0].decode() :
                            try :
                                server_host = re.search(r"(?<=HOST:).+(?=:HOST)", data[0].decode()).group()
                                server_port = re.search(r"(?<=PORT:).+(?=:PORT)", data[0].decode()).group()
                            except :
                                print("[!] security problem in network".upper())
                                os.remove("server_info.json")
                                break
                            else :
                                server["server_host"] = server_host
                                server["server_port"] = server_port
                                try :
                                    with open(self.path_server_info, "x") as file :
                                        json.dump([server], file, indent = 4)
                                except :
                                    with open(self.path_server_info, "w") as file :
                                        json.dump([server], file, indent = 4)
                            break
                        else :
                            continue
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[HANDSHAK] Error!--> {error}")
        except Exception as error :
            print(f"[HANDSHAK] Error!--> {error}")

    def listen(self) :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen :
                listen.bind((socket.gethostbyname(socket.gethostname()), 60321))
                listen.listen(5)
                while True :
                    conn, _ = listen.accept()
                    with conn :
                        data = conn.recv(1024)
                        self.saver(self.path_Inbox, data)
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[LISTEN] Error!--> {error}")
        except Exception as error :
            print(f"[LISTEN] Error!--> {error}")

    def post(self, hostname, message) :
        try :
            time = datetime.datetime.today()
            packet = {
                    "time" : time.strftime("%m/%d/%Y--%H:%M:%S"),
                    "sender" : socket.gethostbyname(socket.gethostname()),
                    "hostname" : hostname,
                    "host" : socket.gethostbyname(hostname),
                    "message" : message
                }
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as net :
                try :
                    with open(self.path_server_info, "r") as file :
                        info = json.load(file)
                    net.connect((info[0]["server_host"], 40321))
                    net.sendall(json.dumps(packet).encode())
                except OSError as error :
                    error = " ".join(str(error).split()[2:])
                    print(f"[POST] Error!--> {error}")
                else :
                    self.saver(self.path_Sent, json.dumps(packet).encode())
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[POST] Error!--> {error}")
        except Exception as error :
            print(f"[POST] Error!--> {error}")

    def saver(self, path, data) :
        try :
            try :
                with open(path, "r") as file :
                    loader = json.load(file)
                    loader.append(json.loads(data.decode()))
                with open(path, "w") as file :
                    json.dump(loader, file, indent = 4)
            except FileNotFoundError :
                with open(path, "x") as file :
                    json.dump([], file)
                with open(path, "r") as file :
                    loader = json.load(file)
                    loader.append(json.loads(data.decode()))
                with open(path, "w") as file :
                    json.dump(loader, file, indent = 4)
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[SAVER] Error!--> {error}")
        except Exception as error :
            print(f"[SAVER] Error!--> {error}")

if __name__ == "__main__" :
    try :
        client = ClientServer()
        client.main()
    except OSError as error :
        error = " ".join(str(error).split()[2:])
        print(f"[RUN] Error!--> {error}")
    except Exception as error :
        print(f"[RUN] Error!--> {error}")