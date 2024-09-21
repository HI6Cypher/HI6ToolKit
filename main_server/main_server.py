import socket
import threading
import json
import os
import datetime
text = """

 __  __         _          _____                                
|  \/  |       (_)        / ____|                               
| \  / |  __ _  _  _ __  | (___    ___  _ __ __   __  ___  _ __ 
| |\/| | / _` || || '_ \  \___ \  / _ \| '__|\ \ / / / _ \| '__|
| |  | || (_| || || | | | ____) ||  __/| |    \ V / |  __/| |   
|_|  |_| \__,_||_||_| |_||_____/  \___||_|     \_/   \___||_|  CyG33k
                                                                

"""
class MainServer :
    def __init__(self) :
        self.text = text
        self.path_unsends = f"{os.getcwd()}/unsends.json"

    def main(self) :
        os.system("cls || clear")
        try :
            if not os.path.exists(self.path_unsends) :
                first = [{
                        "time": "01/01/1970--00:00:00",
                        "sender": "None",
                        "hostname": "None",
                        "host": "None",
                        "message": "MainServer"
                    }]
                with open(self.path_unsends, "x") as file :
                    json.dump(first, file, indent = 4)
            task_0 = threading.Thread(target = self.handshake)
            task_0.start()
            task_1 = threading.Thread(target = self.listen)
            task_1.start()
            print(self.text)
            input("Press anykey to setup the Server... ")
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[MAIN] Error!--> {error}")
        except Exception as error :
            print(f"[MAIN] Error!--> {error}")


    def handshake(self) :
        try :
            payload = "CyGeek [HOST:%s:HOST][PORT:40321:PORT]" % (socket.gethostbyname(socket.gethostname()))
            time = datetime.datetime.today()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as handshake :
                handshake.bind((socket.gethostbyname(socket.gethostname()), 50321))
                while True :
                    try :
                        _, address = handshake.recvfrom(1024)
                        print("[HANDSHAKE]-> %s [%s]" % (address, time.strftime("%m/%d/%Y--%H:%M:%S")))
                        handshake.sendto(payload.encode(), address)
                        with open(self.path_unsends, "r") as file :
                            unsends = json.load(file)
                        for unsend in unsends :
                            if unsend["host"] == address[0] :
                                if self.post(address[0], unsend, address) :
                                    unsends.remove(unsend)
                                    with open(self.path_unsends, "w") as file :
                                        json.dump(unsends, file, indent = 4)
                                else :
                                    pass
                            else :
                                continue
                    except OSError:
                        continue
        except OSError as error:
            error = " ".join(str(error).split()[2:])
            print(f"[HANDSHAKE] Error!--> {error}")
        except Exception as error :
            print(f"[HANDSHAKE] Error!--> {error}")
                        

    def listen(self) :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen :
                listen.bind((socket.gethostbyname(socket.gethostname()), 40321))
                listen.listen(5)
                while True :
                    try :
                        conn, address = listen.accept()
                        with conn :
                            data = conn.recv(1024)
                            if not data :
                                continue
                            else :
                                data = json.loads(data.decode("utf-8"))
                                self.post(data["host"], data, address)
                    except :
                        pass
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[LISTEN] Error!--> {error}")
        except Exception as error :
            print(f"[LISTEN] Error!--> {error}")

    def post(self, host, payload, address) -> bool :
        try :
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as post :
                try :
                    post.connect((host, 60321))
                    post.sendall(json.dumps(payload).encode())
                    return True
                except :
                    self.saver(self.path_unsends, json.dumps(payload))
                    return False
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
                    loader.append(json.loads(data))
                with open(path, "w") as file :
                    json.dump(loader, file, indent = 4)
            except FileNotFoundError :
                with open(path, "x") as file :
                    json.dump([], file)
                with open(path, "r") as file :
                    loader = json.load(file)
                    loader.append(json.loads(data))
                with open(path, "w") as file :
                    json.dump(loader, file, indent = 4)
        except OSError as error :
            error = " ".join(str(error).split()[2:])
            print(f"[SAVER] Error!--> {error}")
        except Exception as error :
            print(f"[SAVER] Error!--> {error}")

if __name__ == "__main__" :
    try :
        server = MainServer()
        server.main()
    except OSError as error :
        error = " ".join(str(error).split()[2:])
        print(f"[RUN] Error!--> {error}")
    except Exception as error :
        print(f"[RUN] Error!--> {error}")