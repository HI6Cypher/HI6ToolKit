import signal

def a(a, b) : print(b.f_locals);exit()

signal.signal(signal.SIGTERM, a)
signal.signal(signal.SIGINT, a)
while True : pass

