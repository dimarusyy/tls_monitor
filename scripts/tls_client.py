import socket, ssl, pprint
import time
import os

print(os.getpid())

while(1):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # require a certificate from the server
    ssl_sock = ssl.wrap_socket(s)
    ssl_sock.connect(('127.0.0.1', 44000))

    ssl_sock.send("<packet>This is ssl payload!</packet>\n")

    pprint.pprint(ssl_sock.getpeercert())

    print("sleeping 10sec ")
    time.sleep(10)

    # note that closing the SSLSocket will also close the underlying socket
    ssl_sock.close()

