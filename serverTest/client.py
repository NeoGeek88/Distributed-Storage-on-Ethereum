import socket, os, sys, time, random, select
from flask import Flask


class Client:
    def __init__(self, host):
        self.host = host

    def listen(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, port))
        sock.listen()


        socket_list = [sock]
        
        print("server started")

        
        print(f"listening on {self.host}:{port}...")

        while True:
            conn, addr = sock.accept()
            print(f"received connection from by {addr}")
            
            with open("file.txt", "wb") as f:
                f.write()
                
        


if __name__ == "__main__":
    host = "127.0.0.1"
    port = int(sys.argv[1]) 

    client = Client(host)

    client.listen(port)
