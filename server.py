import socket

IP = "127.0.0.1"
PORT = 1234

fd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fd.bind((IP,PORT))

fd.listen(1)

#thing