import socket
import threading

HOST = "127.0.0.1"  
PORT = 1234 

def send_thread(sockfd: socket.socket):
    while True:
        message = input()
        sockfd.sendall(message.encode())

def recv_thread(sockfd: socket.socket):
    while True:
        recv_message = sockfd.recv(1024)
        if not recv_message:
                print("Server Disconnected")
                break
        print(recv_message.decode())

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_fd:
        server_fd.connect((HOST, PORT))
        s_thr = threading.Thread(target=send_thread,args=(server_fd,))
        r_thr = threading.Thread(target=recv_thread,args=(server_fd,))
        
        s_thr.start()
        r_thr.start()

        s_thr.join()
        r_thr.join()

if __name__ == "__main__":
    main()