import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import copy 

HOST = "127.0.0.1"
PORT = 1234
curve = ec.SECP256R1()
shared_key  = None
iv = os.urandom(16)
salt = os.urandom(16)

def send_thread(sockfd: socket.socket, public_key: ec.EllipticCurvePrivateKey):
    global shared_key
    global iv
    global salt
    sockfd.sendall(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))

    while not shared_key:
        pass

    while True:
        message = input()
        message = message.encode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=100000, salt=salt, backend=default_backend(), length=32)
        aes_key = kdf.derive(shared_key)
        encryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        sockfd.sendall(ciphertext)

def recv_thread(sockfd: socket.socket, private_key: ec.EllipticCurvePrivateKey):
    global shared_key
    global iv
    global salt
    aes_key = None

    while True:
        recv_message = sockfd.recv(1024)

        try:
            decoded_msg = copy.deepcopy(recv_message).decode()

            if "-----BEGIN PUBLIC KEY-----" in decoded_msg:
                peer_public_key = serialization.load_pem_public_key(recv_message, default_backend())
                shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=100000, salt=salt, backend=default_backend(), length=32)
                aes_key = kdf.derive(shared_key)
                continue
        except:
            pass

        if not recv_message:
            print("Server Disconnected")
            break
        
        print(recv_message)
        decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend()).decryptor()
        decrypted_text = decryptor.update(recv_message) + decryptor.finalize()

        print(decrypted_text)


def main():
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fd:
        fd.bind((HOST, PORT))
        fd.listen()
        client_fd, client_addr = fd.accept()
        print(f"Connected by {client_addr}")
        s_thr = threading.Thread(target=send_thread,args=(client_fd, public_key,))
        r_thr = threading.Thread(target=recv_thread,args=(client_fd, private_key,))

        s_thr.start()
        r_thr.start()

        s_thr.join()
        r_thr.join()

if __name__ == "__main__":
    main()