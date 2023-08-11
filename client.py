import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

HOST = "127.0.0.1"  
PORT = 1234 
curve = ec.SECP256R1()
encryptor = None 

def send_thread(sockfd: socket.socket, public_key: ec.EllipticCurvePrivateKey):
    tag = None
    global encryptor
    sockfd.sendall(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("$sent")

    while not encryptor:
        pass

    while True:
        message = input().encode()
        print("1")
        ciphertext = encryptor.update(message) + encryptor.finalize()
        encrypted_data = ciphertext + encryptor.tag
        sockfd.sendall(encrypted_data)
        print("$sent m")

def recv_thread(sockfd: socket.socket, private_key: ec.EllipticCurvePrivateKey):
    global encryptor

    peer_public_key = None
    kdf = None
    decryptor = None
    cipher = None
    shared_key = None 
    iv = '000000000000' #os.urandom(16)  # 128 bits

    while True:
        recv_message = sockfd.recv(1024)

        try:
            decoded_msg = recv_message.decode()

            if "-----BEGIN PUBLIC KEY-----" in decoded_msg:
                print("$received")
                peer_public_key = serialization.load_pem_public_key(recv_message, default_backend())
                shared_key_primitive = private_key.exchange(ec.ECDH(), peer_public_key)
                print(shared_key_primitive.hex())
                # Key Derivation Function (KDF)
                kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=100000, salt=os.urandom(16), length=32)
                shared_key = kdf.derive(shared_key_primitive)
                cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv), backend = default_backend)
                encryptor = cipher.encryptor()
                continue
        except:
            pass

        if not recv_message:
            print("Server Disconnected")
            break
        
        print("$received m")
        received_ciphertext = recv_message[:-16]  # 16 byte tag
        received_tag = recv_message[-16:]
        print(received_tag)
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv,received_tag))
        decryptor = cipher.decryptor()
        decrypted_plaintext = decryptor.update(received_ciphertext) + decryptor.finalize()

        print(decrypted_plaintext.decode())

def main():
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_fd:
        server_fd.connect((HOST, PORT))
        s_thr = threading.Thread(target=send_thread,args=(server_fd, public_key,))
        r_thr = threading.Thread(target=recv_thread,args=(server_fd, private_key,))
        
        s_thr.start()
        r_thr.start()

        s_thr.join()
        r_thr.join()

if __name__ == "__main__":
    main()