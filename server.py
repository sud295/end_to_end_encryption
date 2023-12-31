import socket
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json

HOST = "127.0.0.1"
PORT = 1234
curve = ec.SECP256R1()
shared_key  = None
iv = b'\xf0<\x92)A7\xaf\\\xa6k\xd6\xfc\x99\x88\x03>' #initialization vector
salt = b'<h\x1az\x94\x89\xec\x907\xe8\xc1\x8e\x03u\xe3\xa1'
rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
rsa_public_key = rsa_private_key.public_key()
aes_key = None

def send_thread(sockfd: socket.socket, public_key: ec.EllipticCurvePrivateKey):
    global iv
    global salt
    global rsa_private_key
    global rsa_public_key
    global aes_key
    # Send the encryption details

    signature = rsa_private_key.sign(public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo), PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH), hashes.SHA256())
    data_dict = {
        "rsa_public_key": rsa_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "ecdh_public_key": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        "initiator": "true",
        "identity": f"{HOST}:{PORT}"
    }

    json_bytes = json.dumps(data_dict).encode() + signature
    sockfd.sendall(json_bytes)

    while not aes_key:
        pass

    while True:
        message = input()
        message = message.encode()
        encryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        sockfd.sendall(ciphertext)

def recv_thread(sockfd: socket.socket, private_key: ec.EllipticCurvePrivateKey):
    shared_key =  None
    global iv
    global salt
    global aes_key
    rsa_phase = True
    peer_rsa_public_key = None

    while True:
        recv_message = sockfd.recv(1024)
    
        if rsa_phase:
            to_decode = recv_message[:-256]
            sig = recv_message[-256:]

            decoded_dict = json.loads(to_decode.decode('utf-8'))
            peer_rsa_public_key = serialization.load_pem_public_key(decoded_dict["rsa_public_key"].encode(), default_backend())
            key = decoded_dict["ecdh_public_key"].encode()

            try:
                peer_rsa_public_key.verify(sig, key, PSS(mgf=MGF1(hashes.SHA256()), salt_length=PSS.MAX_LENGTH), hashes.SHA256())
            except:
                print("Unable to verify peer identity; aborting connection.")
                continue

            peer_public_key = serialization.load_pem_public_key(key, default_backend())
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), iterations=100000, salt=salt, backend=default_backend(), length=32)
            aes_key = kdf.derive(shared_key)
            rsa_phase = False
            continue

        if not recv_message:
            print("Server Disconnected")
            break
        
        decryptor = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend()).decryptor()
        decrypted_text = decryptor.update(recv_message) + decryptor.finalize()

        print(decrypted_text.decode())


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