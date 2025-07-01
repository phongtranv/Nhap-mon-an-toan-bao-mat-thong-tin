# sender_full.py
# -*- coding: utf-8 -*-
import socket
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from hashlib import sha256

HOST = 'localhost'
PORT = 23456

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    return serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

def encrypt_and_send_data(s, des_key):
    plaintext = b"Xin chao, day la thong diep tu Sender!"
    iv = get_random_bytes(8)
    cipher = DES.new(des_key, DES.MODE_CFB, iv=iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))
    ciphertext_hash = sha256(ciphertext).hexdigest()

    payload = {
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "hash": ciphertext_hash
    }

    s.sendall(json.dumps(payload).encode('utf-8'))
    print("Sender: Đã gửi bản mã và hash SHA-256 cho Receiver.")

def start_sender():
    sender_private_key, sender_public_key = generate_rsa_key_pair()
    print("Sender: Đã tạo cặp khóa RSA.")
    sender_public_key_bytes = serialize_public_key(sender_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            print(f"Sender: Đã kết nối tới Receiver trên {HOST}:{PORT}")
            s.sendall("Hello!".encode('utf-8'))
            print("Sender: Đã gửi 'Hello!' tới Receiver.")

            ready_msg = s.recv(1024).decode('utf-8')
            if ready_msg == "Ready!":
                print("Sender: Nhận được 'Ready!' từ Receiver.")
                s.sendall(sender_public_key_bytes)
                print("Sender: Đã gửi khóa công khai của mình tới Receiver.")

                receiver_public_key_bytes = s.recv(4096)
                receiver_public_key = deserialize_public_key(receiver_public_key_bytes)
                print("Sender: Đã nhận khóa công khai của Receiver.")
                print("--- Handshake hoàn tất trên phía Sender ---")

                des_key = b"12345678"  # 8-byte DES key
                encrypt_and_send_data(s, des_key)

            else:
                print(f"Sender: Lỗi handshake, nhận được '{ready_msg}' thay vì 'Ready!'.")
        except ConnectionRefusedError:
            print("Sender: Lỗi kết nối: Đảm bảo Receiver đang chạy.")
        except Exception as e:
            print(f"Sender: Đã xảy ra lỗi trong quá trình handshake: {e}")
        finally:
            s.close()

if __name__ == "__main__":
    start_sender()
