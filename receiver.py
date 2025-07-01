# receiver_full.py
# -*- coding: utf-8 -*-
import socket
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
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

def receive_and_decrypt_data(conn, private_key):
    try:
        raw = conn.recv(4096)
        payload = json.loads(raw.decode('utf-8'))

        iv = bytes.fromhex(payload["iv"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        received_hash = payload["hash"]

        des_key = b"12345678"  # Phải khớp với Sender
        cipher = DES.new(des_key, DES.MODE_CFB, iv=iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), DES.block_size)

        computed_hash = sha256(ciphertext).hexdigest()
        if computed_hash == received_hash:
            print("Receiver: ✅ Hash khớp. Dữ liệu toàn vẹn.")
        else:
            print("Receiver: ❌ Hash không khớp. Dữ liệu bị thay đổi!")

        print(f"Receiver: 📩 Dữ liệu giải mã: {decrypted_data.decode('utf-8')}")

    except Exception as e:
        print(f"Receiver: Lỗi khi nhận/giiải mã: {e}")

def start_receiver():
    receiver_private_key, receiver_public_key = generate_rsa_key_pair()
    print("Receiver: Đã tạo cặp khóa RSA.")
    receiver_public_key_bytes = serialize_public_key(receiver_public_key)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Receiver: Đang lắng nghe trên {HOST}:{PORT}...")

        conn, addr = s.accept()
        with conn:
            print(f"Receiver: Đã chấp nhận kết nối từ {addr}")
            hello_msg = conn.recv(1024).decode('utf-8')
            if hello_msg == "Hello!":
                print("Receiver: Nhận được 'Hello!' từ Sender.")
                conn.sendall("Ready!".encode('utf-8'))
                print("Receiver: Đã gửi 'Ready!' tới Sender.")
                conn.sendall(receiver_public_key_bytes)
                print("Receiver: Đã gửi khóa công khai của mình tới Sender.")
                sender_public_key_bytes = conn.recv(4096)
                sender_public_key = deserialize_public_key(sender_public_key_bytes)
                print("Receiver: Đã nhận khóa công khai của Sender.")
                print("--- Handshake hoàn tất trên phía Receiver ---")
                receive_and_decrypt_data(conn, receiver_private_key)
            else:
                print(f"Receiver: Lỗi handshake, nhận '{hello_msg}' thay vì 'Hello!'.")

if __name__ == "__main__":
    start_receiver()
