from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import socket
import struct

def diffie_hellman_key_exchange(server_socket):
    p = struct.unpack('!Q', server_socket.recv(8))[0]
    g = struct.unpack('!Q', server_socket.recv(8))[0]
    server_public_key = struct.unpack('!Q', server_socket.recv(8))[0]

    private_key = get_random_bytes(8)
    public_key = pow(g, private_key[0], p)

    server_socket.send(struct.pack('!Q', public_key))

    shared_key = pow(server_public_key, private_key[0], p)

    return shared_key.to_bytes(8, byteorder='big')

def des_encrypt(message, key):
    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message, DES.block_size))
    return ciphertext

def main():
    host = '127.0.0.1'
    port = 12345

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    shared_key = diffie_hellman_key_exchange(client_socket)

    with open("mensajeentrada.txt", "rb") as file:
        message = file.read()

    key_des = shared_key[:8]
    ciphertext_des = des_encrypt(message, key_des)
    client_socket.send(ciphertext_des)

    client_socket.close()

if __name__ == "__main__":
    main()