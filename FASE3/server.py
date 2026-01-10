# server.py
import socket
from common import parse_packet, generate_ecdh_keys, derive_shared_secret, encrypt_data
import os

def main():
    server_ip = '127.0.0.1'
    server_port = 12345

    # Creare un socket UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"Server in ascolto su {server_ip}:{server_port}")

    while True:
        # Ricevere pacchetti dal client
        packet, addr = server_socket.recvfrom(1024)
        print(f"Pacchetto ricevuto da {addr}")
        
        # Parsing del pacchetto
        type_byte, conn_id, packet_number, public_key_bytes = parse_packet(packet)
        
        # Generare la coppia di chiavi ECDHE del server
        private_key, public_key = generate_ecdh_keys()

        # Derivare la chiave segreta usando la chiave pubblica del client
        key = derive_shared_secret(private_key, public_key_bytes)

        # Inviare la chiave pubblica del server al client
        server_response = create_initial_packet(conn_id, packet_number, public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        server_socket.sendto(server_response, addr)
        
        print(f"Risposta inviata al client.")

if __name__ == "__main__":
    main()
