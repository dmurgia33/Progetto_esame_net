# client.py
import socket
from common import create_initial_packet, generate_ecdh_keys, derive_shared_secret, encrypt_data
import os

def main():
    server_ip = '127.0.0.1'
    server_port = 12345

    # Creare un socket UDP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Generare la coppia di chiavi ECDHE
    private_key, public_key = generate_ecdh_keys()

    # Creare pacchetto iniziale con la chiave pubblica
    initial_packet = create_initial_packet(1, 1, public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # Inviare pacchetto iniziale al server
    client_socket.sendto(initial_packet, (server_ip, server_port))
    print("Pacchetto INITIAL inviato.")

    # Ricevere la risposta dal server (la sua chiave pubblica)
    response, addr = client_socket.recvfrom(1024)
    type_byte, conn_id, packet_number, peer_public_key_bytes = parse_packet(response)
    
    # Derivare la chiave segreta condivisa usando la chiave pubblica del server
    key = derive_shared_secret(private_key, peer_public_key_bytes)

    # Cifrare i dati con la chiave derivata (esempio di messaggio)
    message = b"Hello, this is a secret message."
    encrypted_message = encrypt_data(key, message)
    print(f"Messaggio cifrato: {encrypted_message}")

    client_socket.close()

if __name__ == "__main__":
    main()
