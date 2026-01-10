# client.py
import socket
from common import create_initial_packet  # Importa la funzione dal modulo common.py


def main():
    server_ip = '127.0.0.1'  # Indirizzo IP del server
    server_port = 12345  # Porta del server

    # Creare un socket UDP
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Dati di esempio (client_id, packet_number, public_key simulato)
    client_id = 1
    packet_number = 1
    public_key = b'\x01' * 32  # Semplice chiave fittizia di 32 byte

    # Creare pacchetto iniziale usando la funzione di common.py
    initial_packet = create_initial_packet(client_id, packet_number, public_key)

    # Inviare pacchetto al server
    client_socket.sendto(initial_packet, (server_ip, server_port))
    print("Pacchetto INITIAL inviato.")

    # Ricevere risposta dal server
    response, addr = client_socket.recvfrom(1024)
    print(f"Risposta ricevuta dal server: {response}")

    client_socket.close()


if __name__ == "__main__":
    main()
