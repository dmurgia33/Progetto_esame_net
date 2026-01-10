# server.py
import socket
from common import parse_packet  # Importa la funzione di parsing dal modulo common.py


def main():
    server_ip = '127.0.0.1'  # Indirizzo IP del server
    server_port = 12345  # Porta su cui il server ascolta

    # Creare un socket UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    print(f"Server in ascolto su {server_ip}:{server_port}")

    while True:
        # Ricevere pacchetti dal client
        packet, addr = server_socket.recvfrom(1024)
        print(f"Pacchetto ricevuto da {addr}")

        # Parsing del pacchetto usando la funzione di common.py
        type_byte, conn_id, packet_number, public_key = parse_packet(packet)
        print(f"Tipo pacchetto: {type_byte}, ConnID: {conn_id}, PacketNumber: {packet_number}")

        # Rispondere al pacchetto con un semplice messaggio
        response = b"Risposta server"
        server_socket.sendto(response, addr)
        print("Risposta inviata al client.")


if __name__ == "__main__":
    main()
