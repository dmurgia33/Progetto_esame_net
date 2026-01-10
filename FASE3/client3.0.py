#client3.0.py
import socket
from common import (
    create_handshake_packet, create_data_packet, parse_header, 
    generate_ecdh_keys, derive_shared_secret, encrypt_data, 
    PTYPE_HANDSHAKE
)

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    # ID fittizio del client (in QUIC vero sarebbe generato casualmente)
    my_conn_id = 101 

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(2.0) # Timeout per non bloccare se il server non risponde

    print(f"=== Client IoT Avviato (ID: {my_conn_id}) ===")

    try:
        # --- FASE 1: HANDSHAKE ---
        print("1. Inizio Handshake...")
        
        # Genera chiavi client
        clt_private_key, clt_public_key = generate_ecdh_keys()

        # Invia Client Hello (Chiave Pubblica)
        initial_packet = create_handshake_packet(my_conn_id, 1, clt_public_key)
        client_socket.sendto(initial_packet, (server_ip, server_port))

        # Ricevi Server Hello
        response, addr = client_socket.recvfrom(2048)
        type_byte, srv_conn_id, srv_pkt_num, payload = parse_header(response)

        if type_byte == PTYPE_HANDSHAKE:
            print(" -> Handshake Risposta Ricevuta dal Server.")
            
            # Estrai chiave server e deriva segreto
            srv_pub_key_bytes = payload[:65]
            shared_key = derive_shared_secret(clt_private_key, srv_pub_key_bytes)
            print(" -> Chiave segreta derivata con successo.")
        else:
            print("Errore: Risposta server non valida.")
            return

        # --- FASE 2: INVIO DATI CIFRATI ---
        print("\n2. Invio Dati Cifrati...")
        
        message = "Ciao Server! Questo è un messaggio top secret."
        print(f" -> Messaggio originale: '{message}'")
        
        # Cifratura
        encrypted_payload = encrypt_data(shared_key, message.encode('utf-8'))
        
        # Creazione pacchetto DATA
        data_packet = create_data_packet(my_conn_id, 2, encrypted_payload)
        
        # Invio
        client_socket.sendto(data_packet, (server_ip, server_port))
        print(" -> Pacchetto dati inviato.")
        
    except socket.timeout:
        print("Timeout: Il server non ha risposto.")
    except Exception as e:
        print(f"Errore: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    main()
