#server3.0.py
import socket
from common import (
    parse_header, generate_ecdh_keys, derive_shared_secret, create_handshake_packet, decrypt_data, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_ip = '127.0.0.1'
    server_port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((server_ip, server_port))

    # STATE MANAGEMENT: Dizionario per salvare le chiavi di sessione
    # Format: { conn_id : shared_key }
    sessions = {} 

    print(f"=== Server IoT Sicuro avviato su {server_ip}:{server_port} ===")

    while True:
        try:
            packet, addr = server_socket.recvfrom(2048)
            
            # 1. Parsing generico dell'header
            type_byte, conn_id, packet_number, payload = parse_header(packet)
            
            # --- CASO A: HANDSHAKE (Inizio connessione) ---
            if type_byte == PTYPE_HANDSHAKE:
                print(f"[HANDSHAKE] Richiesta da {addr} (ID: {conn_id})")
                
                # Payload è la Public Key del Client (65 bytes)
                client_pub_key_bytes = payload[:65] 
                
                # Genera chiavi effimere server
                srv_private_key, srv_public_key = generate_ecdh_keys()
                
                # Calcola il segreto condiviso
                shared_key = derive_shared_secret(srv_private_key, client_pub_key_bytes)
                
                # MEMORIZZA LA CHIAVE PER FUTURI MESSAGGI
                sessions[conn_id] = shared_key
                print(f" -> Chiave derivata e sessione salvata per ID {conn_id}")

                # Rispondi con la chiave pubblica del server
                response = create_handshake_packet(conn_id, packet_number, srv_public_key)
                server_socket.sendto(response, addr)
            
            # --- CASO B: DATA (Messaggio cifrato) ---
            elif type_byte == PTYPE_DATA:
                print(f"[DATA] Pacchetto cifrato da {addr} (ID: {conn_id})")
                
                if conn_id in sessions:
                    session_key = sessions[conn_id]
                    try:
                        # Tenta la decifratura
                        plaintext = decrypt_data(session_key, payload)
                        print(f" -> MESSAGGIO DECIFRATO: '{plaintext.decode('utf-8')}'")
                    except Exception as e:
                        print(f" -> ERRORE Decifratura (Auth Tag invalido?): {e}")
                else:
                    print(f" -> ERRORE: Sessione {conn_id} non trovata (Handshake mancante?)")
            
            else:
                print(f"Tipo pacchetto sconosciuto: {type_byte}")

        except Exception as e:
            print(f"Errore generico nel loop: {e}")

if __name__ == "__main__":
    main()
