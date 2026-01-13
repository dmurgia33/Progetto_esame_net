import socket
import struct
from common import (
    parse_header, create_packet, generate_ecdh_keys, derive_shared_secret, 
    decrypt_data, serialize_public_key,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    # Stato: {conn_id: session_key}
    sessions = {} 
    
    # Per semplicità in FASE 4, usiamo un token fisso (nella FASE 6 sarà crittografico)
    SECRET_TOKEN = b'TOKEN_SICURO_123' 

    print(f"=== Server (Protocollo FASE 4) su {server_ip}:{server_port} ===")

    while True:
        try:
            packet, addr = sock.recvfrom(2048)
            ptype, conn_id, pkt_num, payload = parse_header(packet)

            # --- 1. STATO INIT: Arriva Client Hello ---
            if ptype == PTYPE_INITIAL:
                print(f"[INIT] Ricevuto INITIAL da {addr}. Invio RETRY.")
                # Non salvo nulla (Stateless). Rispondo solo con il Token.
                # Payload RETRY = Token
                resp = create_packet(PTYPE_RETRY, conn_id, 0, SECRET_TOKEN)
                sock.sendto(resp, addr)

            # --- 2. STATO HANDSHAKE: Arriva Client Hello + Token ---
            elif ptype == PTYPE_HANDSHAKE:
                # Il payload qui deve essere: [Token (16 bytes) | PubKey (65 bytes)]
                # Nota: La lunghezza del token la decidiamo noi, qui assumo 16 byte fissi per semplicità
                token_received = payload[:16]
                client_pub_key = payload[16:]

                if token_received != SECRET_TOKEN:
                    print(f"[ERR] Token non valido da {addr}")
                    continue

                print(f"[HANDSHAKE] Token valido. Negoziazione chiavi per ID {conn_id}...")

                # Genera chiavi server
                srv_priv, srv_pub = generate_ecdh_keys()
                
                # Deriva Shared Secret
                shared_key = derive_shared_secret(srv_priv, client_pub_key)
                sessions[conn_id] = shared_key
                
                # Rispondi con la Server PubKey
                # Payload = Server PubKey
                resp_payload = serialize_public_key(srv_pub)
                resp = create_packet(PTYPE_HANDSHAKE, conn_id, pkt_num, resp_payload)
                sock.sendto(resp, addr)
                print(" -> Handshake completato lato Server.")

            # --- 3. STATO ESTABLISHED: Dati cifrati ---
            elif ptype == PTYPE_DATA:
                if conn_id in sessions:
                    try:
                        plaintext = decrypt_data(sessions[conn_id], payload)
                        print(f"[DATA] Messaggio decifrato: {plaintext.decode()}")
                    except Exception as e:
                        print(f"[ERR] Decifratura fallita: {e}")
                else:
                    print(f"[ERR] Sessione {conn_id} inesistente.")

        except Exception as e:
            print(f"Errore: {e}")

if __name__ == "__main__":
    main()
