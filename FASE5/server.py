import socket
from common import (
    parse_raw_header, create_packet, generate_ecdh_keys, derive_session_keys, 
    decrypt_data, serialize_public_key, apply_header_protection, remove_header_protection,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)
import struct

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    # Sessions ora salva una tupla: (session_key, hp_key)
    sessions = {} 
    SECRET_TOKEN = b'TOKEN_SICURO_123' 

    print(f"=== Server (FASE 5 - Header Protection) avviato ===")

    while True:
        try:
            packet, addr = sock.recvfrom(2048)
            # 1. Leggiamo solo Type e ConnID (che sono in chiaro)
            ptype, conn_id, raw_pn_bytes, payload = parse_raw_header(packet)

            # --- INIT e HANDSHAKE (Non cifrati nell'header per questo POC, per semplicità) ---
            if ptype == PTYPE_INITIAL:
                # ... Logica identica alla fase 4 ...
                resp = create_packet(PTYPE_RETRY, conn_id, 0, SECRET_TOKEN)
                sock.sendto(resp, addr)

            elif ptype == PTYPE_HANDSHAKE:
                # ... Logica identica alla fase 4 ...
                token_received = payload[:16]
                client_pub_key = payload[16:]
                if token_received != SECRET_TOKEN: continue

                srv_priv, srv_pub = generate_ecdh_keys()
                # NOTA: Ora derive_session_keys restituisce DUE chiavi
                sess_key, hp_key = derive_session_keys(srv_priv, client_pub_key)
                sessions[conn_id] = (sess_key, hp_key) # Salviamo entrambe
                
                resp_payload = serialize_public_key(srv_pub)
                # NOTA: Per l'handshake lasciamo l'header in chiaro per semplicità di bootstrap
                resp = create_packet(PTYPE_HANDSHAKE, conn_id, 0, resp_payload)
                sock.sendto(resp, addr)
                print(f"[HANDSHAKE] Keys generate per {conn_id}")

            # --- DATA (Qui applichiamo la PROTEZIONE HEADER) ---
            elif ptype == PTYPE_DATA:
                if conn_id in sessions:
                    session_key, hp_key = sessions[conn_id]
                    
                    # 1. Dobbiamo togliere la protezione all'header
                    # Usiamo i primi 16 byte del payload (che è il ciphertext) come "Sample"
                    sample = payload[:16]
                    
                    # Ricostruiamo l'header "protetto" completo per passarlo alla funzione
                    full_protected_header = packet[:9] 
                    
                    # Rimuoviamo la protezione
                    unprotected_header = remove_header_protection(full_protected_header, hp_key, sample)
                    
                    # Ora possiamo leggere il vero Packet Number
                    _, _, real_pn_bytes, _ = parse_raw_header(unprotected_header + payload)
                    real_pkt_num = struct.unpack('!I', real_pn_bytes)[0]
                    
                    print(f"[DATA] Header sbloccato! PktNum reale: {real_pkt_num}")
                    
                    # 2. Decifriamo il payload
                    plaintext = decrypt_data(session_key, payload)
                    print(f"       Messaggio: {plaintext.decode()}")
                else:
                    print(f"[ERR] Sessione {conn_id} sconosciuta")

        except Exception as e:
            print(f"Errore: {e}")

if __name__ == "__main__":
    main()
