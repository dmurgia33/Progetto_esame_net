# server.py
import socket
import struct
from common import (
    parse_raw_header, create_packet, generate_ecdh_keys, derive_session_keys, 
    decrypt_data, serialize_public_key,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    sessions = {} 
    SECRET_TOKEN = b'TOKEN_SICURO_123' 

    print(f"=== Server DEBUG (Header in chiaro) avviato su {server_ip}:{server_port} ===")

    while True:
        try:
            packet, addr = sock.recvfrom(2048)
            ptype, conn_id, raw_pn_bytes, payload = parse_raw_header(packet)

            # --- INIT ---
            if ptype == PTYPE_INITIAL:
                print(f"[INIT] Ricevuto INITIAL da {addr}. Invio RETRY.")
                resp = create_packet(PTYPE_RETRY, conn_id, 0, SECRET_TOKEN)
                sock.sendto(resp, addr)

            # --- HANDSHAKE ---
            elif ptype == PTYPE_HANDSHAKE:
                token_received = payload[:16]
                client_pub_key = payload[16:]
                
                if token_received != SECRET_TOKEN:
                    print("Token errato")
                    continue

                srv_priv, srv_pub = generate_ecdh_keys()
                sess_key, hp_key = derive_session_keys(srv_priv, client_pub_key)
                sessions[conn_id] = sess_key # Salviamo solo la session key per ora
                
                resp_payload = serialize_public_key(srv_pub)
                resp = create_packet(PTYPE_HANDSHAKE, conn_id, 0, resp_payload)
                sock.sendto(resp, addr)
                print(f"[HANDSHAKE] Keys generate per ID {conn_id}")

            # --- DATA (DEBUG: LEGGE IN CHIARO) ---
            elif ptype == PTYPE_DATA:
                if conn_id in sessions:
                    session_key = sessions[conn_id]
                    
                    # QUI STA LA MODIFICA: Leggiamo direttamente il numero grezzo
                    # Non applichiamo 'remove_header_protection'
                    pkt_num_int = struct.unpack('!I', raw_pn_bytes)[0]
                    
                    print(f"[DATA] PktNum ricevuto (IN CHIARO): {pkt_num_int}")
                    
                    try:
                        plaintext = decrypt_data(session_key, payload)
                        print(f"       Messaggio Decifrato: {plaintext.decode()}")
                    except Exception as e:
                        print(f"       Errore decifratura: {e}")
                else:
                    print(f"[ERR] Sessione {conn_id} sconosciuta")

        except Exception as e:
            print(f"Errore: {e}")

if __name__ == "__main__":
    main()
