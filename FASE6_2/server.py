# server.py
import socket
import struct
import os
from common import (
    parse_raw_header, create_packet, generate_ecdh_keys, derive_session_keys, 
    decrypt_data, serialize_public_key, remove_header_protection,
    generate_retry_token, validate_retry_token, parse_handshake_payload,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_ip = '127.0.0.1'
    server_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    # Memoria Sessioni: { conn_id : (session_key, header_protection_key) }
    sessions = {} 
    
    # Chiave segreta per firmare i Token (Nota: in produzione va persistita)
    SERVER_MASTER_KEY = os.urandom(32)

    print(f"=== Server IoT Sicuro (QUIC-like) avviato su {server_ip}:{server_port} ===")

    while True:
        try:
            packet, addr = sock.recvfrom(4096)
            
            # Parsiamo l'header parziale (PktNum è ancora potenzialmente cifrato)
            ptype, conn_id, raw_pn_bytes, payload = parse_raw_header(packet)

            # --- 1. INITIAL: Client si presenta ---
            if ptype == PTYPE_INITIAL:
                print(f"[INIT] Richiesta da {addr}. Invio sfida (Retry Token).")
                # Generiamo un token crittografico legato all'IP
                token = generate_retry_token(SERVER_MASTER_KEY, addr)
                # Rispondiamo con RETRY
                resp = create_packet(PTYPE_RETRY, conn_id, 0, token)
                sock.sendto(resp, addr)

            # --- 2. HANDSHAKE: Client risponde alla sfida ---
            elif ptype == PTYPE_HANDSHAKE:
                try:
                    token_received, client_pub_key = parse_handshake_payload(payload)
                except ValueError:
                    continue 

                # Validiamo il Token
                if not validate_retry_token(SERVER_MASTER_KEY, addr, token_received, validity_seconds=5):
                    print(f"[ERR] Token invalido o scaduto da {addr}. Ignoro.")
                    continue
                
                print(f"[HANDSHAKE] Token valido. Negoziazione chiavi per ID {conn_id}...")

                # ECDHE: Generiamo le nostre chiavi e deriviamo il segreto
                srv_priv, srv_pub = generate_ecdh_keys()
                sess_key, hp_key = derive_session_keys(srv_priv, client_pub_key)
                
                # Salviamo lo stato della sessione
                sessions[conn_id] = (sess_key, hp_key)
                
                # Rispondiamo con Server Hello (contiene la nostra PubKey)
                resp_payload = serialize_public_key(srv_pub)
                resp = create_packet(PTYPE_HANDSHAKE, conn_id, 0, resp_payload)
                sock.sendto(resp, addr)

            # --- 3. DATA: Scambio dati sicuro ---
            elif ptype == PTYPE_DATA:
                if conn_id in sessions:
                    session_key, hp_key = sessions[conn_id]
                    
                    # A. RIMOZIONE HEADER PROTECTION
                    # Usiamo i primi 16 byte del payload (ciphertext) come sample
                    sample = payload[:16]
                    # Ricostruiamo l'header completo cifrato
                    full_protected_header = packet[:9]
                    
                    # Rimuoviamo la maschera XOR
                    unprotected_header = remove_header_protection(full_protected_header, hp_key, sample)
                    
                    # Ora possiamo leggere il vero Packet Number
                    _, _, real_pn_bytes, _ = parse_raw_header(unprotected_header + payload)
                    real_pkt_num = struct.unpack('!I', real_pn_bytes)[0]
                    
                    print(f"[DATA] PktNum sbloccato: {real_pkt_num}")
                    
                    # B. DECIFRATURA PAYLOAD
                    try:
                        plaintext = decrypt_data(session_key, payload)
                        print(f"       Messaggio: '{plaintext.decode()}'")
                    except Exception as e:
                        print(f"       Errore decifratura (Auth Tag invalido?): {e}")
                else:
                    print(f"[ERR] Sessione {conn_id} non trovata.")

        except Exception as e:
            print(f"Errore server generico: {e}")

if __name__ == "__main__":
    main()
