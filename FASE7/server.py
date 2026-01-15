# server.py (FASE 7 - ANTI-REPLAY COMPLETO)
import socket
import struct
import os
from common import (
    parse_raw_header, create_packet, generate_ecdh_keys, derive_session_keys, 
    decrypt_data, serialize_public_key, remove_header_protection,
    generate_retry_token, validate_retry_token, parse_handshake_payload,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

# Configurazione Anti-Replay
WINDOW_SIZE = 20  # Accettiamo pacchetti vecchi solo se distano meno di 20 dal massimo

def is_replay_or_old(session_state, pkt_num):
    """
    Controlla se il pacchetto è un duplicato o troppo vecchio.
    Restituisce True se il pacchetto va scartato.
    """
    seen = session_state['seen_packets']
    max_pn = session_state['max_pn']
    
    # CASO 1: Duplicato esatto
    if pkt_num in seen:
        print(f"[REPLAY] Pacchetto {pkt_num} già processato! Scarto.")
        return True
    
    # CASO 2: Troppo vecchio (fuori dalla finestra)
    # Esempio: Siamo al 100, arriva il 70. Se window=20, il minimo accettabile è 80.
    if pkt_num < (max_pn - WINDOW_SIZE):
        print(f"[OLD] Pacchetto {pkt_num} troppo vecchio (Max: {max_pn}). Scarto.")
        return True
        
    # Se il pacchetto è valido:
    # Aggiorniamo il massimo se necessario
    if pkt_num > max_pn:
        session_state['max_pn'] = pkt_num
        
    # Aggiungiamo ai visti
    seen.add(pkt_num)
    
    # Pulizia: Rimuoviamo dal set i numeri troppo vecchi per non occupare memoria infinita
    # (In un progetto reale si usano bitmask, qui usiamo un set pulito periodicamente)
    if len(seen) > WINDOW_SIZE * 2:
        cutoff = session_state['max_pn'] - WINDOW_SIZE
        # Tieni solo quelli recenti
        session_state['seen_packets'] = {p for p in seen if p > cutoff}
        
    return False

def main():
    server_ip = '0.0.0.0'
    server_port = 12345
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))

    # STRUTTURA DATI AGGIORNATA
    # sessions = { conn_id : { 'keys': (...), 'seen_packets': set(), 'max_pn': 0 } }
    sessions = {} 
    
    SERVER_MASTER_KEY = os.urandom(32)

    print(f"=== Server IoT Sicuro (Fase 7: Anti-Replay) avviato ===")

    while True:
        try:
            packet, addr = sock.recvfrom(4096)
            ptype, conn_id, raw_pn_bytes, payload = parse_raw_header(packet)

            # --- INITIAL ---
            if ptype == PTYPE_INITIAL:
                # (Logica identica a Fase 6)
                token = generate_retry_token(SERVER_MASTER_KEY, addr)
                resp = create_packet(PTYPE_RETRY, conn_id, 0, token)
                sock.sendto(resp, addr)

            # --- HANDSHAKE ---
            elif ptype == PTYPE_HANDSHAKE:
                # (Logica identica a Fase 6)
                try:
                    token_received, client_pub_key = parse_handshake_payload(payload)
                except ValueError: continue 

                if not validate_retry_token(SERVER_MASTER_KEY, addr, token_received, validity_seconds=30):
                    print(f"[ERR] Token invalido da {addr}")
                    continue
                
                print(f"[HANDSHAKE] Nuovo client: {conn_id}")
                srv_priv, srv_pub = generate_ecdh_keys()
                sess_key, hp_key = derive_session_keys(srv_priv, client_pub_key)
                
                # INIZIALIZZIAMO LO STATO ANTI-REPLAY
                sessions[conn_id] = {
                    'keys': (sess_key, hp_key),
                    'seen_packets': set(),
                    'max_pn': 0
                }
                
                resp_payload = serialize_public_key(srv_pub)
                resp = create_packet(PTYPE_HANDSHAKE, conn_id, 0, resp_payload)
                sock.sendto(resp, addr)

            # --- DATA (CON CONTROLLO REPLAY) ---
            elif ptype == PTYPE_DATA:
                if conn_id in sessions:
                    state = sessions[conn_id]
                    session_key, hp_key = state['keys']
                    
                    # 1. Rimuovi Header Protection per leggere il PktNum
                    sample = payload[:16]
                    full_protected_header = packet[:9]
                    unprotected_header = remove_header_protection(full_protected_header, hp_key, sample)
                    _, _, real_pn_bytes, _ = parse_raw_header(unprotected_header + payload)
                    real_pkt_num = struct.unpack('!I', real_pn_bytes)[0]
                    
                    # 2. CONTROLLO ANTI-REPLAY (Cuore della Fase 7)
                    if is_replay_or_old(state, real_pkt_num):
                        # Se è True, ignoriamo il pacchetto e torniamo al while
                        continue 
                    
                    # 3. Decifratura (Se siamo qui, il pacchetto è NUOVO)
                    try:
                        plaintext = decrypt_data(session_key, payload)
                        print(f"[DATA] Pkt {real_pkt_num} Accettato: '{plaintext.decode()}'")
                    except Exception as e:
                        print(f"       Errore decifratura: {e}")
                else:
                    print(f"[ERR] Sessione {conn_id} sconosciuta.")

        except Exception as e:
            print(f"Errore server: {e}")

if __name__ == "__main__":
    main()
