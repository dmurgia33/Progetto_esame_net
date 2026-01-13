import socket
import struct
from common import (
    create_packet, parse_raw_header, generate_ecdh_keys, derive_session_keys, 
    encrypt_data, serialize_public_key, apply_header_protection,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_addr = ('127.0.0.1', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    my_id = 555
    # ... (Parte Handshake identica alla Fase 4 fino al calcolo chiavi) ...
    
    # 1. INITIAL
    clt_priv, clt_pub = generate_ecdh_keys()
    pkt = create_packet(PTYPE_INITIAL, my_id, 1, serialize_public_key(clt_pub))
    sock.sendto(pkt, server_addr)
    
    # 2. RETRY
    resp, _ = sock.recvfrom(2048)
    _, _, _, token = parse_raw_header(resp) # Payload è il token
    
    # 3. HANDSHAKE
    pkt = create_packet(PTYPE_HANDSHAKE, my_id, 2, token + serialize_public_key(clt_pub))
    sock.sendto(pkt, server_addr)
    
    # 4. SERVER HELLO -> Calcolo Chiavi
    resp, _ = sock.recvfrom(2048)
    _, _, _, srv_pub = parse_raw_header(resp)
    
    # ORA ABBIAMO LE DUE CHIAVI
    session_key, hp_key = derive_session_keys(clt_priv, srv_pub)
    print(" -> Chiavi derivate (Session + Header Protection).")

    # 5. INVIO DATI (MODIFICA DEBUG: HEADER IN CHIARO)
    real_pkt_num = 100 
    msg = b"Sto inviando il pacchetto 100 in chiaro!"
    
    # A. Creiamo il pacchetto standard (Header Chiaro + Payload Cifrato)
    encrypted_payload = encrypt_data(session_key, msg)
    packet_clear_header = create_packet(PTYPE_DATA, my_id, real_pkt_num, encrypted_payload)
    
    # --- MODIFICA: SALTIAMO LA PROTEZIONE ---
    # Invece di calcolare la maschera e applicarla, inviamo direttamente packet_clear_header
    
    # protected_header = apply_header_protection(...)  <-- COMMENTA QUESTO
    # final_packet = protected_header + encrypted_payload <-- COMMENTA QUESTO
    
    # Inviamo quello con l'header pulito
    sock.sendto(packet_clear_header, server_addr)
    
    print(f" -> Pacchetto {real_pkt_num} inviato (HEADER IN CHIARO per debug).")

    sock.close()

if __name__ == "__main__":
    main()
