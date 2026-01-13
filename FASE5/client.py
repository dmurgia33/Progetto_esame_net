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

    # 5. INVIO DATI CON HEADER PROTECTION
    real_pkt_num = 0xDEADBEEF  # Facciamo finta di essere al pacchetto 0xDEADBEEF utile per debugging
    msg = b"Header Protection attiva! Non puoi vedere che questo e' il pacchetto 100."
    
    # A. Creiamo il pacchetto standard (Header Chiaro + Payload Cifrato)
    encrypted_payload = encrypt_data(session_key, msg)
    packet_clear_header = create_packet(PTYPE_DATA, my_id, real_pkt_num, encrypted_payload)
    
    # B. Applichiamo la protezione all'Header
    # Prendiamo solo l'header (primi 9 byte)
    header_bytes = packet_clear_header[:9]
    # Sample = primi 16 byte del payload cifrato
    sample = encrypted_payload[:16]
    
    protected_header = apply_header_protection(header_bytes, hp_key, sample)
    
    # C. Assembliamo il pacchetto finale (Header Protetto + Payload Cifrato)
    final_packet = protected_header + encrypted_payload
    
    sock.sendto(final_packet, server_addr)
    print(f" -> Pacchetto {real_pkt_num} inviato con header offuscato.")

    sock.close()

if __name__ == "__main__":
    main()
