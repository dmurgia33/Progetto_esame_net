# test_data_replay.py
import socket
from common import (
    create_packet, parse_raw_header, generate_ecdh_keys, derive_session_keys, 
    encrypt_data, serialize_public_key, apply_header_protection,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_addr = ('127.0.0.1', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    conn_id = 777
    
    # --- HANDSHAKE VELOCE (Codice condensato) ---
    print("1. Handshake...")
    priv, pub = generate_ecdh_keys()
    sock.sendto(create_packet(PTYPE_INITIAL, conn_id, 1, serialize_public_key(pub)), server_addr)
    
    resp, _ = sock.recvfrom(4096) # Ricevo Retry
    _, _, _, token = parse_raw_header(resp)
    
    payload = token + serialize_public_key(pub)
    sock.sendto(create_packet(PTYPE_HANDSHAKE, conn_id, 2, payload), server_addr)
    
    resp, _ = sock.recvfrom(4096) # Ricevo Server Hello
    _, _, _, srv_pub = parse_raw_header(resp)
    sess_key, hp_key = derive_session_keys(priv, srv_pub)
    
    # --- TEST REPLAY ---
    print("2. Preparo un pacchetto DATA valido...")
    pkt_num = 10
    msg = b"Pagamento di 100 euro inviato."
    
    # Costruisco il pacchetto
    enc = encrypt_data(sess_key, msg)
    base = create_packet(PTYPE_DATA, conn_id, pkt_num, enc)
    prot = apply_header_protection(base[:9], hp_key, enc[:16]) + enc
    
    print(f"3. Invio pacchetto {pkt_num} (PRIMA VOLTA)")
    sock.sendto(prot, server_addr)
    
    print(f"4. Invio pacchetto {pkt_num} (SECONDA VOLTA - REPLAY!)")
    sock.sendto(prot, server_addr) # Invio ESATTAMENTE gli stessi byte
    
    print("Test finito. Controlla i log del server.")

if __name__ == "__main__":
    main()
