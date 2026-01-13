# client.py
import socket
from common import (
    create_packet, parse_raw_header, generate_ecdh_keys, derive_session_keys, 
    encrypt_data, serialize_public_key,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_addr = ('127.0.0.1', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    my_id = 555
    pkt_num = 1

    try:
        # 1. INITIAL
        clt_priv, clt_pub = generate_ecdh_keys()
        pkt = create_packet(PTYPE_INITIAL, my_id, 1, serialize_public_key(clt_pub))
        sock.sendto(pkt, server_addr)
        
        # 2. RICEVI RETRY
        resp, _ = sock.recvfrom(2048)
        _, _, _, token = parse_raw_header(resp) 
        
        # 3. HANDSHAKE
        pkt = create_packet(PTYPE_HANDSHAKE, my_id, 2, token + serialize_public_key(clt_pub))
        sock.sendto(pkt, server_addr)
        
        # 4. RICEVI SERVER HELLO
        resp, _ = sock.recvfrom(2048)
        _, _, _, srv_pub = parse_raw_header(resp)
        
        sess_key, hp_key = derive_session_keys(clt_priv, srv_pub)
        print(" -> Chiavi derivate.")

        # 5. INVIO DATI (DEBUG: IN CHIARO)
        real_pkt_num = 0xDEADBEEF 
        msg = b"Vedi il numero 100 in chiaro su Wireshark?"
        
        # Cifriamo il payload
        encrypted_payload = encrypt_data(sess_key, msg)
        
        # Creiamo pacchetto standard (Header in chiaro)
        packet_clear_header = create_packet(PTYPE_DATA, my_id, real_pkt_num, encrypted_payload)
        
        # QUI STA LA MODIFICA: Inviamo direttamente quello in chiaro
        # Senza applicare 'apply_header_protection'
        sock.sendto(packet_clear_header, server_addr)
        
        print(f" -> Pacchetto {real_pkt_num} inviato (HEADER NON PROTETTO).")

    except Exception as e:
        print(f"Errore: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
