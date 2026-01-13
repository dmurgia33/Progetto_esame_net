# client.py
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
    sock.settimeout(2.0)
    
    my_conn_id = 555
    
    try:
        print("--- FASE 1: INITIAL ---")
        # Generiamo chiavi effimere
        clt_priv, clt_pub = generate_ecdh_keys()
        clt_pub_bytes = serialize_public_key(clt_pub)
        
        # Inviamo INITIAL (Payload: PubKey, anche se il server risponderà Retry)
        pkt = create_packet(PTYPE_INITIAL, my_conn_id, 1, clt_pub_bytes)
        sock.sendto(pkt, server_addr)
        
        print("--- FASE 2: ATTESA RETRY ---")
        resp, _ = sock.recvfrom(4096)
        rtype, _, _, token = parse_raw_header(resp)
        
        if rtype != PTYPE_RETRY:
            print("Errore: Mi aspettavo un RETRY!")
            return
        print(" -> Token ricevuto (Crittografico).")

        print("--- FASE 3: HANDSHAKE CON TOKEN ---")
        # Payload: Token + PubKey
        payload = token + clt_pub_bytes
        pkt = create_packet(PTYPE_HANDSHAKE, my_conn_id, 2, payload)
        sock.sendto(pkt, server_addr)
        
        # Ricezione Server Hello
        resp, _ = sock.recvfrom(4096)
        rtype, _, _, srv_pub_bytes = parse_raw_header(resp)
        
        if rtype == PTYPE_HANDSHAKE:
            # Derivazione chiavi finali
            sess_key, hp_key = derive_session_keys(clt_priv, srv_pub_bytes)
            print(" -> Handshake completato. Chiavi derivate.")
        else:
            print("Errore nell'handshake.")
            return

        print("--- FASE 4: INVIO DATI SICURI (Header Protection) ---")
        real_pkt_num = 0xDEADBEEF
        message = b"Ciao Server! Questo messaggio e' sicuro e l'header e' offuscato."
        
        # 1. Cifratura Dati (AES-GCM)
        encrypted_payload = encrypt_data(sess_key, message)
        
        # 2. Creazione Pacchetto Base (Header in chiaro)
        base_packet = create_packet(PTYPE_DATA, my_conn_id, real_pkt_num, encrypted_payload)
        
        # 3. Applicazione Header Protection (XOR Masking)
        header_bytes = base_packet[:9]
        sample = encrypted_payload[:16] # Campione per la maschera
        protected_header = apply_header_protection(header_bytes, hp_key, sample)
        
        # 4. Invio Pacchetto Finale
        final_packet = protected_header + encrypted_payload
        sock.sendto(final_packet, server_addr)
        print(f" -> Pacchetto {real_pkt_num} inviato.")

    except socket.timeout:
        print("Timeout: Nessuna risposta dal server.")
    except Exception as e:
        print(f"Errore Client: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
