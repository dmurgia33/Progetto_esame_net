import socket
import struct
from common import (
    create_packet, parse_header, generate_ecdh_keys, derive_shared_secret, 
    encrypt_data, serialize_public_key,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

def main():
    server_addr = ('127.0.0.1', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    
    my_id = 555
    pkt_num = 1

    try:
        # --- PASSO 1: INITIAL (Invio PubKey - anche se verrà ignorata, serve a triggerare) ---
        print("1. Invio INITIAL...")
        # Nota: In realtà in QUIC Initial contiene già la chiave, ma il server la ignora se vuole fare Retry.
        # Mandiamo 65 byte vuoti o una chiave vera, non importa per il trigger.
        clt_priv, clt_pub = generate_ecdh_keys()
        clt_pub_bytes = serialize_public_key(clt_pub)
        
        pkt = create_packet(PTYPE_INITIAL, my_id, pkt_num, clt_pub_bytes)
        sock.sendto(pkt, server_addr)

        # --- PASSO 2: Attesa RETRY ---
        resp, _ = sock.recvfrom(2048)
        rtype, rid, rnum, rpayload = parse_header(resp)

        if rtype == PTYPE_RETRY:
            token = rpayload # Il server ci ha mandato il token
            print(f"2. Ricevuto RETRY con Token: {token}")
        else:
            print("Errore: Mi aspettavo un RETRY!")
            return

        # --- PASSO 3: HANDSHAKE (Invio Token + PubKey) ---
        print("3. Invio HANDSHAKE con Token...")
        pkt_num += 1
        
        # Payload = Token + PubKey
        payload = token + clt_pub_bytes
        pkt = create_packet(PTYPE_HANDSHAKE, my_id, pkt_num, payload)
        sock.sendto(pkt, server_addr)

        # --- PASSO 4: Attesa HANDSHAKE SERVER (Server PubKey) ---
        resp, _ = sock.recvfrom(2048)
        rtype, rid, rnum, srv_pub_bytes = parse_header(resp)

        if rtype == PTYPE_HANDSHAKE:
            print("4. Ricevuto HANDSHAKE dal Server. Calcolo segreto...")
            shared_key = derive_shared_secret(clt_priv, srv_pub_bytes)
            print(" -> Connessione STABILITA!")
        else:
            print("Errore: Handshake fallito.")
            return

        # --- PASSO 5: DATI (Sessione sicura) ---
        print("5. Invio dati cifrati...")
        msg = b"Funziona il protocollo a 3 vie!"
        enc_msg = encrypt_data(shared_key, msg)
        
        pkt = create_packet(PTYPE_DATA, my_id, pkt_num+1, enc_msg)
        sock.sendto(pkt, server_addr)

    except Exception as e:
        print(f"Errore Client: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
