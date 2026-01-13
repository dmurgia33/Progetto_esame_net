# client_test_replay.py
import socket
import time
from common import (
    create_packet, parse_raw_header, generate_ecdh_keys, 
    serialize_public_key, PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE
)

def main():
    server_addr = ('127.0.0.1', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0) # Timeout breve
    my_id = 999
    
    try:
        # 1. Chiedo il Token (INITIAL)
        print("[CLIENT] 1. Invio INITIAL...")
        _, clt_pub = generate_ecdh_keys()
        pkt = create_packet(PTYPE_INITIAL, my_id, 1, serialize_public_key(clt_pub))
        sock.sendto(pkt, server_addr)
        
        # 2. Ricevo il Token (RETRY)
        resp, _ = sock.recvfrom(4096)
        rtype, _, _, token = parse_raw_header(resp)
        if rtype == PTYPE_RETRY:
            print("[CLIENT] 2. Token ricevuto! È valido per 5 secondi.")
        
        # 3. IL TEST: Aspetto finché il token scade!
        print("[CLIENT] ... Mi addormento per 7 secondi ...")
        time.sleep(7) 
        print("[CLIENT] ... Mi sono svegliato! Provo a usare il token vecchio.")

        # 4. Provo a usare il token scaduto (HANDSHAKE)
        payload = token + serialize_public_key(clt_pub)
        pkt = create_packet(PTYPE_HANDSHAKE, my_id, 2, payload)
        sock.sendto(pkt, server_addr)
        
        # 5. Vediamo se il server risponde
        print("[CLIENT] 3. Ho inviato l'Handshake. Aspetto risposta...")
        resp, _ = sock.recvfrom(4096)
        print(">>> FALLIMENTO: Il server ha risposto! Il token scaduto è stato accettato (MALE).")

    except socket.timeout:
        print("\n>>> SUCCESSO! Il server NON ha risposto.")
        print("    Il token scaduto è stato scartato correttamente.")
    except Exception as e:
        print(f"Errore: {e}")

if __name__ == "__main__":
    main()
