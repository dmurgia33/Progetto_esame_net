# client.py
import socket
import struct
from common import (
    create_packet, parse_raw_header, generate_ecdh_keys, derive_session_keys,
    encrypt_data, serialize_public_key, apply_header_protection,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)


def main():
    server_addr = ('172.20.10.6', 12345)  # Assicurati che l'IP sia corretto
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    my_conn_id = 555

    try:
        # --- FASI 1, 2, 3: HANDSHAKE STANDARD (NON TOCCARE) ---
        print("--- FASE 1: INITIAL ---")
        clt_priv, clt_pub = generate_ecdh_keys()
        clt_pub_bytes = serialize_public_key(clt_pub)
        pkt = create_packet(PTYPE_INITIAL, my_conn_id, 1, clt_pub_bytes)
        sock.sendto(pkt, server_addr)

        print("--- FASE 2: ATTESA RETRY ---")
        resp, _ = sock.recvfrom(4096)
        rtype, _, _, token = parse_raw_header(resp)
        if rtype != PTYPE_RETRY:
            print("Errore: Mi aspettavo un RETRY!")
            return

        print("--- FASE 3: HANDSHAKE CON TOKEN ---")
        payload = token + clt_pub_bytes
        pkt = create_packet(PTYPE_HANDSHAKE, my_conn_id, 2, payload)
        sock.sendto(pkt, server_addr)

        resp, _ = sock.recvfrom(4096)
        rtype, _, _, srv_pub_bytes = parse_raw_header(resp)
        if rtype == PTYPE_HANDSHAKE:
            sess_key, hp_key = derive_session_keys(clt_priv, srv_pub_bytes)
            print(" -> Handshake completato.")
        else:
            print("Errore nell'handshake.")
            return

        # --- FASE 4 MODIFICATA: INVIO DEADBEEF IN CHIARO ---
        print("\n--- FASE 4: DEMO WIRESHARK (NO CRITTOGRAFIA) ---")

        real_pkt_num = 10

        # 1. Creiamo il Payload "DEADBEEF" visibile
        # Lo ripetiamo 8 volte così è lungo e si vede bene nel dump esadecimale
        payload_in_chiaro = bytes.fromhex('DEADBEEF')* 8

        print(f"Stiamo inviando questo payload RAW: {payload_in_chiaro.hex().upper()}")

        # 2. Creiamo il pacchetto SENZA usare 'encrypt_data'
        # Passiamo direttamente i byte grezzi al posto del ciphertext
        packet_raw = create_packet(PTYPE_DATA, my_conn_id, real_pkt_num, payload_in_chiaro)

        # 3. NON applichiamo Header Protection
        # Inviamo il pacchetto così com'è, totalmente nudo
        sock.sendto(packet_raw, server_addr)

        print(f" -> Pacchetto {real_pkt_num} inviato in chiaro!")
        print(" -> CONTROLLA ORA WIRESHARK: Dovresti vedere 'DE AD BE EF' nel payload.")

    except socket.timeout:
        print("Timeout: Nessuna risposta (Normale se il server scarta il pacchetto)")
    except Exception as e:
        print(f"Errore Client: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
