# attack_suite.py
import socket
import time
import struct
import os

# Importiamo le funzioni dal nostro protocollo per "simulare" un client
from common import (
    create_packet, parse_raw_header, generate_ecdh_keys, derive_session_keys, 
    encrypt_data, serialize_public_key, apply_header_protection,
    PTYPE_INITIAL, PTYPE_RETRY, PTYPE_HANDSHAKE, PTYPE_DATA
)

# --- CONFIGURAZIONE ---
# INSERISCI QUI L'IP DEL MAC (SERVER)
SERVER_IP = '192.168.1.XXX'  # <--- MODIFICA QUI CON L'IP VERO
SERVER_PORT = 12345
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

def attack_replay_data():
    """
    ATTACCO 1: Invia lo stesso pacchetto dati due volte.
    Testa: Sliding Window (Fase 7).
    """
    print("\n--- [ATTACCO 1] DATA REPLAY ---")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    conn_id = 111
    
    try:
        # 1. Handshake Rapido (per avere le chiavi)
        print("[HACKER] Eseguo Handshake legittimo...")
        priv, pub = generate_ecdh_keys()
        sock.sendto(create_packet(PTYPE_INITIAL, conn_id, 1, serialize_public_key(pub)), SERVER_ADDR)
        
        resp, _ = sock.recvfrom(4096)
        _, _, _, token = parse_raw_header(resp)
        
        sock.sendto(create_packet(PTYPE_HANDSHAKE, conn_id, 2, token + serialize_public_key(pub)), SERVER_ADDR)
        resp, _ = sock.recvfrom(4096) # Server Hello
        _, _, _, srv_pub = parse_raw_header(resp)
        sess_key, hp_key = derive_session_keys(priv, srv_pub)
        
        # 2. Creazione Pacchetto Dati
        pkt_num = 10
        msg = b"Bonifico di 1000 Euro"
        print(f"[HACKER] Creo pacchetto {pkt_num}: '{msg.decode()}'")
        
        enc = encrypt_data(sess_key, msg)
        base = create_packet(PTYPE_DATA, conn_id, pkt_num, enc)
        prot_header = apply_header_protection(base[:9], hp_key, enc[:16])
        final_packet = prot_header + enc
        
        # 3. L'ATTACCO
        print("[HACKER] Invio pacchetto (Originale)...")
        sock.sendto(final_packet, SERVER_ADDR)
        time.sleep(0.5)
        
        print("[HACKER] !!! REPLAY ATTACK !!! Rinvio lo stesso pacchetto...")
        sock.sendto(final_packet, SERVER_ADDR)
        
        print("[HACKER] Attacco completato. Controlla il Server: deve dire 'Replay/Già processato'.")
        
    except Exception as e:
        print(f"Errore: {e}")
    finally:
        sock.close()

def attack_expired_token():
    """
    ATTACCO 2: Usa un token vecchio.
    Testa: Anti-Spoofing Temporale (Fase 6).
    """
    print("\n--- [ATTACCO 2] TOKEN EXPIRED ---")
    print("NB: Assicurati che il server abbia 'validity_seconds=5' per non aspettare troppo.")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    conn_id = 222
    
    try:
        # 1. Chiedo Token
        print("[HACKER] Chiedo un Token valido...")
        priv, pub = generate_ecdh_keys()
        sock.sendto(create_packet(PTYPE_INITIAL, conn_id, 1, serialize_public_key(pub)), SERVER_ADDR)
        
        resp, _ = sock.recvfrom(4096)
        _, _, _, token = parse_raw_header(resp)
        print("[HACKER] Token ricevuto.")
        
        # 2. Attesa Maligna
        print("[HACKER] Aspetto 7 secondi affinche' scada...")
        time.sleep(7)
        
        # 3. Tentativo di uso
        print("[HACKER] Provo a usare il token SCADUTO!")
        payload = token + serialize_public_key(pub)
        sock.sendto(create_packet(PTYPE_HANDSHAKE, conn_id, 2, payload), SERVER_ADDR)
        
        # 4. Verifica
        try:
            sock.recvfrom(4096)
            print(">>> FALLITO: Il server ha risposto (Token accettato).")
        except socket.timeout:
            print(">>> SUCCESSO: Il server NON ha risposto (Token scartato).")
            
    except Exception as e:
        print(f"Errore: {e}")
    finally:
        sock.close()

def attack_tampering():
    """
    ATTACCO 3: Modifica il payload cifrato.
    Testa: AES-GCM Auth Tag (Fase 3).
    """
    print("\n--- [ATTACCO 3] TAMPERING (Man-in-the-Middle) ---")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    conn_id = 333
    
    try:
        # 1. Handshake
        print("[HACKER] Handshake...")
        priv, pub = generate_ecdh_keys()
        sock.sendto(create_packet(PTYPE_INITIAL, conn_id, 1, serialize_public_key(pub)), SERVER_ADDR)
        resp, _ = sock.recvfrom(4096)
        _, _, _, token = parse_raw_header(resp)
        sock.sendto(create_packet(PTYPE_HANDSHAKE, conn_id, 2, token + serialize_public_key(pub)), SERVER_ADDR)
        resp, _ = sock.recvfrom(4096)
        _, _, _, srv_pub = parse_raw_header(resp)
        sess_key, hp_key = derive_session_keys(priv, srv_pub)
        
        # 2. Preparazione Pacchetto
        pkt_num = 50
        msg = b"Messaggio Integro"
        enc = encrypt_data(sess_key, msg) # enc contiene: IV + TAG + CIPHERTEXT
        
        # 3. MANOMISSIONE
        # Modifichiamo l'ultimo byte del ciphertext
        # Trasformiamo i bytes in bytearray per modificarli
        mutable_enc = bytearray(enc)
        mutable_enc[-1] = mutable_enc[-1] ^ 0xFF # Invertiamo i bit dell'ultimo byte
        tampered_enc = bytes(mutable_enc)
        
        print(f"[HACKER] Messaggio originale cifrato: {enc.hex()[:20]}...")
        print(f"[HACKER] Messaggio MANOMESSO:        {tampered_enc.hex()[:20]}...")
        
        # Header Protection sul payload manomesso (per simulare un pacchetto che sembra vero)
        base = create_packet(PTYPE_DATA, conn_id, pkt_num, tampered_enc)
        prot_header = apply_header_protection(base[:9], hp_key, tampered_enc[:16])
        final_packet = prot_header + tampered_enc
        
        sock.sendto(final_packet, SERVER_ADDR)
        print("[HACKER] Pacchetto corrotto inviato. Il server dovrebbe dare Errore Decifratura.")
        
    except Exception as e:
        print(f"Errore: {e}")
    finally:
        sock.close()

def main():
    while True:
        print("\n=== QUIC ATTACK SUITE ===")
        print(f"Target: {SERVER_IP}:{SERVER_PORT}")
        print("1. Attack Data Replay (Testa Sliding Window)")
        print("2. Attack Token Expiry (Testa Anti-Spoofing)")
        print("3. Attack Tampering (Testa Crittografia)")
        print("0. Esci")
        
        choice = input("Scegli attacco: ")
        
        if choice == '1': attack_replay_data()
        elif choice == '2': attack_expired_token()
        elif choice == '3': attack_tampering()
        elif choice == '0': break
        else: print("Scelta non valida")
        
        time.sleep(1)

if __name__ == "__main__":
    main()
