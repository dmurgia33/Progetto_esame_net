# common.py (FASE 5 - Header Protection)
import struct
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- COSTANTI ---
PTYPE_INITIAL   = 0x01
PTYPE_RETRY     = 0x02
PTYPE_HANDSHAKE = 0x03
PTYPE_DATA      = 0x04

# --- SERIALIZZAZIONE ---
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def create_packet(ptype, conn_id, pkt_num, payload=b''):
    """Crea un pacchetto con header in chiaro (prima della protezione)"""
    # Header: Type (1) | ConnID (4) | PktNum (4)
    header = struct.pack('!B I I', ptype, conn_id, pkt_num)
    return header + payload

# --- FUNZIONI CRITTOGRAFICHE AGGIORNATE ---

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_session_keys(private_key, peer_public_key_bytes):
    """
    Deriva le chiavi di sessione.
    Restituisce: (session_key, hp_key)
    """
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_key_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Deriviamo 48 bytes: 32 per Session Key (AES-256), 16 per Header Protection Key (AES-128)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48, 
        salt=None,
        info=b'iot_quic_v1', 
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    
    session_key = key_material[:32] # Primi 32 bytes
    hp_key = key_material[32:]      # Ultimi 16 bytes
    
    return session_key, hp_key

def encrypt_data(key, plaintext, associated_data=None):
    """Cifra il payload usando AES-GCM"""
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # In un vero protocollo, l'header viene passato come 'associated_data' per autenticarlo
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext 

def decrypt_data(key, data, associated_data=None):
    """Decifra il payload"""
    if len(data) < 28:
        raise ValueError("Dati troppo corti")
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
        
    return decryptor.update(ciphertext) + decryptor.finalize()

# --- HEADER PROTECTION LOGIC (IL CUORE DELLA FASE 5) ---

def apply_header_protection(header_bytes, hp_key, sample):
    """
    Applica lo XOR al Packet Number usando una maschera derivata dal sample del ciphertext.
    Header Format: [Type (1)][ConnID (4)][PktNum (4)]
    """
    # 1. Genera la maschera usando AES-ECB sulla chiave HP e il Sample
    # Usiamo AES-ECB perché ci serve solo trasformare il blocco Sample in una maschera pseudo-random
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    # Tronchiamo il sample a 16 bytes (dimensione blocco AES)
    mask = encryptor.update(sample[:16]) + encryptor.finalize()
    
    # 2. Estrai il packet number originale (ultimi 4 bytes dell'header)
    pkt_num_bytes = header_bytes[5:9]
    
    # 3. Fai lo XOR tra i primi 4 bytes della maschera e il PktNum
    masked_pkt_num = bytes(a ^ b for a, b in zip(pkt_num_bytes, mask[:4]))
    
    # 4. Ricostruisci l'header con il PktNum offuscato
    protected_header = header_bytes[:5] + masked_pkt_num
    return protected_header

def remove_header_protection(protected_header, hp_key, sample):
    """
    Rimuove lo XOR per leggere il Packet Number reale.
    È simmetrico: (A XOR B) XOR B = A
    """
    # La logica è identica: rigeneriamo la stessa maschera e facciamo XOR
    return apply_header_protection(protected_header, hp_key, sample)

def parse_raw_header(packet):
    """
    Parsa solo le parti IN CHIARO dell'header (Type, ConnID).
    Il PktNum restituito qui è ancora cifrato/garbage se la protezione è attiva.
    """
    if len(packet) < 9:
        raise ValueError("Packet too short")
    type_byte, conn_id = struct.unpack('!B I', packet[:5])
    raw_pn = packet[5:9] # Bytes grezzi del packet number
    payload = packet[9:]
    return type_byte, conn_id, raw_pn, payload
