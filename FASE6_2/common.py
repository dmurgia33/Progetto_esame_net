# common.py
import struct
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# --- COSTANTI PROTOCOLLO ---
PTYPE_INITIAL   = 0x01
PTYPE_RETRY     = 0x02
PTYPE_HANDSHAKE = 0x03
PTYPE_DATA      = 0x04

# --- SERIALIZZAZIONE CHIAVI ---
def serialize_public_key(public_key):
    """Serializza la chiave pubblica in formato X9.62 Uncompressed (65 bytes)"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

# --- COSTRUZIONE E PARSING PACCHETTI ---
def create_packet(ptype, conn_id, pkt_num, payload=b''):
    """Crea un pacchetto con header standard (non protetto)"""
    # Header: Type (1 byte) | ConnID (4 bytes) | PktNum (4 bytes)
    header = struct.pack('!B I I', ptype, conn_id, pkt_num)
    return header + payload

def parse_raw_header(packet):
    """
    Legge Type e ConnID in chiaro. 
    Restituisce il Packet Number come bytes grezzi (perché potrebbe essere offuscato).
    """
    if len(packet) < 9:
        raise ValueError("Pacchetto troppo corto")
    type_byte, conn_id = struct.unpack('!B I', packet[:5])
    raw_pn = packet[5:9] # I 4 bytes del packet number (potenzialmente cifrati)
    payload = packet[9:]
    return type_byte, conn_id, raw_pn, payload

def parse_handshake_payload(payload):
    """Separa il Token (variabile) dalla Chiave Pubblica (fissa 65 bytes)"""
    if len(payload) < 65:
        raise ValueError("Payload handshake troppo corto")
    public_key = payload[-65:]     # Ultimi 65 byte sono la chiave
    token = payload[:-65]          # Tutto il resto prima è il token
    return token, public_key

# --- CRITTOGRAFIA (ECDHE + AES-GCM) ---
def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_session_keys(private_key, peer_public_key_bytes):
    """Deriva Session Key (dati) e Header Protection Key (header)"""
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_key_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Deriviamo 48 bytes: 32 per SessionKey, 16 per HPKey
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48, 
        salt=None,
        info=b'iot_quic_v1', 
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    return key_material[:32], key_material[32:]

def encrypt_data(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext 

def decrypt_data(key, data):
    if len(data) < 28: raise ValueError("Dati insufficienti")
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# --- HEADER PROTECTION (FASE 5) ---
def apply_header_protection(header_bytes, hp_key, sample):
    """Applica XOR mask al Packet Number usando AES-ECB sul sample"""
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    # Usa i primi 16 byte del sample per generare la maschera
    mask = encryptor.update(sample[:16]) + encryptor.finalize()
    
    pkt_num_bytes = header_bytes[5:9]
    # XOR tra Packet Number originale e la Maschera
    masked_pkt_num = bytes(a ^ b for a, b in zip(pkt_num_bytes, mask[:4]))
    
    return header_bytes[:5] + masked_pkt_num

def remove_header_protection(protected_header, hp_key, sample):
    """Rimuove la maschera (operazione simmetrica)"""
    return apply_header_protection(protected_header, hp_key, sample)

# --- ANTI-SPOOFING TOKEN (FASE 6) ---
def generate_retry_token(master_key, address_tuple):
    """Cifra 'TIMESTAMP:IP' con la Master Key del server"""
    ip_addr = address_tuple[0]
    timestamp = int(time.time())
    token_data = f"{timestamp}:{ip_addr}".encode('utf-8')
    return encrypt_data(master_key, token_data)

def validate_retry_token(master_key, address_tuple, token, validity_seconds=30):
    try:
        plaintext = decrypt_data(master_key, token)
        ts_str, ip_in_token = plaintext.decode('utf-8').split(':', 1)
        
        if ip_in_token != address_tuple[0]: return False # IP Mismatch
        if time.time() - int(ts_str) > validity_seconds: return False # Expired
        
        return True
    except:
        return False
