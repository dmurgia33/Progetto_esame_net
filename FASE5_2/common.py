# common.py
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
    """Crea un pacchetto con header in chiaro"""
    # Header: Type (1) | ConnID (4) | PktNum (4)
    header = struct.pack('!B I I', ptype, conn_id, pkt_num)
    return header + payload

def parse_raw_header(packet):
    """Parsa Type e ConnID. Restituisce PktNum come bytes grezzi."""
    if len(packet) < 9:
        raise ValueError("Packet too short")
    type_byte, conn_id = struct.unpack('!B I', packet[:5])
    raw_pn = packet[5:9] # Bytes grezzi del packet number
    payload = packet[9:]
    return type_byte, conn_id, raw_pn, payload

# --- CRITTOGRAFIA ---
def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_session_keys(private_key, peer_public_key_bytes):
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_key_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=48, 
        salt=None,
        info=b'iot_quic_v1', 
        backend=default_backend()
    )
    key_material = hkdf.derive(shared_secret)
    session_key = key_material[:32]
    hp_key = key_material[32:]
    return session_key, hp_key

def encrypt_data(key, plaintext):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext 

def decrypt_data(key, data):
    if len(data) < 28:
        raise ValueError("Dati troppo corti")
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Le funzioni di protezione header restano qui ma NON verranno chiamate in questa versione debug
def apply_header_protection(header_bytes, hp_key, sample):
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    mask = encryptor.update(sample[:16]) + encryptor.finalize()
    pkt_num_bytes = header_bytes[5:9]
    masked_pkt_num = bytes(a ^ b for a, b in zip(pkt_num_bytes, mask[:4]))
    return header_bytes[:5] + masked_pkt_num
