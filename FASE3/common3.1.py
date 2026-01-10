#common3.1.py (AGGIORNAMENTO PER PROTOCOLLO A STATI)
import struct
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# --- TIPI DI PACCHETTO AGGIORNATI ---
PTYPE_INITIAL   = 0x01  # Client Hello (Primo tentativo)
PTYPE_RETRY     = 0x02  # Server Hello Retry Request (Sfida Token)
PTYPE_HANDSHAKE = 0x03  # Client Hello con Token + Server Hello
PTYPE_DATA      = 0x04  # Application Data (Cifrato)

# --- SERIALIZZAZIONE E PARSING ---

def serialize_public_key(public_key):
    """Converte oggetto chiave pubblica in 65 bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

def parse_header(packet):
    """Parsa l'header comune (Type, ConnID, PktNum)"""
    if len(packet) < 9:
        raise ValueError("Pacchetto troppo corto")
    type_byte, conn_id, packet_number = struct.unpack('!B I I', packet[:9])
    payload = packet[9:]
    return type_byte, conn_id, packet_number, payload

# --- COSTRUTTORI DI PACCHETTI SPECIFICI ---

def create_packet(ptype, conn_id, pkt_num, payload=b''):
    """Funzione generica per creare pacchetti"""
    header = struct.pack('!B I I', ptype, conn_id, pkt_num)
    return header + payload

# --- FUNZIONI CRITTOGRAFICHE ---

def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, peer_public_key_bytes):
    # Deserializza la chiave del peer
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), peer_public_key_bytes
    )
    # Calcolo ECDH
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    
    # Derivazione chiave (HKDF)
    # Nota: In produzione si dovrebbero derivare 2 chiavi (Client->Server e Server->Client)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32, # Chiave AES-256
        salt=None,
        info=b'iot_quic_handshake', 
        backend=default_backend()
    ).derive(shared_secret)
    return key

def encrypt_data(key, data):
    iv = os.urandom(12) # In futuro: Derivare da Packet Number per risparmiare byte
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext 

def decrypt_data(key, data):
    if len(data) < 28: # 12 IV + 16 Tag
        raise ValueError("Dati troppo corti per decifratura")
        
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
