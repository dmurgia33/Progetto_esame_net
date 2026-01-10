#common3.1.py (AGGIORNAMENTO PER PROTOCOLLO A STATI)
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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

  
