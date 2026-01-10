# common.py
import struct
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import os

# Funzione per creare un pacchetto INITIAL (da usare sia nel client che nel server)
def create_initial_packet(client_id, packet_number, public_key):
    # Crea un pacchetto con il formato [Type, ConnID, PacketNumber, PublicKey]
    return struct.pack('!B I I 65s', 0x01, client_id, packet_number, public_key)

# Funzione per analizzare un pacchetto (da usare sia nel client che nel server)
def parse_packet(packet):
    # Estrae il tipo, conn_id, packet_number e public_key dal pacchetto
    type_byte, conn_id, packet_number, public_key = struct.unpack('!B I I 65s', packet)
    return type_byte, conn_id, packet_number, public_key

# Funzione per generare una coppia di chiavi ECDHE
def generate_ecdh_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Funzione per derivare una chiave segreta condivisa usando ECDHE
def derive_shared_secret(private_key, peer_public_key):
    # Deserializzare la chiave pubblica del peer
    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    # Derivazione della chiave di sessione usando HKDF
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'key_derivation', backend=default_backend()).derive(shared_secret)
    return key

# Funzione per cifrare i dati con AES-GCM
def encrypt_data(key, data):
    iv = os.urandom(12)  # Vector di inizializzazione random per AES-GCM
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + encryptor.tag + ciphertext  # IV + tag + ciphertext

# Funzione per decifrare i dati con AES-GCM
def decrypt_data(key, data):
    iv = data[:12]  # I primi 12 byte sono l'IV
    tag = data[12:28]  # I successivi 16 byte sono il tag
    ciphertext = data[28:]  # Il resto è il ciphertext
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()
