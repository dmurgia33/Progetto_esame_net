# common.py
import struct

# Funzione per creare un pacchetto INITIAL (da usare sia nel client che nel server)
def create_initial_packet(client_id, packet_number, public_key):
    # Crea un pacchetto con il formato [Type, ConnID, PacketNumber, PublicKey]
    return struct.pack('!B I I 32s', 0x01, client_id, packet_number, public_key)

# Funzione per analizzare un pacchetto (da usare sia nel client che nel server)
def parse_packet(packet):
    # Estrae il tipo, conn_id, packet_number e public_key dal pacchetto
    type_byte, conn_id, packet_number, public_key = struct.unpack('!B I I 32s', packet)
    return type_byte, conn_id, packet_number, public_key
