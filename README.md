# Progetto_network_security

# Secure User-Space Transport Protocol (S-UDP) 🛡️🚀

![Language](https://img.shields.io/badge/Language-Python_3.x-blue.svg)
![Security](https://img.shields.io/badge/Security-AEAD_%2F_ECDHE-green.svg)
![License](https://img.shields.io/badge/License-MIT-orange.svg)

**S-UDP** è un'implementazione sperimentale di un protocollo di trasporto sicuro operante in **User Space** sopra UDP.
Ispirato all'architettura di **QUIC** e **TLS 1.3**, il progetto mira a combinare la bassa latenza del datagramma con garanzie avanzate di sicurezza, privacy e resilienza.

---

## 📋 Panoramica
Il protocollo risolve i limiti intrinseci dei trasporti tradizionali:
- **Vs TCP:** Elimina l'Head-of-Line Blocking e riduce la latenza di handshake.
- **Vs UDP Standard:** Aggiunge cifratura, autenticazione e gestione dello stato.

L'intero stack è sviluppato in **Python** utilizzando primitive crittografiche moderne, offrendo un canale sicuro *by-design* resistente a sniffing e manipolazione.

## ✨ Funzionalità Chiave

### 🔒 Sicurezza & Crittografia
* **Authenticated Encryption (AEAD):** Utilizzo di **AES-256-GCM** per garantire confidenzialità e integrità del payload.
* **Perfect Forward Secrecy (PFS):** Scambio chiavi effimero tramite **ECDHE** (Curva SECP256R1/P-256).
* **Privacy Avanzata:** Meccanismo di **Header Protection** per offuscare il *Packet Number* e prevenire la Traffic Analysis.

### 🛡️ Resilienza di Rete
* **Anti-Spoofing:** Handshake con **Stateless Retry Token** per prevenire attacchi di amplificazione e DoS.
* **Anti-Replay:** Implementazione lato server di una **Sliding Window** ($O(1)$) per scartare pacchetti duplicati.
* **Connection Migration:** Utilizzo di un **Connection ID** per mantenere la sessione attiva anche al variare dell'indirizzo IP/Porta del client (es. passaggio Wi-Fi <-> 4G).

---

FASE 0 → Scopo e assunzioni

FASE 1 → Specifica del protocollo (logica)

FASE 2 → UDP minimale (senza sicurezza)

FASE 3 → Crittografia isolata (senza protocollo)

FASE 4 → Integrazione protocollo + handshake

FASE 5 → Protezione dati e header

FASE 6 → Anti-spoofing (Retry Token)

FASE 7 → Anti-replay (sliding window)

FASE 8 → Attack Suite e validazione
