Certamente. Ecco la versione aggiornata del `README.md`, focalizzata esclusivamente sull'architettura, le specifiche tecniche e i principi di funzionamento del protocollo, rimuovendo le istruzioni operative di installazione e utilizzo.

---

# S-UDP (Secure UDP) - Protocollo di Trasporto Cifrato in User Space

> **Autori:** Francesco Falchi & Davide Murgia
> **Corso:** Cybersecurity & AI, Università di Cagliari

## 📄 Descrizione del Progetto

**S-UDP** è un'implementazione *proof-of-concept* di un protocollo di trasporto sicuro operante in User Space su UDP. Il progetto nasce dall'esigenza di superare i limiti strutturali dei protocolli tradizionali: l'ossificazione del TCP nel kernel e la mancanza nativa di sicurezza dell'UDP.

Ispirandosi all'architettura dello standard **QUIC**, S-UDP fornisce un canale che coniuga la bassa latenza del datagramma con garanzie di sicurezza comparabili a TLS 1.3, implementando cifratura autenticata, forward secrecy e protezione della privacy dei metadati.

## ✨ Caratteristiche Tecniche

### 🔐 Sicurezza e Crittografia (AEAD)

Il cuore del protocollo si basa su primitive crittografiche moderne per garantire la confidenzialità e l'integrità dei dati:

* **Cifratura Autenticata:** Utilizzo di **AES-256-GCM** (Galois/Counter Mode). Questo garantisce che ogni manipolazione del payload (bit-flipping o tampering) venga rilevata matematicamente tramite la verifica del Tag di Autenticazione prima della decifratura.


* **Perfect Forward Secrecy (PFS):** Ogni sessione genera chiavi effimere tramite scambio **ECDHE** (Curva SECP256R1/NIST P-256). La compromissione futura delle chiavi del server non pregiudica la sicurezza delle sessioni passate.


* 
**Derivazione delle Chiavi:** Implementazione di **HKDF (SHA-256)** per derivare chiavi crittograficamente indipendenti per la cifratura dei dati e per la protezione degli header.



### 🕵️ Privacy e Header Protection

A differenza dei protocolli tradizionali dove gli header viaggiano in chiaro, S-UDP implementa la **Header Protection**.

* 
**Offuscamento:** Il *Packet Number* viene mascherato applicando una maschera XOR generata tramite **AES-ECB** su un campione del payload cifrato.


* 
**Anti-Traffic Analysis:** Questo rende i metadati indistinguibili dal rumore casuale, impedendo a osservatori esterni di analizzare i pattern di traffico o calcolare il RTT osservando i numeri di sequenza.



### 🛡️ Resilienza e Difesa

Il protocollo integra meccanismi nativi per mitigare attacchi comuni verso UDP:

* **Anti-Spoofing (Stateless Retry):** Il server non alloca memoria alla prima richiesta. Invia invece un **Token Crittografico** opaco che il client deve restituire per dimostrare il possesso dell'IP, prevenendo attacchi di amplificazione e allocazione risorse (SYN-Flood).


* **Anti-Replay (Sliding Window):** Il server mantiene una finestra scorrevole degli ID pacchetto processati. I pacchetti duplicati o troppo vecchi (fuori finestra) vengono scartati istantaneamente per prevenire attacchi di replay.


* 
**Connection Migration:** L'uso di un *Connection ID* arbitrario disaccoppia la sessione dalla tupla IP/Porta, permettendo teoricamente la persistenza della connessione anche al variare della rete (es. passaggio da Wi-Fi a 4G).



## 🏗️ Architettura del Protocollo

Il sistema è modellato come una **Macchina a Stati Finiti** che gestisce il ciclo di vita della connessione attraverso quattro fasi distinte:

1. **Fase INITIAL:** Il Client genera una coppia di chiavi effimere e invia la propria chiave pubblica. Il Server riceve la richiesta ma rimane stateless.


2. **Fase RETRY (Challenge):** Il Server risponde con un pacchetto RETRY contenente un Token cifrato (con timestamp e IP client). Nessuna risorsa viene ancora allocata sul server.


3. **Fase HANDSHAKE:** Il Client rispedisce il Token intatto insieme alla sua chiave pubblica. Il Server valida il Token; se valido, alloca la sessione, deriva le chiavi simmetriche e completa lo scambio.


4. **Fase DATA:** La connessione è stabilita. Tutto il traffico successivo è cifrato con AES-GCM e gli header sono offuscati.



## 📂 Struttura del Repository

Il codice sorgente riflette l'approccio modulare adottato nello sviluppo del protocollo:

* 
**`server.py`**: Implementa la logica lato server, inclusa la macchina a stati, la gestione della *Sliding Window* per l'anti-replay e la generazione/validazione dei Token stateless.


* 
**`client_completo.py`**: Client legittimo capace di eseguire l'handshake a 4 vie, gestire la ricezione del Retry Token e stabilire il canale cifrato.


* **`attack_suite.py`**: Suite di test offensivi sviluppata per validare la sicurezza. Include moduli per simulare:
* 
*Data Replay Attack* (Test della Sliding Window).


* 
*Token Expiry Attack* (Test della validazione temporale dei Token).


* 
*Tampering/Man-in-the-Middle* (Test dell'integrità AES-GCM).





## 📊 Validazione

L'efficacia del protocollo è stata verificata tramite analisi del traffico con **Wireshark**, confermando che:

* Il payload presenta un'elevata entropia (indistinguibile dal rumore).


* I numeri di sequenza non sono leggibili in chiaro grazie alla Header Protection.


* Le difese contro Replay e Spoofing reagiscono correttamente agli scenari di attacco simulati.



---

*Progetto accademico - Laurea Magistrale in Computer Engineering, Cybersecurity & AI.*

FASE 0 → Scopo e assunzioni

FASE 1 → Specifica del protocollo (logica)

FASE 2 → UDP minimale (senza sicurezza)

FASE 3 → Crittografia isolata (senza protocollo)

FASE 4 → Integrazione protocollo + handshake

FASE 5 → Protezione dati e header

FASE 6 → Anti-spoofing (Retry Token)

FASE 7 → Anti-replay (sliding window)

FASE 8 → Attack Suite e validazione
