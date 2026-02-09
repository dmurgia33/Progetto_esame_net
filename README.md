S-UDP: Secure User-Space Transport Protocol
S-UDP è un prototipo di protocollo di trasporto sicuro costruito interamente in Python sopra UDP. L'obiettivo è offrire la velocità di UDP unita alla sicurezza di TLS 1.3, gestendo tutto a livello applicativo (User Space) anziché a livello di Kernel.

Caratteristiche principali:

Cifratura Totale: Protezione dei dati con AES-GCM.

Privacy dell'Header: Anche i metadati (come i numeri di pacchetto) sono nascosti.

Sicurezza Avanzata: Protezione contro attacchi Replay e IP Spoofing.

Connessione Moderna: Scambio chiavi con ECDHE per una sicurezza a prova di futuro (Forward Secrecy).

Le Fasi del Progetto
Il progetto è stato sviluppato in modo incrementale, aggiungendo un mattoncino di sicurezza alla volta:

Fase 0 - Pianificazione: Definizione degli obiettivi e scelta delle tecnologie.

Fase 1 - Logica: Disegno del formato dei pacchetti (come sono fatti i "messaggi").

Fase 2 - Trasporto Base: Creazione di un Client e un Server che si scambiano semplici messaggi UDP in chiaro.

Fase 3 - Il "Motore" Crittografico: Sviluppo e test delle funzioni di cifratura in isolamento.

Fase 4 - Handshake: Implementazione del "saluto" tra Client e Server per concordare le chiavi segrete.

Fase 5 - Protezione Totale: Cifratura del contenuto e offuscamento dell'intestazione (Header) per massima privacy.

Fase 6 - Anti-Spoofing: Aggiunta di un sistema di "Token" per verificare che l'IP del Client sia reale.

Fase 7 - Anti-Replay: Implementazione di una "Finestra Scorrevole" per ignorare pacchetti vecchi o duplicati.

Fase 8 - Test di Attacco: Creazione di una suite per tentare di "rompere" il protocollo e confermarne la robustezza.
Bash
python client.py
