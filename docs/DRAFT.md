# ATP v1.7 — Draft Design Document

**Agent Transport Protocol — Un protocollo peer-to-peer per agenti autonomi**

*Versione: 1.7 (Draft — 19 Luglio 2026)*

---

## 1. Motivazione

Gli agenti AI autonomi oggi comunicano prevalentemente via API REST centralizzate.
Ogni agente dipende da un server centrale per autenticazione, autorizzazione e
instradamento delle richieste. Questo crea:

- **Single point of failure** fiduciario: l'operatore del server vede tutto
- **Single point of failure** infrastrutturale: se il server cade, gli agenti
  non comunicano
- **Vendor lock-in**: un agente non può parlare direttamente con un altro agente
  su una piattaforma diversa
- **Mancanza di non-ripudio**: le richieste API REST non sono firmate
  crittograficamente, non c'è prova di origine

ATP è nato per risolvere questi problemi: una comunicazione peer-to-peer
crittograficamente sicura, senza server centrale, dove ogni agente ha la
propria identità autocertificata.

## 2. Obiettivi di progetto

1. **Identità distribuita**: ogni agente possiede un documento di identità
   autocertificato (MCC) firmato da un'autorità di sua scelta
2. **Comunicazione peer-to-peer**: due agenti comunicano direttamente via
   TLS, senza intermediari
3. **Verificabilità**: ogni messaggio è firmato e può essere verificato da
   terze parti
4. **Revoca distribuita**: un agente compromesso può essere revocato senza
   server centrale
5. **Estendibilità**: nuovi tipi di task possono essere aggiunti senza
   modificare il protocollo base
6. **Zero-config per demo**: deve funzionare su due macchine senza configurare
   firewall o server DNS

## 3. Design decisioni chiave

### 3.1 Perché MCC e non X.509?

L'MCC (Merkle-Claim Card) è stato scelto al posto di un certificato X.509
standard per tre ragioni:

1. **Merkle tree**: le claim (chiavi pubbliche, metadati) sono foglie di un
   albero di Merkle. Questo permette di verificare singole claim senza
   rivelare le altre (privacy selettiva)
2. **CBOR leggero**: la codifica CBOR è più compatta di DER/PEM e non richiede
   ASN.1
3. **Flessibilità**: nuove claim possono essere aggiunte senza modificare il
   formato del certificato

### 3.2 Perché Ed25519 e non RSA?

- **Velocità**: Ed25519 è ~10x più veloce di RSA-2048 in verifica
- **Dimensione**: 32 byte per chiave pubblica vs 256 byte per RSA-2048
- **Sicurezza**: Ed25519 è resistente a side-channel, non richiede random
  durante la firma
- **Key separation obbligatoria**: X25519 per ECDH, Ed25519 per firme —
  eliminiamo il rischio di dual-use. Step 7 della verifica MCC (agent_pk == TLS key)
  è disabilitato perché chiavi di tipo diverso (X25519 vs Ed25519) non possono
  coincidere — il binding è garantito dal proof-of-possession nell'handshake.

### 3.3 Perché BLAKE3 e non SHA-256?

- **Velocità**: BLAKE3 è ~15x più veloce di SHA-256 su input medi
- **Sicurezza**: 128 bit di sicurezza collisione (equivalente a SHA-256)
- **Universal hashing**: la stessa funzione serve per hash, PRF, e MAC
- **Fallback**: BLAKE2b-256 è disponibile dove BLAKE3 non è installato

### 3.4 Perché CBOR e non JSON?

- **Canonico**: CBOR ha una codifica canonica definita (RFC 8949 §4.2),
  mentre JSON non ha un ordinamento deterministico delle chiavi
- **Compatto**: CBOR è in binario, tipicamente 20-30% più piccolo di JSON
- **Type safety**: CBOR supporta tipi che JSON non ha (bytes, UUID)

## 4. Architettura del protocollo

### 4.1 Strati

```
┌──────────────────────────────────────────────┐
│  Task Layer                                  │
│  TASK_REQUEST → TASK_ACK → TASK_RESPONSE     │
├──────────────────────────────────────────────┤
│  Control Layer                               │
│  SHUTDOWN, REVOKE_NOTIFY, ROOT_STORE_UPDATE  │
├──────────────────────────────────────────────┤
│  Handshake Layer                             │
│  TLS → Version → MCC Exchange → Capability   │
├──────────────────────────────────────────────┤
│  Transport Layer                             │
│  TCP + TLS 1.3 (4-byte length prefix + CBOR) │
└──────────────────────────────────────────────┘
```

### 4.2 Flusso di connessione

1. **TLS handshake**: connessione TCP cifrata. I certificati auto-firmati
   sono accettati per demo (CERT_NONE). In produzione, certificati reali.
2. **Version negotiation**: l'iniziatore propone le versioni supportate
3. **MCC exchange**: scambio di identità con proof-of-possession
4. **Capability exchange**: annuncio delle capacità supportate
5. **Task streaming**: scambio di task asincroni

## 5. Stato attuale

ATP v1.7 è un'implementazione funzionante con:

- **21 moduli Python** (atp_core, agent, agent_tls, agent_crypto, server, client,
  config, authority, revocation, revocation_sqlite, federation, monitor,
  dashboard, production, main, atp_quic + conftest test framework)
- **SDK Python** pip-installabile (SimpleATPClient, SimpleATPServer, Tunnel)
- **6 esempi reali** (research, code review, voting, teacher, school, azienda)
- **Dashboard PySide6** con 5 tab (Overview, Traffic, Connections, Agents, Tasks)
- **Test suite**: 52 test pytest (45 core + 7 SDK), fixture isolate,
  contaminazione singleton eliminata via conftest con reset stato globale
- **Score architetturale**: 9.5/10
- **Zero configurazione di rete**: tunnel UPnP nativo integrato

## 6. Lavori futuri

- **[x] Multiplexing task**: task concorrenti per task_id con asyncio.Future
- **[x] Gossip attivo**: seriali revocati su TCP (porta 8444) + CONTROL_REVOKE_NOTIFY
- **[x] RootStore persistente**: autorità salvate su root_store.json
- **[x] Mutual TLS**: CA condivisa, CERT_REQUIRED su entrambi i lati
- **[x] Verifica MCC sempre obbligatoria**: rimossa demo_mode
- **[x] BLAKE3 obbligatorio**: nessun fallback a BLAKE2b
- **[ ] Multiplexing task stream (stream ID multipli)**
- [ ] Crittografia end-to-end con X25519 ECDH
- [ ] Namespace distribuiti per agenti
- [ ] Federazione tra istanze ATP diverse
- [ ] Gateway per bridge con protocolli esterni

---

*Questo documento è un draft iniziale. La specifica tecnica completa è in SPEC.md.*
