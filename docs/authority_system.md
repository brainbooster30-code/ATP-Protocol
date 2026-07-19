# ATP v1.7 — Il sistema delle autorità certificanti

## Perché servono autorità in ATP

ATP è un protocollo **peer-to-peer**: non esiste un server centrale che autentichi gli agenti.
Invece, ogni agente possiede un **MCC** (Merkle-Claim Card) — un documento di identità
autocertificato che contiene le sue chiavi pubbliche, firmato da un'autorità.

Il problema: se due agenti non condividono un server centrale, come fa l'agente A a
verificare che l'MCC dell'agente B non sia stato falsificato? Serve una catena di
fiducia — il sistema delle autorità certificanti.

## Livelli d'uso delle autorità

### Livello 0 — Lab/Demo (localhost)

```
Agente A ──TCP──→ Agente B
```

Entrambi gli agenti girano sulla stessa macchina, nello stesso processo.
Usano la stessa istanza `Authority` (singleton thread-safe). Le chiavi
pubbliche di tutte le autorità vengono registrate automaticamente nel
RootStore condiviso.

**Configurazione:** `demo_mode=True` per saltare la verifica della firma
(non necessario — la stessa Authority firma entrambi gli MCC).

### Livello 1 — Multimacchina / LAN

```
Macchina A: Agente A + Authority_A    Macchina B: Agente B + Authority_B
┌────────────────────┐                ┌────────────────────┐
│  Authority_A──→MCC_A│───ATP──→       │  RootStore: {A?}   │
│  RootStore: {A, B?}│←──ATP───       │  Authority_B──→MCC_B│
└────────────────────┘                └────────────────────┘
```

Ogni macchina ha la propria istanza `Authority` con chiavi Ed25519 diverse.
Il problema: il RootStore della macchina B non conosce la chiave pubblica
dell'Authority_A, quindi non può verificare la firma di MCC_A.

**Soluzioni:**
1. **demo_mode=True** (default nell'SDK) — salta la verifica della firma,
   trust-on-first-use. Adatto per demo e testing.
2. **Scambio manuale delle chiavi** — ogni macchina registra l'authority_pk
   dell'altra via `RootStore.add_authority()`. Adatto per LAN fidata.

**Configurazione:** `ATPAgent(demo_mode=True)` o registrare le authority
reciproche.

### Livello 2 — Produzione (singola organizzazione)

```
┌─────────────────────┐
│  Root Store         │  ← firmato dall'authority principale
│  ├─ authority_ops   │     (distribuito a tutti gli agenti)
│  ├─ authority_rd    │
│  └─ authority_hr    │
└─────────┬───────────┘
          │
    ┌─────┴─────┐
    │  Chain    │  ← chain-of-manifests per audit
    │  of       │     ogni modifica al RootStore è firmata
    │  Manifests│     dall'authority precedente
    └───────────┘
```

L'organizzazione gestisce un **RootStore centrale** con tutte le authority
fidate. Il RootStore viene distribuito a tutti gli agenti come manifesto
firmato. Le modifiche vengono tracciate in una **catena di manifesti**
(chain-of-manifests): ogni nuovo manifesto è firmato dall'authority del
manifesto precedente.

**Configurazione:** `demo_mode=False`. Authority registrate nel RootStore
con TTL (default 365 giorni). L'**8-step verify** di MCC include:
1. versione MCC == 1
2. expiry_date > now
3. tutti i campi critical_mask presenti
4. ricalcolo del root_hash
5. recupero authority_pk dal RootStore
6. verifica firma Ed25519 sul commitment CBOR
7. (opzionale) agent_pk corrisponde all'identità TLS
8. (ATP-Full) serial_number non revocato

### Livello 3 — Produzione (multi-organizzazione)

```
Org A: [authority_a]──→MCC_a                 Org B: [authority_b]──→MCC_b
          │                                              │
          │  RootStore A: {a}                           │  RootStore B: {b}
          │  RootStore B: {b} ← via gossip              │  RootStore A: {a}
          │              o interscambio                  │
          └──────────────────ATP───────────────────────┘
                           │
                    DegradationPolicy
                    ├─ CONFIRMED  (fresco < 1h)
                    ├─ STALE      (fresco < 24h)
                    └─ UNCERTAIN  (oltre 24h → connessione rifiutata)
```

Due organizzazioni diverse hanno authority diverse. Per comunicare:
1. Si scambiano i manifesti del RootStore (fuori banda o via protocollo)
2. Ogni agente registra l'authority dell'altra organizzazione
3. La **DegradationPolicy** gestisce la freschezza delle chiavi:
   - **CONFIRMED** — authority aggiornata da meno di 1 ora
   - **STALE** — authority aggiornata da meno di 24 ore
   - **UNCERTAIN** — oltre 24 ore, connessione rifiutata per task critici

### Livello 4 — Internet / Pubblico (futuro)

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  Autorità     │    │  Autorità     │    │  Autorità     │
│  di Root      │───→│  intermedia   │───→│  locale       │───→ MCC
└───────────────┘    └───────────────┘    └───────────────┘
       │                     │                    │
       └─────────────────────┴────────────────────┘
                    CA gerarchica tipo X.509
```

Per uso pubblico su internet, ATP può integrarsi con una PKI tradizionale
(X.509) o con una Web of Trust stile PGP. Il commitment CBOR dell'MCC
include già i 5 campi necessari (`root_hash`, `expiry_date`, `mcc_version`,
`authority_id`, `serial_number`) — sufficienti per una gerarchia di CA.

**Nota:** questo livello non è ancora implementato nell'SDK corrente.
L'architettura dell'MCC lo supporta: il campo `authority_id` può riferirsi
a una CA intermedia, e la firma Ed25519 sul commitment CBOR è
matematicamente la stessa per qualsiasi livello.

## Interazione con il protocollo

### Flusso di verifica durante l'handshake

```
Agent A                              Agent B
   │                                    │
   │──── MCC_BIND_REQUEST ────────────→│
   │    (MCC_A + nonce_i)              │
   │                                    ├─ MCC_A.verify() ← 8 step
   │                                    │  1. mcc_version==1
   │                                    │  2. expiry check
   │                                    │  3. critical_mask
   │                                    │  4. root_hash ricalcolato
   │                                    │  5. authority_pk ← RootStore
   │                                    │  6. firma Ed25519 verificata
   │                                    │  7. (opz) agent_pk match
   │                                    │  8. (opz) seriale non revocato
   │                                    │
   │←─── MCC_BIND_RESPONSE ────────────│
   │    (MCC_B + nonce_r + firma)      │
   ├─ MCC_B.verify() ← 8 step          │
   │                                    │
   │──── MCC_BIND_CONFIRM ────────────→│
   │    (firma proof-of-possession)     │
   │                                    │
   v  BOUND                          v  BOUND
```

### Degradation e fallback

Quando un authority non è nel RootStore, il sistema applica la
DegradationPolicy:

1. Se l'authority è **CONFIRMED** o **STALE**: la verifica procede
   normalmente
2. Se l'authority è **UNCERTAIN**: connessione rifiutata
3. Fallback: se l'authority non è nel RootStore ma non è scaduta,
   viene usata l'authority di default (`get_default_authority()`)

### Revoca

La revoca di un serial_number (o di un'intera authority) si propaga via
**Gossip Protocol**:
1. `revoke_serial(serial)` → aggiunge al CuckooFilter locale
2. Il GossipProtocol diffonde il seriale ai peer conosciuti
3. Durante la verifica (step 8), `check_revoked(serial)` controlla
   il CuckooFilter
4. Se il seriale è revocato, la verifica fallisce

### demo_mode

`demo_mode=True` è un'opzione di `ATPAgent` che salta completamente la
verifica dell'authority (step 5-6). Serve per:
- Deployment su macchine diverse senza configurare il RootStore
- Testing e sviluppo locale
- Demo rapide

Per produzione: `demo_mode=False` + authority registrate nel RootStore.
